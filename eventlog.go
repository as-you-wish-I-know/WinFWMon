// Copyright (c) 2026 WinFWMon Contributors
// SPDX-License-Identifier: MIT
//
// Reads Windows Filtering Platform connection audit events (5156 allow / 5157
// block) from the Security event log via PowerShell's Get-WinEvent. Each event
// carries a FilterRTID identifying the exact WFP filter that made the decision,
// which wfpFilters resolves to the governing firewall rule name — precise
// attribution that the pfirewall.log text format cannot provide.
// See LICENSE for full license text.

package main

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// eventPollInterval is how often the Security log is polled for new events.
const eventPollInterval = 1 * time.Second

// initialEventBacklog is how many recent events to load on first poll so the
// window is populated immediately rather than waiting for new connections.
const initialEventBacklog = 500

// incrementalPollCap bounds how many newest events each incremental poll reads
// before the RecordId high-water filter is applied, so a high-volume Security
// log is never scanned in full. If more than this many events arrive within one
// poll interval, the oldest beyond the cap are missed — acceptable for a live
// monitor, and the cap is generous relative to the 1s interval.
const incrementalPollCap = 2000

// EventSource polls the Security event log for WFP connection events and sends
// parsed entries to out. Start and Stop are safe to call from any goroutine;
// Stop blocks until the polling goroutine has exited.
type EventSource struct {
	out      chan *LogEntry
	stopCh   chan struct{}
	doneCh   chan struct{}
	once     sync.Once
	lastRID  int64     // highest event RecordId seen so far (high-water mark)
	lastTime time.Time // timestamp of the newest event seen (for StartTime narrowing)
	firstRun bool
	backlog  int // how many events to pull on the first run (0 = default)
}

func newEventSource(out chan *LogEntry) *EventSource {
	return &EventSource{
		out:      out,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
		firstRun: true,
	}
}

func (s *EventSource) Start() { go s.run() }

// RunOnce performs a single backlog poll (no recurring polling) and sends the
// parsed entries to out, then returns. Used by history mode when the PowerShell
// source is explicitly forced (--powershell); the default history path uses the
// faster native EvtQuery reader instead. It honors the stop channel so a
// shutdown during ingest is clean.
//
// If done is non-nil it is called once with the number of events actually sent
// to out, after the send loop finishes (but not if the stop channel aborted the
// send early). Like run(), it closes doneCh on return so a subsequent Stop()
// (which waits on doneCh) does not block forever. Launch as a goroutine once.
func (s *EventSource) RunOnce(done func(count int)) {
	defer close(s.doneCh)
	entries := s.poll()
	sent := 0
	for _, e := range entries {
		select {
		case s.out <- e:
			sent++
		case <-s.stopCh:
			return // aborted by shutdown; do not report completion
		}
	}
	if done != nil {
		done(sent)
	}
}

// Stop signals the polling goroutine to exit and waits for it to finish.
func (s *EventSource) Stop() {
	s.once.Do(func() { close(s.stopCh) })
	<-s.doneCh
}

func (s *EventSource) isStopped() bool {
	select {
	case <-s.stopCh:
		return true
	default:
		return false
	}
}

func (s *EventSource) run() {
	defer close(s.doneCh)
	dbg("eventsource: starting")

	for {
		if s.isStopped() {
			dbg("eventsource: stop requested, exiting")
			return
		}

		entries := s.poll()
		for _, e := range entries {
			select {
			case s.out <- e:
			case <-s.stopCh:
				return
			}
		}

		select {
		case <-s.stopCh:
			return
		case <-time.After(eventPollInterval):
		}
	}
}

// poll queries for new events since the last seen RecordId and returns the
// parsed entries in chronological order.
func (s *EventSource) poll() []*LogEntry {
	rawOut, err := runPowerShell(s.buildQuery())
	if err != nil {
		dbg("eventsource: query error: %v", err)
		return nil
	}
	out := decodeToUTF8([]byte(rawOut))

	var entries []*LogEntry
	var maxRID int64
	var maxTime time.Time
	lineNum := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r\n ")
		if line == "" {
			continue
		}
		lineNum++
		if s.firstRun && lineNum <= 3 {
			dbg("eventsource: sample line %d: %q", lineNum, line)
		}
		e, rid, ok := parseEventLine(line)
		if !ok {
			continue
		}
		if rid > maxRID {
			maxRID = rid
		}
		if e.HasTimestamp && e.Timestamp.After(maxTime) {
			maxTime = e.Timestamp
		}
		entries = append(entries, e)
	}

	if maxRID > s.lastRID {
		s.lastRID = maxRID
	}
	if maxTime.After(s.lastTime) {
		s.lastTime = maxTime
	}
	if s.firstRun {
		// If the backlog was empty we never learned a baseline time; seed it to
		// now so the first incremental query narrows correctly rather than
		// scanning from epoch.
		if s.lastTime.IsZero() {
			s.lastTime = time.Now()
		}
		dbg("eventsource: first poll parsed %d events, high-water RID=%d", len(entries), s.lastRID)
		s.firstRun = false
	} else if len(entries) > 0 {
		dbg("eventsource: poll parsed %d new events, high-water RID=%d", len(entries), s.lastRID)
	}
	return entries
}

// buildQuery returns the PowerShell script that emits new 5156/5157 events as
// pipe-delimited lines. On the first run it pulls a bounded backlog; afterward
// it returns only events with a RecordId greater than the high-water mark.
//
// Output fields per line (pipe-delimited):
//   RecordId|TimeCreated(o)|EventID|ProcessId|Application|Direction|
//   SourceAddress|SourcePort|DestAddress|DestPort|Protocol|FilterRTID
func (s *EventSource) buildQuery() string {
	// First run: pull a bounded backlog of the newest events. Incremental
	// runs: narrow the query SERVER-SIDE by StartTime so Get-WinEvent only
	// returns (and we only render) events at/after the last one we saw. This
	// is the key to low latency — without it, every poll re-renders thousands
	// of old events' XML, which took ~10s per poll on a busy machine.
	var hashtable string
	if s.firstRun {
		hashtable = "@{LogName='Security'; Id=5156,5157}"
	} else {
		// StartTime uses the last event's timestamp. PowerShell parses the
		// round-trip ('o') format via [datetime]::Parse. We subtract a small
		// guard interval and rely on the RecordId filter below to drop the
		// boundary duplicates, so no event straddling the boundary is missed.
		startStr := s.lastTime.Add(-2 * time.Second).Format(time.RFC3339Nano)
		hashtable = "@{LogName='Security'; Id=5156,5157; StartTime=[datetime]::Parse('" +
			startStr + "')}"
	}

	maxEvents := initialEventBacklog
	if s.backlog > 0 {
		maxEvents = s.backlog
	}
	if !s.firstRun {
		maxEvents = incrementalPollCap
	}
	filter := " -MaxEvents " + strconv.Itoa(maxEvents)

	ridFilter := ""
	if !s.firstRun {
		// Cheap dedupe of the StartTime boundary overlap; operates on the small
		// server-narrowed set, not the whole log.
		ridFilter = " | Where-Object { $_.RecordId -gt " +
			strconv.FormatInt(s.lastRID, 10) + " }"
	}

	// Read EventData fields by name from the event XML (robust against field
	// ordering). @(...) forces an array even for a single event, so
	// [array]::Reverse works (a scalar would throw). Newest-first from
	// Get-WinEvent, reversed to chronological order for display.
	return `
$ErrorActionPreference = 'SilentlyContinue'
$evts = @(Get-WinEvent -FilterHashtable ` + hashtable + filter + ridFilter + `)
if ($evts.Count -gt 0) {
  [array]::Reverse($evts)
  foreach ($e in $evts) {
    $x = [xml]$e.ToXml()
    $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    $line = @(
      $e.RecordId,
      $e.TimeCreated.ToString('o'),
      $e.Id,
      $d['ProcessID'],
      $d['Application'],
      $d['Direction'],
      $d['SourceAddress'],
      $d['SourcePort'],
      $d['DestAddress'],
      $d['DestPort'],
      $d['Protocol'],
      $d['FilterRTID']
    ) -join '|'
    $line
  }
}
`
}

// parseEventLine parses one pipe-delimited event line into a LogEntry. It
// returns the entry, the event RecordId (for the high-water mark), and ok.
func parseEventLine(line string) (*LogEntry, int64, bool) {
	f := strings.Split(line, "|")
	if len(f) < 12 {
		return nil, 0, false
	}

	rid, ridErr := strconv.ParseInt(strings.TrimSpace(f[0]), 10, 64)
	if ridErr != nil || rid <= 0 {
		// Not a real event line (e.g. a stray warning that happened to contain
		// pipe characters). Reject so it neither shows nor corrupts the
		// high-water mark.
		return nil, 0, false
	}

	var ts time.Time
	hasTS := false
	if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(f[1])); err == nil {
		ts = t.Local()
		hasTS = true
	}

	action := "ALLOW"
	if strings.TrimSpace(f[2]) == "5157" {
		action = "DROP"
	}

	pid, _ := strconv.Atoi(strings.TrimSpace(f[3]))
	appPath := strings.TrimSpace(f[4])
	appName := devicePathToFriendly(appPath)

	e := &LogEntry{
		Timestamp:    ts,
		HasTimestamp: hasTS,
		Action:       action,
		Direction:    normaliseEventDirection(strings.TrimSpace(f[5])),
		SrcIP:        strings.TrimSpace(f[6]),
		SrcPort:      atoiOr0(f[7]),
		DstIP:        strings.TrimSpace(f[8]),
		DstPort:      atoiOr0(f[9]),
		Protocol:     protocolNumberToName(strings.TrimSpace(f[10])),
		Path:         appName,
		ProcessName:  appName, // authoritative: captured at event time
		PID:          pid,
		FilterID:     atoiOr0(f[11]),
		RawLine:      line,
	}
	return e, rid, true
}

func atoiOr0(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// normaliseEventDirection maps the event's Direction value to INBOUND/OUTBOUND.
// Depending on how the event XML is rendered, the Direction field may be the
// literal word ("Inbound"/"Outbound") or a message-table token. Observed token
// forms across Windows versions include %%14592 / %%14593 and the shorter
// %592 / %593, so all are accepted. The raw value is logged under --debug so
// any unhandled encoding on a given machine can be identified.
func normaliseEventDirection(raw string) string {
	r := strings.ToUpper(strings.TrimSpace(raw))
	switch r {
	case "INBOUND", "%%14592", "%14592", "%592":
		return "INBOUND"
	case "OUTBOUND", "%%14593", "%14593", "%593":
		return "OUTBOUND"
	default:
		if r != "" {
			dbg("normaliseEventDirection: unhandled direction value %q", raw)
		}
		return "UNKNOWN"
	}
}

// protocolNumberToName converts an IANA protocol number to a readable name.
// Covers the protocols that realistically appear in WFP connection events;
// anything unrecognised falls through to "proto <n>" so it is still legible.
func protocolNumberToName(num string) string {
	switch strings.TrimSpace(num) {
	case "":
		return ""
	case "0":
		return "HOPOPT"
	case "1":
		return "ICMP"
	case "2":
		return "IGMP"
	case "3":
		return "GGP"
	case "4":
		return "IPv4" // IPv4 encapsulation
	case "6":
		return "TCP"
	case "8":
		return "EGP"
	case "9":
		return "IGP"
	case "17":
		return "UDP"
	case "27":
		return "RDP"
	case "33":
		return "DCCP"
	case "41":
		return "IPv6" // IPv6 encapsulation
	case "43":
		return "IPv6-Route"
	case "44":
		return "IPv6-Frag"
	case "46":
		return "RSVP"
	case "47":
		return "GRE"
	case "50":
		return "ESP"
	case "51":
		return "AH"
	case "58":
		return "ICMPv6"
	case "59":
		return "IPv6-NoNxt"
	case "60":
		return "IPv6-Opts"
	case "88":
		return "EIGRP"
	case "89":
		return "OSPF"
	case "94":
		return "IPIP"
	case "103":
		return "PIM"
	case "112":
		return "VRRP"
	case "115":
		return "L2TP"
	case "132":
		return "SCTP"
	case "136":
		return "UDPLite"
	case "137":
		return "MPLS-in-IP"
	default:
		// Unknown/unassigned protocol number: keep it legible and labelled.
		if _, err := strconv.Atoi(strings.TrimSpace(num)); err == nil {
			return "proto " + strings.TrimSpace(num)
		}
		return num
	}
}

// devicePathToFriendly converts an NT device path
// (\device\harddiskvolumeN\path\app.exe) to just the executable basename, which
// is what we display. Full path normalisation to a drive letter would require
// volume mapping; the basename is sufficient for identification.
func devicePathToFriendly(p string) string {
	if p == "" {
		return ""
	}
	if idx := strings.LastIndexAny(p, `\/`); idx >= 0 {
		return p[idx+1:]
	}
	return p
}
