// Copyright (c) 2026 WinFWMon Contributors
// SPDX-License-Identifier: MIT
//
// Matches a connection event to a recognizable Windows Defender Firewall rule
// (the kind a user sees in wf.msc), used for the "Matched Rule" column. This is
// distinct from the WFP filter that actually fired (the "WFP Filter" column,
// resolved precisely from the event's FilterRTID): for most traffic the filter
// that fires at the audited layer is low-level infrastructure, not a named UI
// rule, so this matcher finds the user-facing rule by the connection's
// attributes — program, direction, protocol, and ports.
//
// Because the firewall log/event does not record which UI rule applied, this is
// a heuristic. To avoid misleading attribution it only reports a rule on a
// STRONG match (program match, or a tight direction+protocol+concrete-port
// match); otherwise it yields "(No matching rule)".
// See LICENSE for full license text.

package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// sentinelNoMatch is the Matched Rule value used when no recognizable firewall
// rule was found for an event. Defined here (the producer) and referenced by
// the filter's "hide no-match" option so the two never drift apart.
const sentinelNoMatch = "(No matching rule)"

// FirewallRule is an in-memory snapshot of a single Windows Defender Firewall
// rule, restricted to the fields used for attribute matching.
type FirewallRule struct {
	Name        string
	Direction   int32  // 1=inbound, 2=outbound, 0=any
	Protocol    int32  // 6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6, 256=any
	LocalPorts  string // comma-separated list, range lo-hi, or "*"
	RemotePorts string
	Action      int32  // 1=allow, 0=block
	Enabled     bool
	Program     string // executable path the rule is scoped to, or "" for any
}

// RuleMatcher holds the loaded firewall rules and matches events against them.
type RuleMatcher struct {
	mu    sync.RWMutex
	rules []FirewallRule
}

var globalMatcher = &RuleMatcher{}

// LoadRules enumerates Windows Defender Firewall rules via PowerShell. On error
// or empty result the previous snapshot is kept.
func (rm *RuleMatcher) LoadRules() error {
	out, err := runPowerShell(firewallRuleScript)
	if err != nil {
		dbg("LoadRules: powershell error: %v", err)
		return err
	}
	out = decodeToUTF8([]byte(out))
	dbg("LoadRules: powershell returned %d bytes", len(out))

	var rules []FirewallRule
	sampled := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r\n ")
		if line == "" {
			continue
		}
		r, ok := parseRuleLine(line)
		if !ok {
			continue
		}
		if sampled < 3 {
			dbg("LoadRules: sample rule %q dir=%d proto=%d lport=%q rport=%q prog=%q",
				r.Name, r.Direction, r.Protocol, r.LocalPorts, r.RemotePorts, r.Program)
			sampled++
		}
		rules = append(rules, r)
	}

	if len(rules) == 0 {
		// Diagnostic: zero rules parsed means either the query errored/returned
		// nothing, or its output format no longer matches parseRuleLine. Log the
		// byte count and the first few raw lines so the cause is visible rather
		// than silently keeping an empty snapshot.
		dbg("LoadRules: parsed 0 rules (keeping previous); raw output %d bytes", len(out))
		shown := 0
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimRight(line, "\r\n ")
			if line == "" {
				continue
			}
			dbg("LoadRules: raw line: %q", line)
			shown++
			if shown >= 5 {
				break
			}
		}
		if shown == 0 {
			dbg("LoadRules: raw output had no non-empty lines")
		}
		return nil
	}

	rm.mu.Lock()
	rm.rules = rules
	rm.mu.Unlock()
	dbg("LoadRules: loaded %d firewall rules", len(rules))
	return nil
}

// firewallRuleScript emits one pipe-delimited line per rule:
//   DisplayName|Direction|Action|Enabled|Protocol|LocalPort|RemotePort|Program
// Filters are fetched with the BULK cmdlets and indexed by their own InstanceID,
// then joined to each rule by the rule's Name.
//
// IMPORTANT TRADEOFF: the alternative "pipeline" form ($rules |
// Get-NetFirewallPortFilter) round-trips to the CIM provider once per rule and
// HANGS on a full rule set (hundreds of rules) — it never completes, leaving
// attribution permanently showing "(Rules not loaded)". The bulk form is fast
// (one query) but, on some systems, fails with "Access is denied", in which
// case ports/protocol come back "Any" and attribution falls back to
// direction/program matching. A degraded-but-instant load is far better than a
// hang, and the precise WFP Filter column (resolved via netsh) is unaffected
// either way. So we use the bulk form and tolerate "Any" when it is denied.
const firewallRuleScript = `
$ErrorActionPreference = 'SilentlyContinue'
$portByID = @{}
Get-NetFirewallPortFilter | ForEach-Object { $portByID[$_.InstanceID] = $_ }
$appByID = @{}
Get-NetFirewallApplicationFilter | ForEach-Object { $appByID[$_.InstanceID] = $_ }
Get-NetFirewallRule | ForEach-Object {
    $r = $_
    $key = $r.Name
    $pf = $portByID[$key]
    if ($pf -and $pf.LocalPort)  { $lp = ($pf.LocalPort  -join ',') } else { $lp = '*' }
    if ($pf -and $pf.RemotePort) { $rp = ($pf.RemotePort -join ',') } else { $rp = '*' }
    if ($pf -and $pf.Protocol)   { $proto = $pf.Protocol } else { $proto = 'Any' }
    $af = $appByID[$key]
    if ($af -and $af.Program -and $af.Program -ne 'Any') { $prog = $af.Program } else { $prog = '' }
    $r.DisplayName + '|' + $r.Direction + '|' + $r.Action + '|' + $r.Enabled + '|' + $proto + '|' + $lp + '|' + $rp + '|' + $prog
}
`

// parseRuleLine parses one pipe-delimited rule line. Fields are split
// right-to-left so display names containing "|" are safe.
func parseRuleLine(line string) (FirewallRule, bool) {
	const trailingFieldCount = 7 // Direction|Action|Enabled|Protocol|LPort|RPort|Program
	parts := make([]string, trailingFieldCount+1)

	rest := line
	for i := trailingFieldCount; i > 0; i-- {
		idx := strings.LastIndexByte(rest, '|')
		if idx < 0 {
			return FirewallRule{}, false
		}
		parts[i] = strings.TrimSpace(rest[idx+1:])
		rest = rest[:idx]
	}
	parts[0] = strings.TrimSpace(rest)
	if parts[0] == "" {
		return FirewallRule{}, false
	}

	r := FirewallRule{
		Name:        parts[0],
		LocalPorts:  parts[5],
		RemotePorts: parts[6],
		Program:     parts[7],
	}

	switch parts[1] {
	case "Inbound":
		r.Direction = 1
	case "Outbound":
		r.Direction = 2
	default:
		r.Direction = 0
	}
	if parts[2] == "Allow" {
		r.Action = 1
	}
	r.Enabled = strings.EqualFold(parts[3], "True")
	r.Protocol = protocolToInt(parts[4])
	return r, true
}

// ruleCandidate is a rule that could apply to an event, with its specificity
// score (higher = more specific) and whether it qualified as a STRONG match
// (program match, or tight direction+protocol+concrete-port match).
type ruleCandidate struct {
	Name   string
	Score  int
	Strong bool
}

// candidates returns every enabled rule whose action, direction, protocol and
// ports are consistent with the event, sorted most-specific first. Each is
// flagged Strong per the same criteria Match uses. This is the shared core for
// both Match (which keeps only strong candidates) and the detail view (which
// shows the looser full list). Caller must hold rm.mu (read).
func (rm *RuleMatcher) candidates(e *LogEntry) []ruleCandidate {
	entryDir := directionToInt(e.Direction)
	entryProto := protocolToInt(e.Protocol)
	entryAction := int32(1) // ALLOW
	if e.Action == "DROP" {
		entryAction = 0
	}

	var localPort, remotePort int
	switch entryDir {
	case 2: // OUTBOUND: local=source, remote=dest
		localPort, remotePort = e.SrcPort, e.DstPort
	default: // INBOUND/unknown: local=dest, remote=source
		localPort, remotePort = e.DstPort, e.SrcPort
	}

	proc := strings.ToLower(strings.TrimSpace(e.ProcessName))
	if proc == "" && e.Path != "" {
		proc = strings.ToLower(baseName(e.Path))
	}

	var out []ruleCandidate
	for i := range rm.rules {
		r := &rm.rules[i]
		if !r.Enabled || r.Action != entryAction {
			continue
		}
		if r.Direction != 0 && r.Direction != entryDir {
			continue
		}
		if r.Protocol != 256 && entryProto != 0 && r.Protocol != entryProto {
			continue
		}
		if !portMatches(r.LocalPorts, localPort) || !portMatches(r.RemotePorts, remotePort) {
			continue
		}
		// A program-scoped rule whose program does NOT match this process is
		// genuinely inapplicable, so it is excluded from even the loose list.
		if r.Program != "" && (proc == "" || !programMatches(r.Program, proc)) {
			continue
		}

		programMatch := r.Program != "" && proc != "" && programMatches(r.Program, proc)
		tightTuple := r.Direction != 0 && r.Protocol != 256 &&
			(specificPort(r.LocalPorts, localPort) || specificPort(r.RemotePorts, remotePort))

		out = append(out, ruleCandidate{
			Name:   r.Name,
			Score:  ruleScore(r),
			Strong: programMatch || tightTuple,
		})
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// Match returns the recognizable firewall rule name for the event, or
// "(No matching rule)" when there is no strong attribute match, or
// "(Rules not loaded)" before the snapshot is ready.
func (rm *RuleMatcher) Match(e *LogEntry) string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if len(rm.rules) == 0 {
		return "(Rules not loaded)"
	}

	cands := rm.candidates(e)

	best := ""
	bestScore := -1
	strongCount := 0
	for _, c := range cands {
		if !c.Strong {
			continue
		}
		strongCount++
		if c.Score > bestScore {
			bestScore = c.Score
			best = c.Name
		}
	}

	if strongCount == 0 {
		return sentinelNoMatch
	}
	if strongCount == 1 {
		return best
	}
	return fmt.Sprintf("%s (+%d more)", best, strongCount-1)
}

// PossibleMatches returns the names of all rules consistent with the event,
// most-specific first, each tagged to show whether it is a strong match. This
// is the looser list shown in the detail view; it includes generic rules that
// Match deliberately suppresses. The returned strings are display-ready, e.g.
// "Allow Chrome (strong)" or "Core Networking (broad)". A nil/empty result
// means no enabled rule's conditions are consistent with the packet.
func (rm *RuleMatcher) PossibleMatches(e *LogEntry, limit int) (lines []string, loaded bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if len(rm.rules) == 0 {
		return nil, false
	}

	cands := rm.candidates(e)
	for i, c := range cands {
		if limit > 0 && i >= limit {
			lines = append(lines, fmt.Sprintf("... and %d more", len(cands)-limit))
			break
		}
		tag := "broad"
		if c.Strong {
			tag = "strong"
		}
		lines = append(lines, fmt.Sprintf("%s (%s)", c.Name, tag))
	}
	return lines, true
}

func ruleScore(r *FirewallRule) int {
	score := 0
	if r.Program != "" {
		score += 8
	}
	if r.Direction != 0 {
		score += 4
	}
	if r.Protocol != 256 {
		score += 4
	}
	if isSpecificPort(r.LocalPorts) {
		score += 2
	}
	if isSpecificPort(r.RemotePorts) {
		score += 2
	}
	return score
}

// programMatches reports whether the rule's program path basename equals proc
// (already lower-cased).
func programMatches(program, procLower string) bool {
	p := strings.ToLower(strings.TrimSpace(program))
	if p == "" || p == "any" || p == "system" {
		return false
	}
	return baseName(p) == procLower
}

func baseName(p string) string {
	if idx := strings.LastIndexAny(p, `\/`); idx >= 0 {
		return p[idx+1:]
	}
	return p
}

func directionToInt(direction string) int32 {
	switch direction {
	case "INBOUND":
		return 1
	case "OUTBOUND":
		return 2
	default:
		return 0
	}
}

// protocolToInt maps either a protocol name (TCP/UDP/...) or an IANA number
// string to the internal protocol code; 256 means "any".
func protocolToInt(p string) int32 {
	switch strings.ToUpper(strings.TrimSpace(p)) {
	case "TCP", "6":
		return 6
	case "UDP", "17":
		return 17
	case "ICMP", "ICMPV4", "1":
		return 1
	case "ICMPV6", "58":
		return 58
	case "", "ANY", "256":
		return 256
	default:
		if n, err := strconv.Atoi(p); err == nil {
			return int32(n)
		}
		return 256
	}
}

// portMatches reports whether port is covered by spec. spec may be "*"/"any"/
// empty (any), a single number, a range "lo-hi", or a comma-separated list.
// Port 0 (not specified) matches any spec.
func portMatches(spec string, port int) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" || strings.EqualFold(spec, "any") {
		return true
	}
	if port == 0 {
		return true
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := parsePortRange(part); ok {
			if port >= lo && port <= hi {
				return true
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil && n == port {
			return true
		}
	}
	return false
}

func parsePortRange(s string) (int, int, bool) {
	dash := strings.IndexByte(s, '-')
	if dash <= 0 || dash == len(s)-1 {
		return 0, 0, false
	}
	lo, err1 := strconv.Atoi(strings.TrimSpace(s[:dash]))
	hi, err2 := strconv.Atoi(strings.TrimSpace(s[dash+1:]))
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return lo, hi, true
}

// isSpecificPort reports whether spec names a concrete port (not a wildcard).
func isSpecificPort(spec string) bool {
	spec = strings.TrimSpace(spec)
	return spec != "" && spec != "*" && !strings.EqualFold(spec, "any")
}

// specificPort reports whether spec names a concrete port that port satisfies.
func specificPort(spec string, port int) bool {
	return isSpecificPort(spec) && portMatches(spec, port)
}
