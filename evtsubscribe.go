// Copyright (c) 2026 WinFWMon Contributors
// SPDX-License-Identifier: MIT
//
// EvtSubscribe push event source. A low-latency alternative to the PowerShell
// poll source (eventlog.go): instead of spawning Get-WinEvent on a timer, it
// registers a wevtapi push subscription to the Security channel and receives
// 5156/5157 events as they are written, typically surfacing them in well under a
// second versus several seconds for polling.
//
// It produces the SAME *LogEntry values as the poll path — the raw event fields
// are extracted from the same event XML and fed through the same transforms
// (devicePathToFriendly, normaliseEventDirection, protocolNumberToName), a
// parity confirmed field-for-field against the poll path on real machines. All
// downstream work (rule matching, WFP filter resolution, filtering, display) is
// source-agnostic and unchanged.
//
// The wevtapi bindings use NewLazySystemDLL/NewProc (no third-party dependency)
// and were validated working on real Windows. This file is validated
// structurally, not compiled, by its author.

package main

import (
	"encoding/xml"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	evtSubscribeActionDeliver  = 1
	evtSubscribeToFutureEvents = 1
	evtRenderEventXml          = 1

	// EvtQuery flags (for the history-backlog reader).
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200

	// GetLastError code that marks the end of an EvtNext result set.
	errorNoMoreItems = 259
)

var (
	modwevtapi         = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe   = modwevtapi.NewProc("EvtSubscribe")
	procEvtRender      = modwevtapi.NewProc("EvtRender")
	procEvtCloseHandle = modwevtapi.NewProc("EvtClose")
	procEvtQuery       = modwevtapi.NewProc("EvtQuery")
	procEvtNext        = modwevtapi.NewProc("EvtNext")
)

// evtSubscribeSource is a push-based event source satisfying the same
// Start/Stop contract as the PowerShell EventSource, so the UI controls it
// identically.
type evtSubscribeSource struct {
	out      chan *LogEntry
	handle   windows.Handle
	callback uintptr
	stopped  bool
}

// newEvtSubscribeSource creates (but does not start) a push source feeding out.
func newEvtSubscribeSource(out chan *LogEntry) *evtSubscribeSource {
	return &evtSubscribeSource{out: out}
}

// Start registers the subscription. If it returns an error, the caller should
// fall back to the PowerShell source (the binding may be unavailable on some
// systems). Subscribes to future events only; the UI shows new events as they
// arrive, matching the live-monitor model.
func (s *evtSubscribeSource) Start() error {
	s.callback = syscall.NewCallback(func(action uintptr, ctx uintptr, evt uintptr) uintptr {
		if int(action) != evtSubscribeActionDeliver {
			return 0
		}
		xmlStr, err := evtRenderXML(windows.Handle(evt))
		if err != nil {
			dbg("evtsubscribe: render error: %v", err)
			return 0
		}
		if e, ok := parseEventXMLToEntry(xmlStr); ok {
			// Non-blocking send: never stall the wevtapi callback thread. The
			// channel is large; uiPump drains it promptly.
			select {
			case s.out <- e:
			default:
				dbg("evtsubscribe: channel full, dropped an event")
			}
		}
		return 0
	})

	// Subscribe to 5156 and 5157 only, server-side, so the callback is not woken
	// for unrelated Security events (logons, policy changes, etc.).
	const query = "*[System[(EventID=5156 or EventID=5157)]]"
	chanPtr, err := windows.UTF16PtrFromString("Security")
	if err != nil {
		return err
	}
	queryPtr, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return err
	}

	r1, _, callErr := procEvtSubscribe.Call(
		0, // local session
		0, // no signal event (callback form)
		uintptr(unsafe.Pointer(chanPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		0, // no bookmark
		0, // no context
		s.callback,
		uintptr(evtSubscribeToFutureEvents),
	)
	if r1 == 0 {
		return fmt.Errorf("EvtSubscribe failed: %v", callErr)
	}
	s.handle = windows.Handle(r1)
	dbg("evtsubscribe: subscription started")
	return nil
}

// Stop closes the subscription. Safe to call once; idempotent-guarded by the
// caller (startEventSource replaces the source).
func (s *evtSubscribeSource) Stop() {
	if s.stopped {
		return
	}
	s.stopped = true
	if s.handle != 0 {
		procEvtCloseHandle.Call(uintptr(s.handle))
		s.handle = 0
	}
	dbg("evtsubscribe: subscription stopped")
}

// evtRenderXML renders an event handle to XML via the two-call EvtRender
// pattern. Called synchronously inside the delivery callback (the handle is only
// valid for the duration of that call).
func evtRenderXML(evt windows.Handle) (string, error) {
	var bufferUsed, propertyCount uint32
	procEvtRender.Call(
		0, uintptr(evt), uintptr(evtRenderEventXml),
		0, 0,
		uintptr(unsafe.Pointer(&bufferUsed)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)
	if bufferUsed == 0 {
		return "", fmt.Errorf("EvtRender: zero buffer size")
	}
	buf := make([]byte, bufferUsed)
	r1, _, callErr := procEvtRender.Call(
		0, uintptr(evt), uintptr(evtRenderEventXml),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufferUsed)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)
	if r1 == 0 {
		return "", fmt.Errorf("EvtRender failed: %v", callErr)
	}
	n := int(bufferUsed)
	if n > len(buf) {
		n = len(buf)
	}
	u16 := make([]uint16, n/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = uint16(buf[2*i]) | uint16(buf[2*i+1])<<8
	}
	return windows.UTF16ToString(u16), nil
}

// --- Event XML schema (System + EventData) ---

type evtXMLData struct {
	Name string `xml:"Name,attr"`
	Text string `xml:",chardata"`
}

type evtXMLEvent struct {
	System struct {
		EventID     string `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID int64 `xml:"EventRecordID"`
	} `xml:"System"`
	EventData struct {
		Data []evtXMLData `xml:"Data"`
	} `xml:"EventData"`
}

// parseEventXMLToEntry parses a rendered event XML string into a *LogEntry,
// producing the SAME fields the PowerShell poll path produces (verified by the
// parity diagnostic). EventData fields are read by name (order-independent),
// exactly as the poll path reads them. Returns ok=false for non-5156/5157
// events or unparseable XML.
func parseEventXMLToEntry(xmlStr string) (*LogEntry, bool) {
	var e evtXMLEvent
	if err := xml.Unmarshal([]byte(xmlStr), &e); err != nil {
		return nil, false
	}

	eid := strings.TrimSpace(e.System.EventID)
	action := ""
	switch eid {
	case "5156":
		action = "ALLOW"
	case "5157":
		action = "DROP"
	default:
		return nil, false // not a WFP connection event
	}

	d := make(map[string]string, len(e.EventData.Data))
	for _, item := range e.EventData.Data {
		d[item.Name] = item.Text
	}

	// Timestamp: SystemTime is UTC; convert to local, mirroring the poll path
	// which parses TimeCreated and calls .Local().
	var ts time.Time
	hasTS := false
	if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(e.System.TimeCreated.SystemTime)); err == nil {
		ts = t.Local()
		hasTS = true
	}

	appPath := strings.TrimSpace(d["Application"])
	appName := devicePathToFriendly(appPath)
	pid := atoiOr0(d["ProcessID"])

	entry := &LogEntry{
		Timestamp:    ts,
		HasTimestamp: hasTS,
		Action:       action,
		Direction:    normaliseEventDirection(strings.TrimSpace(d["Direction"])),
		SrcIP:        strings.TrimSpace(d["SourceAddress"]),
		SrcPort:      atoiOr0(d["SourcePort"]),
		DstIP:        strings.TrimSpace(d["DestAddress"]),
		DstPort:      atoiOr0(d["DestPort"]),
		Protocol:     protocolNumberToName(strings.TrimSpace(d["Protocol"])),
		Path:         appName,
		ProcessName:  appName,
		PID:          pid,
		FilterID:     atoiOr0(d["FilterRTID"]),
		RawLine:      fmt.Sprintf("EvtSubscribe RecordId=%d EventID=%s", e.System.EventRecordID, eid),
	}
	return entry, true
}

// readBacklogViaEvtQuery reads up to maxEvents of the most recent 5156/5157
// events from the Security log using EvtQuery/EvtNext (the pull-based sibling of
// EvtSubscribe), rendering each with the same EvtRender path and parsing it with
// the same parseEventXMLToEntry used by the live source. This replaces the slow
// PowerShell [xml] DOM backlog read used in history mode (which built an XML DOM
// per event and took ~20s for a few thousand events).
//
// Events are queried newest-first (reverse direction) so we can stop after
// maxEvents, then returned in chronological (oldest-first) order to match how
// the rest of the app expects a backlog. Each event handle from EvtNext is
// rendered and then closed individually.
//
// It honors stopCh: if that channel is closed mid-read (app shutting down), it
// stops early and returns what it has so far.
func readBacklogViaEvtQuery(maxEvents int, stopCh <-chan struct{}) ([]*LogEntry, error) {
	const query = "*[System[(EventID=5156 or EventID=5157)]]"

	pathPtr, err := windows.UTF16PtrFromString("Security")
	if err != nil {
		return nil, err
	}
	queryPtr, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return nil, err
	}

	r1, _, callErr := procEvtQuery.Call(
		0, // local session
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		uintptr(evtQueryChannelPath|evtQueryReverseDirection),
	)
	if r1 == 0 {
		return nil, fmt.Errorf("EvtQuery failed: %v", callErr)
	}
	resultSet := windows.Handle(r1)
	defer procEvtCloseHandle.Call(uintptr(resultSet))

	// Collected newest-first; reversed to chronological before returning.
	out := make([]*LogEntry, 0, maxEvents)

	const batchSize = 64
	var batch [batchSize]windows.Handle

readLoop:
	for len(out) < maxEvents {
		// Cooperative shutdown check between batches.
		select {
		case <-stopCh:
			break readLoop
		default:
		}

		var returned uint32
		rNext, _, nextErr := procEvtNext.Call(
			uintptr(resultSet),
			uintptr(batchSize),
			uintptr(unsafe.Pointer(&batch[0])),
			uintptr(0xFFFFFFFF), // INFINITE timeout
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if rNext == 0 {
			// FALSE: either end of set (ERROR_NO_MORE_ITEMS) or a real error.
			if en, ok := nextErr.(syscall.Errno); ok && uintptr(en) == errorNoMoreItems {
				break
			}
			// Any other error: stop, but return what we have.
			dbg("readBacklogViaEvtQuery: EvtNext error: %v", nextErr)
			break
		}
		n := int(returned)
		for i := 0; i < n; i++ {
			h := batch[i]
			xmlStr, rerr := evtRenderXML(h)
			if rerr == nil {
				if e, ok := parseEventXMLToEntry(xmlStr); ok {
					out = append(out, e)
				}
			}
			procEvtCloseHandle.Call(uintptr(h))
			if len(out) >= maxEvents {
				// Close any remaining handles in this batch before stopping.
				for j := i + 1; j < n; j++ {
					procEvtCloseHandle.Call(uintptr(batch[j]))
				}
				break
			}
		}
		if n == 0 {
			break
		}
	}

	// out is newest-first; reverse to chronological (oldest-first).
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}
