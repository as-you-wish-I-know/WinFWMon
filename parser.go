// Copyright (c) 2026 WinFWMon Contributors
// SPDX-License-Identifier: MIT
//
// Core event record type shared across the application. Events are produced by
// the Security event-log source (see eventlog.go) and resolved to rule names by
// the WFP filter table (see wfpfilters.go).
// See LICENSE for full license text.

package main

import "time"

// LogEntry represents a single firewall connection event (WFP 5156/5157).
type LogEntry struct {
	Timestamp       time.Time
	HasTimestamp    bool   // false if the event time could not be parsed
	Action          string // "ALLOW" or "DROP"
	Protocol        string // "TCP", "UDP", "ICMP", etc.
	SrcIP           string
	DstIP           string
	SrcPort         int
	DstPort         int
	Direction       string // "INBOUND", "OUTBOUND", or "UNKNOWN"
	Path            string // process executable name (from the event's Application field)
	PID             int    // process ID (0 if absent/unknown)
	ProcessName     string // resolved from PID; populated after parsing
	FilterID        int    // WFP filter run-time ID (FilterRTID) from the event
	MatchedRuleName string // recognizable Defender Firewall rule (heuristic, by attributes)
	WFPFilterName   string // the actual low-level WFP filter that fired (from FilterID)
	Count           int    // number of collapsed duplicate events (0/1 = single)
	RawLine         string
}
