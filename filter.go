// Copyright (c) 2026 WinFWMon Contributors
// SPDX-License-Identifier: MIT
//
// Filter model for protocol, IP, port, and direction.
// See LICENSE for full license text.

package main

import (
	"strconv"
	"strings"
	"time"
)

// matchField reports whether field matches the user-supplied filter value,
// case-insensitively. The matching mode is chosen by the value's syntax:
//
//   - If value is wrapped in double quotes with at least one character between
//     them (e.g. "192.168.1.1"), it is an EXACT match: field must equal the
//     unquoted text exactly. This lets the user pin an exact value, so
//     "192.168.1.1" matches that address but not 192.168.1.100.
//   - Otherwise value is a SUBSTRING match (the default), so 192.168.1.1 (no
//     quotes) matches both 192.168.1.1 and 192.168.1.100.
//
// A malformed/partial quote (only one quote, or empty "") is NOT treated as
// exact; the literal text (including any quote characters) is used as a
// substring, which keeps mid-typing behavior unsurprising. An empty value
// matches everything (filter inactive).
func matchField(field, value string) bool {
	if value == "" {
		return true
	}
	if len(value) >= 3 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		exact := value[1 : len(value)-1]
		return strings.EqualFold(field, exact)
	}
	return strings.Contains(strings.ToLower(field), strings.ToLower(value))
}

// Filter holds the active filter criteria. An empty string field matches everything.
type Filter struct {
	Protocol    string // case-insensitive substring match against entry protocol
	SourceIP    string // substring match against source IP
	DestIP      string // substring match against destination IP
	SourcePort  string // substring match against the port number, or "" for all; quote for exact
	DestPort    string // substring match against the port number, or "" for all; quote for exact
	Direction   string // exact match: "INBOUND", "OUTBOUND", or "" for all
	Action      string // exact match: "ALLOW", "DROP", or "" for all
	PID         string // exact decimal PID, or "" for all
	Process     string // case-insensitive substring match against process name
	MatchedRule string // case-insensitive substring match against matched rule

	// Negate flags invert the corresponding match (show everything that does
	// NOT match). They have no effect when their filter field is empty.
	ProtocolNegate    bool
	SourceIPNegate    bool
	DestIPNegate      bool
	SourcePortNegate  bool
	DestPortNegate    bool
	PIDNegate         bool
	ProcessNegate     bool
	MatchedRuleNegate bool

	// HideNoMatch, when true, hides events that did not resolve to a
	// recognizable firewall rule (Matched Rule is "(No matching rule)"), so the
	// view shows only events governed by a named rule.
	HideNoMatch bool

	// OnlyAfter, when non-zero, hides entries whose timestamp is before it.
	// Entries with no parsed timestamp are NOT hidden (treated as current),
	// so a timestamp-parse failure never silently drops a live event.
	OnlyAfter time.Time

	// HideNoise, when true, hides high-volume multicast/broadcast chatter
	// (mDNS, SSDP, etc.) so it does not bury ordinary connections. NoisePorts
	// is an OPTIONAL narrowing: when non-empty, only multicast/broadcast traffic
	// whose source or destination port is in the set counts as noise. When
	// empty (the default), ALL multicast/broadcast traffic is treated as noise.
	HideNoise  bool
	NoisePorts map[int]bool

	// HideLoopback, when true, hides traffic where BOTH endpoints are loopback
	// addresses (IPv4 127.0.0.0/8 or IPv6 ::1) — i.e. purely local-to-local
	// chatter. Traffic with only one loopback endpoint is NOT hidden.
	HideLoopback bool

	// IPVersion restricts which IP family is shown: "" or "all" shows both,
	// "ipv4" shows only IPv4 events, "ipv6" shows only IPv6 events. An event
	// whose family cannot be determined (no parseable address) is never hidden.
	IPVersion string
}

// ipFamily classifies an address as "ipv4", "ipv6", or "" (undetermined). The
// rule is simple and matches how the rest of the code distinguishes families:
// a colon means IPv6, a dot means IPv4; anything else (empty/malformed) is
// undetermined.
func ipFamily(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	if strings.Contains(ip, ":") {
		return "ipv6"
	}
	if strings.Contains(ip, ".") {
		return "ipv4"
	}
	return ""
}

// eventIPVersion returns the family of an event, preferring whichever endpoint
// is determinable. If neither endpoint yields a family it returns "" so the
// caller can choose not to hide it.
func eventIPVersion(srcIP, dstIP string) string {
	if fam := ipFamily(srcIP); fam != "" {
		return fam
	}
	return ipFamily(dstIP)
}

// isLoopback reports whether ip is an IPv4 loopback address (127.0.0.0/8) or
// the IPv6 loopback address (::1, in either compressed or expanded form).
func isLoopback(ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}
	if strings.Contains(ip, ":") {
		// IPv6 loopback is exactly ::1. Accept the compressed form and the
		// fully expanded form; ignore any zone suffix (e.g. "::1%1").
		if i := strings.IndexByte(ip, '%'); i >= 0 {
			ip = ip[:i]
		}
		switch strings.ToLower(ip) {
		case "::1", "0:0:0:0:0:0:0:1":
			return true
		}
		return false
	}
	// IPv4: 127.0.0.0/8 — first octet 127.
	dot := strings.IndexByte(ip, '.')
	if dot <= 0 {
		return false
	}
	first, err := strconv.Atoi(ip[:dot])
	if err != nil {
		return false
	}
	return first == 127
}

// isMulticastOrBroadcast reports whether ip is an IPv4/IPv6 multicast address
// or an IPv4 broadcast-style address (ending in .255). Multicast/broadcast is a
// property of the address, not the port, so this is the core noise criterion.
func isMulticastOrBroadcast(ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}
	// IPv6 multicast: ff00::/8 (address begins with "ff", case-insensitive).
	if len(ip) >= 2 && (ip[0] == 'f' || ip[0] == 'F') && (ip[1] == 'f' || ip[1] == 'F') {
		return true
	}
	if strings.Contains(ip, ":") {
		return false // other IPv6
	}
	// IPv4: multicast 224.0.0.0–239.255.255.255 (first octet 224–239), or a
	// limited/subnet broadcast address ending in .255.
	dot := strings.IndexByte(ip, '.')
	if dot <= 0 {
		return false
	}
	first, err := strconv.Atoi(ip[:dot])
	if err != nil {
		return false
	}
	if first >= 224 && first <= 239 {
		return true
	}
	return strings.HasSuffix(ip, ".255")
}

// isNoise reports whether the entry is multicast/broadcast chatter. The
// definition is address-based: either endpoint being a multicast or broadcast
// address makes it noise, regardless of protocol or port. If NoisePorts is
// non-empty it acts as an optional narrowing — only multicast/broadcast traffic
// on one of those ports (source or destination) qualifies — letting a user who
// wants to hide, say, only mDNS restrict the filter to port 5353.
func (f *Filter) isNoise(e *LogEntry) bool {
	if !isMulticastOrBroadcast(e.DstIP) && !isMulticastOrBroadcast(e.SrcIP) {
		return false
	}
	if len(f.NoisePorts) == 0 {
		return true // no narrowing: all multicast/broadcast is noise
	}
	return f.NoisePorts[e.DstPort] || f.NoisePorts[e.SrcPort]
}

// Matches returns true if the entry satisfies all non-empty filter criteria.
// Invalid port strings (non-numeric or out-of-range) match nothing, giving
// the user clear feedback that their filter text has no effect.
func (f *Filter) Matches(e *LogEntry) bool {
	if f.Protocol != "" {
		matched := matchField(e.Protocol, f.Protocol)
		if matched == f.ProtocolNegate {
			return false
		}
	}

	if f.SourceIP != "" {
		matched := matchField(e.SrcIP, f.SourceIP)
		if matched == f.SourceIPNegate {
			return false
		}
	}

	if f.DestIP != "" {
		matched := matchField(e.DstIP, f.DestIP)
		if matched == f.DestIPNegate {
			return false
		}
	}

	if f.SourcePort != "" {
		// Match against the port's string form, so unquoted "80" is a substring
		// match (also matches 8080) and quoted "80" is exact. Port 0 means
		// "unknown/unparsed" and is rendered as "0".
		matched := matchField(strconv.Itoa(e.SrcPort), f.SourcePort)
		if matched == f.SourcePortNegate {
			return false
		}
	}

	if f.DestPort != "" {
		matched := matchField(strconv.Itoa(e.DstPort), f.DestPort)
		if matched == f.DestPortNegate {
			return false
		}
	}

	if f.Direction != "" && !strings.EqualFold(e.Direction, f.Direction) {
		return false
	}

	if f.Action != "" && !strings.EqualFold(e.Action, f.Action) {
		return false
	}

	if f.PID != "" {
		p, err := strconv.Atoi(strings.TrimSpace(f.PID))
		if err != nil || p < 0 {
			// Invalid PID text — match nothing so the active filter is visible.
			return false
		}
		matched := e.PID == p
		if matched == f.PIDNegate {
			return false
		}
	}

	if f.Process != "" {
		matched := matchField(e.ProcessName, f.Process)
		if matched == f.ProcessNegate {
			return false
		}
	}

	if f.MatchedRule != "" {
		matched := matchField(e.MatchedRuleName, f.MatchedRule)
		if matched == f.MatchedRuleNegate {
			return false
		}
	}

	// "Only after launch": hide entries timestamped before the cutoff. Entries
	// with no parsed timestamp are treated as current and kept.
	if !f.OnlyAfter.IsZero() && e.HasTimestamp && e.Timestamp.Before(f.OnlyAfter) {
		return false
	}

	// Hide multicast/broadcast chatter (mDNS, SSDP) when requested.
	if f.HideNoise && f.isNoise(e) {
		return false
	}

	// Hide events with no recognizable firewall rule when requested.
	if f.HideNoMatch && e.MatchedRuleName == sentinelNoMatch {
		return false
	}

	// Hide purely local loopback-to-loopback traffic when requested. Both
	// endpoints must be loopback; traffic with only one loopback end is kept.
	if f.HideLoopback && isLoopback(e.SrcIP) && isLoopback(e.DstIP) {
		return false
	}

	// Restrict to a single IP family when requested. An event whose family
	// cannot be determined is never hidden (matches the loopback precedent:
	// a parse failure must not silently drop events).
	if f.IPVersion == "ipv4" || f.IPVersion == "ipv6" {
		if fam := eventIPVersion(e.SrcIP, e.DstIP); fam != "" && fam != f.IPVersion {
			return false
		}
	}

	return true
}
