// Copyright (c) 2026 WinFWMon Contributors
// SPDX-License-Identifier: MIT
//
// Resolves WFP filter run-time IDs (from event 5156/5157 FilterRTID) to the
// governing firewall rule name, by parsing the XML that
// "netsh wfp show filters" produces. This is precise attribution: the filter
// named here is the one WFP actually used to allow or block the connection.
// See LICENSE for full license text.

package main

import (
	"bytes"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"
)

// FilterResolver holds a snapshot mapping WFP filterId -> display name.
// All methods are safe for concurrent use.
type FilterResolver struct {
	mu    sync.RWMutex
	names map[int64]string
}

var globalFilters = &FilterResolver{names: make(map[int64]string)}

// Load runs "netsh wfp show filters" and rebuilds the filterId->name map.
// On error or empty result the previous snapshot is preserved, so a transient
// failure does not blank out rule names already being resolved.
func (fr *FilterResolver) Load() error {
	// file=- writes the XML to stdout instead of a file on disk.
	out, err := runCommand(`netsh wfp show filters file=-`)
	if err != nil {
		dbg("FilterResolver.Load: netsh error: %v", err)
		return err
	}
	dbg("FilterResolver.Load: netsh returned %d bytes", len(out))

	names, perr := parseWFPFilters(out)
	if perr != nil || len(names) == 0 {
		dbg("FilterResolver.Load: parsed %d filters, err=%v (keeping previous)", len(names), perr)
		if perr != nil {
			return perr
		}
		return nil
	}

	fr.mu.Lock()
	fr.names = names
	fr.mu.Unlock()
	dbg("FilterResolver.Load: loaded %d WFP filters", len(names))
	return nil
}

// FilterName returns the low-level WFP filter name for an entry's FilterID
// (the actual filter that allowed/blocked the packet). Returns sentinels when
// the table is not yet loaded or the ID is absent/unnamed.
func (fr *FilterResolver) FilterName(e *LogEntry) string {
	fr.mu.RLock()
	loaded := len(fr.names) > 0
	name := fr.names[int64(e.FilterID)]
	fr.mu.RUnlock()

	if !loaded {
		return "(Filters not loaded)"
	}
	if e.FilterID <= 0 {
		return "(No filter ID)"
	}
	if name == "" {
		return "(Unnamed filter)"
	}
	return name
}

// parseWFPFilters extracts the filterId->name map from netsh XML output.
//
// It does NOT use a strict whole-document XML unmarshal: the netsh output is
// ~4 MB and contains <asString> blobs of raw provider bytes that are not
// well-formed XML, so Go's strict parser aborts the entire document on the
// first bad element (observed: "attribute name without = in element"). Instead
// we scan for just the two tags we need.
//
// Within a filter <item>, netsh emits <displayData><name>RULE</name> near the
// top and <filterId>N</filterId> near the bottom, with nested
// <filterCondition><item>... in between that carry NO name of their own. So we
// simply remember the most recent <name> seen and commit (name, filterId) when
// a <filterId> appears, then clear the pending name. Nested nameless items do
// not disturb this because they contain no <name> tag.
func parseWFPFilters(out string) (map[int64]string, error) {
	text := decodeToUTF8([]byte(out))

	names := make(map[int64]string, 1024)

	const (
		nameOpen  = "<name>"
		nameClose = "</name>"
		fidOpen   = "<filterId>"
		fidClose  = "</filterId>"
	)

	var lastName string
	sampled := 0

	i := 0
	for i < len(text) {
		nextName := indexFrom(text, nameOpen, i)
		nextFid := indexFrom(text, fidOpen, i)

		// Pick whichever of the two tags comes first.
		next, isName := -1, false
		switch {
		case nextName < 0 && nextFid < 0:
			next = -1
		case nextFid < 0:
			next, isName = nextName, true
		case nextName < 0:
			next, isName = nextFid, false
		case nextName < nextFid:
			next, isName = nextName, true
		default:
			next, isName = nextFid, false
		}
		if next < 0 {
			break
		}

		if isName {
			start := next + len(nameOpen)
			end := indexFrom(text, nameClose, start)
			if end < 0 {
				i = start
				continue
			}
			lastName = strings.TrimSpace(text[start:end])
			i = end + len(nameClose)
			continue
		}

		// <filterId>
		start := next + len(fidOpen)
		end := indexFrom(text, fidClose, start)
		if end < 0 {
			i = start
			continue
		}
		idStr := strings.TrimSpace(text[start:end])
		if id, err := strconv.ParseInt(idStr, 10, 64); err == nil && id > 0 {
			if sampled < 3 {
				dbg("parseWFPFilters: sample filterId=%d name=%q", id, lastName)
				sampled++
			}
			if lastName != "" {
				names[id] = lastName
			}
		}
		lastName = "" // consumed; do not leak to the next item
		i = end + len(fidClose)
	}

	dbg("parseWFPFilters: extracted %d named filters", len(names))
	return names, nil
}

// indexFrom returns the index of sub in s at or after position from, or -1.
func indexFrom(s, sub string, from int) int {
	if from >= len(s) {
		return -1
	}
	idx := strings.Index(s[from:], sub)
	if idx < 0 {
		return -1
	}
	return from + idx
}

// decodeToUTF8 converts raw command output to a UTF-8 string, handling the
// UTF-8 BOM and both byte orders of UTF-16 (with BOM). If no BOM is present the
// bytes are assumed already UTF-8 (the common case for netsh console output).
func decodeToUTF8(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}): // UTF-8 BOM
		return string(b[3:])
	case bytes.HasPrefix(b, []byte{0xFF, 0xFE}): // UTF-16 LE BOM
		return decodeUTF16(b[2:], false)
	case bytes.HasPrefix(b, []byte{0xFE, 0xFF}): // UTF-16 BE BOM
		return decodeUTF16(b[2:], true)
	default:
		return string(b)
	}
}

// decodeUTF16 decodes UTF-16 bytes (without BOM) in the given byte order.
func decodeUTF16(b []byte, bigEndian bool) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1] // drop a dangling odd byte rather than panic
	}
	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(u16); i++ {
		if bigEndian {
			u16[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		} else {
			u16[i] = uint16(b[2*i+1])<<8 | uint16(b[2*i])
		}
	}
	return string(utf16.Decode(u16))
}
