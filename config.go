// Copyright (c) 2026 WinFWMon Contributors
// SPDX-License-Identifier: MIT
//
// Persistence of UI preferences to a JSON file beside the executable: noise
// ports, the toggle states, event-window size, time-display settings, the
// column layout (visibility, width, visual order), and the filter-bar state.
// Loading never fails the app: any error falls back to built-in defaults, so a
// missing or corrupt config is harmless.
// See LICENSE for full license text.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// config is the on-disk preference set. Pointers are used for the booleans so
// that a field absent from an older/partial config file is distinguishable
// from an explicit false, letting loadConfig apply the documented default
// rather than silently forcing the zero value.
type config struct {
	NoisePorts  []int `json:"noisePorts,omitempty"`
	HideNoise   *bool `json:"hideNoise,omitempty"`
	Collapse    *bool `json:"collapseDuplicates,omitempty"`
	OnlyAfter   *bool `json:"onlyAfterLaunch,omitempty"`
	LiveTail    *bool `json:"liveTail,omitempty"`
	HideNoMatch *bool `json:"hideNoMatch,omitempty"`
	HighlightICMP *bool `json:"highlightICMP,omitempty"`
	HideLoopback *bool `json:"hideLoopback,omitempty"`
	WindowSize  *int  `json:"windowSize,omitempty"`
	TimePrecision *string `json:"timePrecision,omitempty"`
	TimeZone      *string `json:"timeZone,omitempty"`

	// Column layout: per-column visibility and width (keyed by stable title so a
	// future reordering of columnDefs cannot misapply a saved layout), plus the
	// visual (drag) order as a list of titles. Mirrors WinFWRules.
	Columns     []columnState `json:"columns,omitempty"`
	ColumnOrder []string      `json:"columnOrder,omitempty"`

	// Filters holds the persisted filter-bar state that is NOT already captured
	// by the dedicated toggle fields above (HideNoise/OnlyAfter/etc.). It is a
	// single nested object so the ~dozen text fields, dropdowns, and negate flags
	// stay grouped; an absent block means "no saved filters" (all empty).
	Filters *filterState `json:"filters,omitempty"`
}

// columnState records one column's persisted layout by title (stable across
// versions even if column order in code changes).
type columnState struct {
	Title   string `json:"title"`
	Visible bool   `json:"visible"`
	Width   int    `json:"width"`
}

// filterState is the persisted snapshot of the text/dropdown filter controls
// and their negate flags. The launch-time "Only after launch" cutoff is NOT
// stored here: its checked state persists via config.OnlyAfter, but the cutoff
// itself is per-session (it means "since this run started") and is recomputed
// from the current launch time each run, so a stored timestamp would be
// meaningless. See applyFilters.
type filterState struct {
	Protocol    string `json:"protocol,omitempty"`
	SrcIP       string `json:"srcIP,omitempty"`
	DstIP       string `json:"dstIP,omitempty"`
	SrcPort     string `json:"srcPort,omitempty"`
	DstPort     string `json:"dstPort,omitempty"`
	Direction   string `json:"direction,omitempty"`
	Action      string `json:"action,omitempty"`
	IPVersion   string `json:"ipVersion,omitempty"` // dropdown display text, e.g. "IPv4 only"
	PID         string `json:"pid,omitempty"`
	Process     string `json:"process,omitempty"`
	MatchedRule string `json:"matchedRule,omitempty"`

	ProtocolNot    bool `json:"protocolNot,omitempty"`
	SrcIPNot       bool `json:"srcIPNot,omitempty"`
	DstIPNot       bool `json:"dstIPNot,omitempty"`
	SrcPortNot     bool `json:"srcPortNot,omitempty"`
	DstPortNot     bool `json:"dstPortNot,omitempty"`
	PIDNot         bool `json:"pidNot,omitempty"`
	ProcessNot     bool `json:"processNot,omitempty"`
	MatchedRuleNot bool `json:"matchedRuleNot,omitempty"`
}

// configPath returns the path for the config file. If --config=<path> was
// given on the command line that path is used; otherwise it defaults to
// WinFWMon.json in the same directory as the executable. If the executable
// path cannot be determined it falls back to a bare filename in the working
// directory.
func configPath() string {
	if app.configOverride != "" {
		return app.configOverride
	}
	exe, err := os.Executable()
	if err != nil {
		return "WinFWMon.json"
	}
	return filepath.Join(filepath.Dir(exe), "WinFWMon.json")
}

// validateConfigOverride checks that a user-supplied --config path is usable:
// its parent directory must exist and the file must be writable (or creatable).
// Returns an error describing the problem, or nil if the path is fine. This is
// used to fail loudly at startup rather than silently falling back to the
// default location, which would mean the user's settings quietly do not persist
// where they asked.
func validateConfigOverride(path string) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("directory %q does not exist or is not accessible: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", dir)
	}
	// Probe writability by opening the target for append/create without
	// truncating any existing config, then close it. If the file did not already
	// exist, remove the probe file so validation has no side effect (previously
	// it left an empty file behind).
	_, statErr := os.Stat(path)
	preexisting := statErr == nil

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("config file %q is not writable: %w", path, err)
	}
	_ = f.Close()

	if !preexisting {
		if rmErr := os.Remove(path); rmErr != nil {
			dbg("validateConfigOverride: could not remove probe file %s: %v", path, rmErr)
		}
	}
	return nil
}

// loadConfig reads the config file. A missing or unreadable/corrupt file is not
// an error: it returns an empty config (all-default) and ok=false so the caller
// can simply apply defaults. ok=true means a file was successfully parsed.
func loadConfig() (config, bool) {
	var c config
	data, err := os.ReadFile(configPath())
	if err != nil {
		dbg("loadConfig: no config read (%v); using defaults", err)
		return c, false
	}
	if err := json.Unmarshal(data, &c); err != nil {
		dbg("loadConfig: corrupt config (%v); using defaults", err)
		return config{}, false
	}
	dbg("loadConfig: loaded config from %s", configPath())
	return c, true
}

// save writes the config to disk. Errors are logged but not fatal — failing to
// persist preferences should never interrupt the user.
func (c config) save() {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		dbg("config.save: marshal error: %v", err)
		return
	}
	if err := os.WriteFile(configPath(), data, 0644); err != nil {
		dbg("config.save: write error: %v", err)
		return
	}
	dbg("config.save: wrote %s", configPath())
}

// boolPtr returns a pointer to b, for building a config to save.
func boolPtr(b bool) *bool { return &b }

// portsToSortedSlice converts a port set to a sorted slice for stable on-disk
// ordering (so the file does not churn between saves).
func portsToSortedSlice(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// portsFromSlice converts a slice of ports to a set, ignoring out-of-range
// values. Returns nil if the slice yields no valid ports, so the caller can
// fall back to defaults.
func portsFromSlice(s []int) map[int]bool {
	out := make(map[int]bool, len(s))
	for _, p := range s {
		if p > 0 && p <= 65535 {
			out[p] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ---- Column layout (title-keyed) helpers, mirroring WinFWRules ----

// columnDefIndex returns the index of the column with the given title in
// columnDefs, or -1 if there is no such column.
func columnDefIndex(title string) int {
	for i := range columnDefs {
		if columnDefs[i].title == title {
			return i
		}
	}
	return -1
}

// columnTitlesToCompleteOrder converts a saved list of column titles to a full
// logical order: each recognised, not-yet-seen title in turn, then any columns
// whose titles were absent from the saved list appended in their natural order.
// The result is always a complete permutation of all column indices, so it is
// safe to hand to setColumnOrder even if the saved file predates a new column.
func columnTitlesToCompleteOrder(titles []string) []int {
	seen := map[string]bool{}
	order := make([]int, 0, len(columnDefs))
	for _, title := range titles {
		idx := columnDefIndex(title)
		if idx < 0 || seen[title] {
			continue
		}
		seen[title] = true
		order = append(order, idx)
	}
	for i := range columnDefs {
		if !seen[columnDefs[i].title] {
			order = append(order, i)
		}
	}
	return order
}

// columnOrderTitleSlice renders a logical column order as the list of column
// titles, for stable title-keyed persistence.
func columnOrderTitleSlice(order []int) []string {
	titles := make([]string, 0, len(order))
	for _, i := range order {
		if i >= 0 && i < len(columnDefs) {
			titles = append(titles, columnDefs[i].title)
		}
	}
	return titles
}
