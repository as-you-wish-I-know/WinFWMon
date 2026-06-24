// Copyright (c) 2026 WinFWMon Contributors
// SPDX-License-Identifier: MIT
//
// Entry point, UI, table model, live-tail pump.
// See LICENSE for full license text.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

// Application identity. appVersion is the single source of truth for the
// version shown in the window title and About dialog.
const (
	appName    = "WinFWMon"
	appVersion = "1.0"
)

// Window-size bounds. The "event window" is the maximum number of events held
// in memory; when exceeded, the oldest are dropped in bulk so the model never
// reallocates on every insertion. The size is user-configurable (Preferences →
// Event Window, or persisted in the config file) within these bounds.
const (
	defaultWindowSize = 2000
	minWindowSize     = 100
	maxWindowSize     = 50000
)

// trimKeepFraction is the fraction of the window retained after a trim. Keeping
// below 100% gives headroom so a trim is not triggered again on the very next
// insertion (which would thrash). 0.9 keeps the trim batch at 10% of the window.
const trimKeepFraction = 0.9

// ---- Table Model ----

// columnDef describes one table column: its heading, default width, whether it
// is hidden by default, and how to extract its display value from an entry.
type columnDef struct {
	title         string
	width         int
	hiddenDefault bool
	value         func(e *LogEntry) string
}

// columnDefs is the ordered list of all available columns. The TableView is
// built from this list, and the column-visibility dialog toggles entries here.
// Keeping a single source of truth avoids the scattered hard-coded indices the
// model used previously.
var columnDefs = []columnDef{
	{title: "Date", width: 90, hiddenDefault: true, value: func(e *LogEntry) string {
		if !e.HasTimestamp {
			return "-"
		}
		return eventTimeIn(e.Timestamp).Format("2006-01-02")
	}},
	{title: "Time", width: 95, value: func(e *LogEntry) string {
		if !e.HasTimestamp {
			return "-"
		}
		return formatEventTime(e.Timestamp)
	}},
	{title: "Action", width: 60, value: func(e *LogEntry) string { return e.Action }},
	{title: "Count", width: 55, hiddenDefault: true, value: func(e *LogEntry) string {
		if e.Count > 1 {
			return strconv.Itoa(e.Count)
		}
		return ""
	}},
	{title: "Direction", width: 80, value: func(e *LogEntry) string { return e.Direction }},
	{title: "Protocol", width: 65, value: func(e *LogEntry) string { return e.Protocol }},
	{title: "Source IP", width: 130, value: func(e *LogEntry) string { return e.SrcIP }},
	{title: "Src Port", width: 65, value: func(e *LogEntry) string { return portString(e.SrcPort) }},
	{title: "Dest IP", width: 130, value: func(e *LogEntry) string { return e.DstIP }},
	{title: "Dst Port", width: 65, value: func(e *LogEntry) string { return portString(e.DstPort) }},
	{title: "PID", width: 60, value: func(e *LogEntry) string {
		if e.PID > 0 {
			return strconv.Itoa(e.PID)
		}
		return ""
	}},
	{title: "Process", width: 140, value: func(e *LogEntry) string { return e.ProcessName }},
	{title: "Matched Rule", width: 300, value: func(e *LogEntry) string { return e.MatchedRuleName }},
	{title: "WFP Filter", width: 220, hiddenDefault: true, value: func(e *LogEntry) string { return e.WFPFilterName }},
}

// portString renders a port number, or "" for the zero/placeholder value.
func portString(port int) string {
	if port > 0 {
		return strconv.Itoa(port)
	}
	return ""
}

// eventTimeIn returns t converted to the user-selected display zone (local by
// default, or UTC if configured). All event-time rendering goes through this so
// the Date column, Time column, and detail/export views agree.
func eventTimeIn(t time.Time) time.Time {
	if app.timeZone == "utc" {
		return t.UTC()
	}
	return t.Local()
}

// timeLayout returns the clock-time format string for the configured precision.
func timeLayout() string {
	switch app.timePrecision {
	case "millis":
		return "15:04:05.000"
	case "micros":
		return "15:04:05.000000"
	default: // "seconds" or unset
		return "15:04:05"
	}
}

// formatEventTime renders an event timestamp's clock time in the configured
// zone and precision. Used by the Time column, the detail view, and export.
func formatEventTime(t time.Time) string {
	return eventTimeIn(t).Format(timeLayout())
}

// timeColumnTitle returns the Time column header, annotated with the zone when
// UTC is selected so the displayed times are never ambiguous.
func timeColumnTitle() string {
	if app.timeZone == "utc" {
		return "Time (UTC)"
	}
	return "Time"
}

// entryModel is the walk TableView data source.
// It maintains two slices: all (unfiltered) and visible (current filter applied).
// mu protects both slices; it must be held for any read or write.
type entryModel struct {
	walk.TableModelBase
	mu            sync.RWMutex
	all           []*LogEntry
	visible       []*LogEntry // filtered entries, one per event
	display       []*LogEntry // what the table shows: visible, or a collapsed view
	filter        Filter
	collapse      bool // collapse duplicate multicast rows in the display
	highlightICMP bool // colour ICMP/ICMPv6 rows with paler shades
	maxRows       int  // window size: max entries retained (0 until set)
	keepRows      int  // entries retained after a trim (derived from maxRows)
}

func newEntryModel() *entryModel {
	m := &entryModel{}
	m.maxRows = defaultWindowSize
	m.keepRows = int(float64(defaultWindowSize) * trimKeepFraction)
	return m
}

// setWindowSize updates the in-memory event-window cap at runtime. If the new
// cap is smaller than the current contents, the oldest entries are trimmed
// immediately and the visible/display slices rebuilt; the caller is responsible
// for publishing a reset afterwards. Returns true if the visible set changed
// (so the caller knows whether a republish/repaint is needed).
func (m *entryModel) setWindowSize(n int) bool {
	if n < minWindowSize {
		n = minWindowSize
	}
	if n > maxWindowSize {
		n = maxWindowSize
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxRows = n
	m.keepRows = int(float64(n) * trimKeepFraction)
	if m.keepRows < 1 {
		m.keepRows = 1
	}
	changed := false
	// Trim the unfiltered set down to the new cap if needed.
	if len(m.all) > m.maxRows {
		m.all = trimOldest(m.all, m.keepRows)
	}
	// Trim the visible set too; if it shrinks, the table changes.
	if len(m.visible) > m.maxRows {
		m.visible = trimOldest(m.visible, m.keepRows)
		changed = true
	}
	if changed {
		m.rebuildDisplay()
	}
	return changed
}

// trimOldest returns a fresh slice containing the last keep entries of in,
// dropping the oldest. A new backing array is allocated so the old (larger)
// one can be garbage-collected rather than pinned by a reslice.
func trimOldest(in []*LogEntry, keep int) []*LogEntry {
	if keep >= len(in) {
		return in
	}
	fresh := make([]*LogEntry, keep, keep+keep/9+1)
	copy(fresh, in[len(in)-keep:])
	return fresh
}

// setHighlightICMP toggles the paler-colour treatment for ICMP/ICMPv6 rows.
func (m *entryModel) setHighlightICMP(on bool) {
	m.mu.Lock()
	m.highlightICMP = on
	m.mu.Unlock()
}

// rebuildDisplay recomputes the display slice from visible, applying collapse
// if enabled. Caller must hold m.mu (write).
func (m *entryModel) rebuildDisplay() {
	if !m.collapse {
		m.display = m.visible
		return
	}
	m.display = collapseNoise(m.visible, &m.filter)
}

// RowCount satisfies walk.TableModel. Called on the UI goroutine.
func (m *entryModel) RowCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.display)
}

// Value satisfies walk.TableModel. Walk may call this with any row index
// including negative values during repaints; both bounds are checked.
func (m *entryModel) Value(row, col int) interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if row < 0 || row >= len(m.display) {
		return nil
	}
	if col < 0 || col >= len(columnDefs) {
		return nil
	}
	return columnDefs[col].value(m.display[row])
}

// StyleCell sets the row background by action: green for ALLOW, red for DROP.
// When ICMP highlighting is on, ICMP/ICMPv6 rows use a noticeably paler shade
// of the same colour (pale green if allowed, pale red if dropped) so control
// messages stand out from ordinary traffic. Walk may pass row=-1 during
// repaints; bounds are checked.
func (m *entryModel) StyleCell(style *walk.CellStyle) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	row := style.Row()
	if row < 0 || row >= len(m.display) {
		return
	}
	e := m.display[row]
	icmp := m.highlightICMP && (e.Protocol == "ICMP" || e.Protocol == "ICMPv6")
	switch e.Action {
	case "DROP":
		if icmp {
			style.BackgroundColor = walk.RGB(225, 150, 150) // pale red
			style.TextColor = walk.RGB(0, 0, 0)
		} else {
			style.BackgroundColor = walk.RGB(180, 40, 40)
			style.TextColor = walk.RGB(255, 255, 255)
		}
	case "ALLOW":
		if icmp {
			style.BackgroundColor = walk.RGB(170, 215, 180) // pale green
			style.TextColor = walk.RGB(0, 0, 0)
		} else {
			style.BackgroundColor = walk.RGB(34, 120, 60)
			style.TextColor = walk.RGB(255, 255, 255)
		}
	}
}

// addEntry ingests e. It always appends to the unfiltered slice (all). It
// appends to the visible slice ONLY when live (paused==false); while paused the
// visible slice is left frozen so it stays consistent with what the TableView
// last painted — walk requires the model to be stable between publish calls,
// and mutating visible without publishing causes stale/garbage/<nil> rows on
// repaint. Paused entries are still captured in all and become visible on
// resume via rebuildVisible.
//
// When a slice reaches the window size (maxRows) the oldest entries are dropped
// in one bulk operation (down to keepRows) to amortise allocation.
//
// Returns visibleChanged=true if the visible slice was modified, so the caller
// can skip the repaint/auto-scroll when nothing the filter shows changed.
func (m *entryModel) addEntry(e *LogEntry, paused bool) (visibleChanged bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.all = append(m.all, e)
	if len(m.all) > m.maxRows {
		m.all = trimOldest(m.all, m.keepRows)
	}

	if paused {
		return false
	}

	if m.filter.Matches(e) {
		m.visible = append(m.visible, e)
		visibleChanged = true
		if len(m.visible) > m.maxRows {
			m.visible = trimOldest(m.visible, m.keepRows)
		}
		// NOTE: display is intentionally NOT rebuilt here. addEntry is called in
		// a per-entry loop over a batch; rebuilding the (possibly collapsed)
		// display on every entry would be O(n²) across a large burst. The caller
		// rebuilds the display once after the batch via refreshDisplay().
	}
	return visibleChanged
}

// refreshDisplay rebuilds the display slice once (e.g. after a batch of
// addEntry calls). Safe to call on the UI goroutine.
func (m *entryModel) refreshDisplay() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rebuildDisplay()
}

// republishTable tells the TableView its data changed AND forces a full
// viewport repaint. PublishRowsReset alone updates walk's row count, but when a
// change keeps a similar row count while altering row *contents* (e.g. a filter
// that swaps which events occupy the visible rows), walk may not repaint cells
// whose row indices still exist — leaving stale text on screen that looks like
// rows the filter should have removed. Invalidate() forces those cells to
// repaint. Must run on the UI goroutine.
func republishTable() {
	app.model.PublishRowsReset()
	if app.table != nil {
		app.table.Invalidate()
	}
}

// collapseNoise returns a display slice in which multicast/broadcast "noise"
// events that share an identical key (action, direction, protocol, src/dst
// IP+port, and PID) are merged into a single representative row whose Count
// records how many were merged. Non-noise events, and noise events that differ
// in any key field, pass through unchanged with Count 0.
//
// nf supplies the noise classification (its NoisePorts set), so collapse uses
// exactly the same definition of "noise" as the hide filter — keeping the two
// features consistent when the user customises the port set.
//
// The representative is a shallow COPY so the original entries (shared with the
// all/visible slices) are never mutated. Grouping is global so scattered
// repeats collapse to one row; the row keeps the latest occurrence's timestamp.
func collapseNoise(in []*LogEntry, nf *Filter) []*LogEntry {
	if len(in) == 0 {
		return in
	}
	type key struct {
		action, dir, proto, sip, dip string
		sport, dport, pid            int
	}
	groups := make(map[key]*LogEntry)
	out := make([]*LogEntry, 0, len(in))

	for _, e := range in {
		if !nf.isNoise(e) {
			out = append(out, e)
			continue
		}
		k := key{e.Action, e.Direction, e.Protocol, e.SrcIP, e.DstIP,
			e.SrcPort, e.DstPort, e.PID}
		if rep, ok := groups[k]; ok {
			rep.Count++
			if e.HasTimestamp && (!rep.HasTimestamp || e.Timestamp.After(rep.Timestamp)) {
				rep.Timestamp = e.Timestamp
				rep.HasTimestamp = true
			}
			continue
		}
		cp := *e // shallow copy; never mutate the shared original
		cp.Count = 1
		groups[k] = &cp
		out = append(out, &cp)
	}
	return out
}

// rebuildVisible recomputes the visible slice from all entries under the
// current filter. Used on resume (after a paused interval during which only
// all was updated) and anywhere the visible slice must be resynchronised with
// the full set.
func (m *entryModel) rebuildVisible() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.visible = nil
	for _, e := range m.all {
		if m.filter.Matches(e) {
			m.visible = append(m.visible, e)
		}
	}
	m.rebuildDisplay()
}

// setCollapse toggles collapsed display and rebuilds the display slice.
func (m *entryModel) setCollapse(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.collapse = on
	m.rebuildDisplay()
}

// applyFilter replaces the active filter and rebuilds the visible slice.
func (m *entryModel) applyFilter(f Filter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.filter = f
	// Rebuild into a fresh nil slice to release the old backing array.
	m.visible = nil
	for _, e := range m.all {
		if f.Matches(e) {
			m.visible = append(m.visible, e)
		}
	}
	m.rebuildDisplay()
}

// clear releases all stored entries and frees backing arrays for GC.
func (m *entryModel) clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.all = nil
	m.visible = nil
	m.display = nil
}

// visibleSnapshot returns a shallow copy of the currently displayed rows
// (collapsed if collapse is on), taken under lock so it is safe to iterate
// after the call. Pointers are shared; entries are effectively immutable once
// displayed, so reading their fields is safe. Used by export so the file
// matches exactly what is on screen.
func (m *entryModel) visibleSnapshot() []*LogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*LogEntry, len(m.display))
	copy(out, m.display)
	return out
}

// ---- App State ----

// appState holds all mutable runtime state for the application.
//
// Concurrency rules:
//   - All UI control fields (mw, table, etc.) are set once by buildUI and
//     accessed only on the UI goroutine thereafter.
//   - paused and logPath are only read/written on the UI goroutine.
//   - totalCount is protected by mu; it is written inside mw.Synchronize
//     (UI goroutine) so the lock is technically redundant today, but is
//     retained in case background code ever needs to read it.
//   - pumpStop is closed by the UI goroutine on exit to terminate uiPump.
type appState struct {
	model            *entryModel
	eventSource      *EventSource
	entryChan        chan *LogEntry
	pumpStop         chan struct{} // closed to terminate uiPump goroutine
	pumpStopOnce     sync.Once     // guards the close of pumpStop
	paused           bool
	logPath          string
	uiReady          bool          // true once all UI control refs are wired in buildUI
	restoreOnExit    bool          // restore prior audit policy on exit
	auditEnabledByUs bool          // true if we changed the audit policy
	auditingOn       bool          // current runtime state of WFP connection auditing
	priorAuditState  wfpAuditState // audit state before we changed it
	startStopBtn     *walk.PushButton
	reloadBtn        *walk.PushButton
	reloadAction     *walk.Action
	reloadingRules   atomic.Bool
	launchTime       time.Time
	noisePorts       map[int]bool // UDP ports treated as multicast/broadcast noise
	windowSize       int          // configured event-window size (0 = default)
	timePrecision    string       // "seconds" | "millis" | "micros" (default seconds)
	timeZone         string       // "local" | "utc" (default local)
	loadedConfig     config       // preferences read at startup, applied in buildUI
	historyMode      bool         // --history: show existing events only, no auditing/polling
	configOverride   string       // --config=<path>: non-default config location ("" = default)

	totalCount int
	mu         sync.Mutex

	// Walk UI controls — UI goroutine only after buildUI returns.
	mw                 *walk.MainWindow
	table              *walk.TableView
	statusBar          *walk.StatusBarItem
	countBar           *walk.StatusBarItem
	pauseBtn           *walk.PushButton
	filterProto        *walk.LineEdit
	filterProtoNot     *walk.CheckBox
	filterSrcIP        *walk.LineEdit
	filterDstIP        *walk.LineEdit
	filterSrcPort      *walk.LineEdit
	filterDstPort      *walk.LineEdit
	filterDirection    *walk.ComboBox
	filterAction       *walk.ComboBox
	filterIPVersion    *walk.ComboBox
	filterPID          *walk.LineEdit
	filterProcess      *walk.LineEdit
	filterRule         *walk.LineEdit
	filterPIDNot       *walk.CheckBox
	filterProcNot      *walk.CheckBox
	filterRuleNot      *walk.CheckBox
	filterSrcIPNot     *walk.CheckBox
	filterDstIPNot     *walk.CheckBox
	filterSrcPortNot   *walk.CheckBox
	filterDstPortNot   *walk.CheckBox
	filterHideNoMatch  *walk.CheckBox
	onlyAfterCheck     *walk.CheckBox
	hideNoiseCheck     *walk.CheckBox
	collapseCheck      *walk.CheckBox
	hideLoopbackCheck  *walk.CheckBox
	highlightICMPCheck *walk.CheckBox
	liveTailCheck      *walk.CheckBox
}

var app = &appState{}

// setStatus updates the status bar text. Nil-safe for the pre-realisation window.
func setStatus(text string) {
	if app.statusBar != nil {
		app.statusBar.SetText(text)
	}
}

// setCount updates the count bar text. Nil-safe for the pre-realisation window.
func setCount(text string) {
	if app.countBar != nil {
		app.countBar.SetText(text)
	}
}

func main() {
	// Parse all command-line arguments up front. Headless commands (--help,
	// --wfp[=on|off]) run and exit here without ever creating a window.
	cli, exitNow, code := parseAndDispatchArgs(os.Args[1:])
	if exitNow {
		os.Exit(code)
	}
	if cli.debug {
		enableDebugLogging()
	}
	app.historyMode = cli.history
	app.configOverride = cli.configPath

	defer func() {
		if r := recover(); r != nil {
			// Best-effort: restore any audit policy we changed before crashing.
			// Wrap in its own recover so a failure here does not hide the
			// original error.
			func() {
				defer func() { recover() }() //nolint:errcheck
				if app.auditEnabledByUs {
					restoreWFPAuditing(app.priorAuditState)
				}
			}()
			showFatalError(fmt.Sprintf("Unexpected crash:\n\n%v", r))
		}
	}()

	app.model = newEntryModel()
	app.entryChan = make(chan *LogEntry, 500)
	app.pumpStop = make(chan struct{})
	app.launchTime = time.Now()
	// Empty noise-port set = treat ALL multicast/broadcast as noise (the
	// default). A non-empty set is an optional narrowing the user can configure.
	app.noisePorts = map[int]bool{}

	// If a custom config location was requested, validate it now and fail loudly
	// rather than silently falling back to the default (which would mean the
	// user's settings quietly do not persist where they asked).
	if err := validateConfigOverride(app.configOverride); err != nil {
		showFatalError(fmt.Sprintf(
			"The configuration path specified with --config cannot be used:\n\n%v",
			err))
		os.Exit(1)
	}

	// Defaults for time display; overridden by config below if present.
	app.timePrecision = "seconds"
	app.timeZone = "local"

	// Load persisted preferences. Defaults already set above stay in effect for
	// anything the config does not specify. Checkbox states are applied later in
	// buildUI (once the controls exist); noise ports can be applied now.
	if cfg, ok := loadConfig(); ok {
		app.loadedConfig = cfg
		// nil means "no narrowing"; only override the empty default when the
		// config actually specified ports.
		if ports := portsFromSlice(cfg.NoisePorts); ports != nil {
			app.noisePorts = ports
		}
		if cfg.WindowSize != nil {
			app.windowSize = *cfg.WindowSize
		}
		if cfg.TimePrecision != nil {
			app.timePrecision = *cfg.TimePrecision
		}
		if cfg.TimeZone != nil {
			app.timeZone = *cfg.TimeZone
		}
	}
	// Apply the (clamped) window size to the model before any events arrive.
	app.model.setWindowSize(effectiveWindowSize())

	// Load the WFP filter table (for the precise WFP Filter column) and the
	// Defender Firewall rules (for the recognizable Matched Rule column) in the
	// background. Both resolvers return sentinels until their load completes.
	go func() {
		if err := globalFilters.Load(); err != nil {
			dbg("startup: initial filter load failed: %v", err)
		}
	}()
	go func() {
		if err := globalMatcher.LoadRules(); err != nil {
			dbg("startup: initial rule load failed: %v", err)
		}
	}()

	if err := buildUI(); err != nil {
		showFatalError(fmt.Sprintf(
			"Failed to create main window:\n\n%v\n\n"+
				"Common causes:\n"+
				"  - Missing rsrc.syso  (re-run build.bat)\n"+
				"  - Windows version too old (requires Windows 10+)",
			err))
	}
}

// showFatalError writes msg to stderr, shows a Win32 MessageBox, then exits.
// Uses raw Win32 so it works even if walk never initialised.
func showFatalError(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	title, _ := syscall.UTF16PtrFromString("WinFWMon - Fatal Error")
	text, _ := syscall.UTF16PtrFromString(msg)
	user32 := syscall.NewLazyDLL("user32.dll")
	user32.NewProc("MessageBoxW").Call(
		0,
		uintptr(unsafe.Pointer(text)),
		uintptr(unsafe.Pointer(title)),
		0x10, // MB_ICONERROR
	)
	os.Exit(1)
}

func buildUI() error {
	var (
		filterProto        *walk.LineEdit
		filterProtoNot     *walk.CheckBox
		filterSrcIP        *walk.LineEdit
		filterDstIP        *walk.LineEdit
		filterSrcPort      *walk.LineEdit
		filterDstPort      *walk.LineEdit
		filterDirection    *walk.ComboBox
		filterAction       *walk.ComboBox
		filterIPVersion    *walk.ComboBox
		filterPID          *walk.LineEdit
		filterProcess      *walk.LineEdit
		filterRule         *walk.LineEdit
		filterPIDNot       *walk.CheckBox
		filterProcNot      *walk.CheckBox
		filterRuleNot      *walk.CheckBox
		filterSrcIPNot     *walk.CheckBox
		filterDstIPNot     *walk.CheckBox
		filterSrcPortNot   *walk.CheckBox
		filterDstPortNot   *walk.CheckBox
		filterHideNoMatch  *walk.CheckBox
		onlyAfterCheck     *walk.CheckBox
		hideNoiseCheck     *walk.CheckBox
		collapseCheck      *walk.CheckBox
		hideLoopbackCheck  *walk.CheckBox
		highlightICMPCheck *walk.CheckBox
		liveTailCheck      *walk.CheckBox
		pauseBtn           *walk.PushButton
		startStopBtn       *walk.PushButton
		reloadBtn          *walk.PushButton
		reloadAction       *walk.Action
		table              *walk.TableView
		statusItem         *walk.StatusBarItem
		countItem          *walk.StatusBarItem
		mw                 *walk.MainWindow
	)

	columns := make([]TableViewColumn, len(columnDefs))
	for i, c := range columnDefs {
		title := c.title
		if c.title == "Time" {
			title = timeColumnTitle()
		}
		columns[i] = TableViewColumn{
			Title:  title,
			Width:  c.width,
			Hidden: c.hiddenDefault,
		}
	}

	err := MainWindow{
		AssignTo: &mw,
		Title:    appName + " - Windows Firewall Monitor v" + appVersion,
		MinSize:  Size{Width: 1100, Height: 650},
		Size:     Size{Width: 1280, Height: 760},
		Layout:   VBox{MarginsZero: true, SpacingZero: true},
		MenuItems: []MenuItem{
			Menu{
				Text: "&Preferences",
				Items: []MenuItem{
					Action{
						Text:        "&Columns...",
						OnTriggered: func() { showColumnsDialog() },
					},
					Action{
						Text:        "&Noise Filter...",
						OnTriggered: func() { showNoiseDialog() },
					},
					Action{
						Text:        "&Event Window...",
						OnTriggered: func() { showEventWindowDialog() },
					},
					Action{
						Text:        "&Time Display...",
						OnTriggered: func() { showTimeDialog() },
					},
				},
			},
			Menu{
				Text: "&Help",
				Items: []MenuItem{
					Action{
						Text:        "&About the Windows Security Log...",
						OnTriggered: func() { showSecurityLogHelp(mw) },
					},
					Action{
						Text:        "&About...",
						OnTriggered: func() { showAbout(mw) },
					},
				},
			},
		},
		Children: []Widget{

			// ---- Filter bar ----
			// ---- Filter row 1: classification (IP version / Direction / Action) ----
			Composite{
				Layout: HBox{Margins: Margins{Left: 8, Right: 8, Top: 6, Bottom: 3}, Spacing: 6},
				Children: []Widget{
					Label{Text: "IP:"},
					ComboBox{
						AssignTo:              &filterIPVersion,
						Value:                 "",
						Model:                 []string{"", "IPv4 only", "IPv6 only"},
						MaxSize:               Size{Width: 90},
						OnCurrentIndexChanged: func() { applyFilters() },
					},
					Label{Text: "Direction:"},
					ComboBox{
						AssignTo:              &filterDirection,
						Value:                 "",
						Model:                 []string{"", "INBOUND", "OUTBOUND"},
						MaxSize:               Size{Width: 100},
						OnCurrentIndexChanged: func() { applyFilters() },
					},
					Label{Text: "Action:"},
					ComboBox{
						AssignTo:              &filterAction,
						Value:                 "",
						Model:                 []string{"", "ALLOW", "DROP"},
						MaxSize:               Size{Width: 80},
						OnCurrentIndexChanged: func() { applyFilters() },
					},
					HSpacer{},
					PushButton{
						AssignTo:  &startStopBtn,
						Text:      "Start",
						MaxSize:   Size{Width: 80},
						OnClicked: func() { onStartStopAuditing() },
					},
					PushButton{
						AssignTo:  &reloadBtn,
						Text:      "Reload Rules",
						MaxSize:   Size{Width: 110},
						OnClicked: func() { reloadRuleData() },
					},
					PushButton{
						Text:      "Clear Filters",
						MaxSize:   Size{Width: 90},
						OnClicked: func() { clearFilters() },
					},
				},
			},

			// ---- Filter row 2: addressing (Src IP / Src Port / Dst IP / Dst Port) ----
			Composite{
				Layout: HBox{Margins: Margins{Left: 8, Right: 8, Top: 0, Bottom: 3}, Spacing: 6},
				Children: []Widget{
					Label{Text: "Protocol:"},
					LineEdit{
						AssignTo:      &filterProto,
						MaxSize:       Size{Width: 80},
						OnTextChanged: func() { applyFilters() },
					},
					CheckBox{
						AssignTo:         &filterProtoNot,
						Text:             "Not",
						OnCheckedChanged: func() { applyFilters() },
					},
					Label{Text: "Src IP:"},
					LineEdit{
						AssignTo:      &filterSrcIP,
						MinSize:       Size{Width: 140},
						MaxSize:       Size{Width: 170},
						ToolTipText:   `Substring match (e.g. 192.168 matches all). Wrap in quotes for exact: "192.168.1.1" matches only that address.`,
						OnTextChanged: func() { applyFilters() },
					},
					CheckBox{
						AssignTo:         &filterSrcIPNot,
						Text:             "Not",
						OnCheckedChanged: func() { applyFilters() },
					},
					Label{Text: "Src Port:"},
					LineEdit{
						AssignTo:      &filterSrcPort,
						MaxSize:       Size{Width: 60},
						ToolTipText:   `Substring match (80 also matches 8080). Wrap in quotes for exact: "80" matches only port 80.`,
						OnTextChanged: func() { applyFilters() },
					},
					CheckBox{
						AssignTo:         &filterSrcPortNot,
						Text:             "Not",
						OnCheckedChanged: func() { applyFilters() },
					},
					Label{Text: "Dst IP:"},
					LineEdit{
						AssignTo:      &filterDstIP,
						MinSize:       Size{Width: 140},
						MaxSize:       Size{Width: 170},
						ToolTipText:   `Substring match (e.g. 192.168 matches all). Wrap in quotes for exact: "192.168.1.1" matches only that address.`,
						OnTextChanged: func() { applyFilters() },
					},
					CheckBox{
						AssignTo:         &filterDstIPNot,
						Text:             "Not",
						OnCheckedChanged: func() { applyFilters() },
					},
					Label{Text: "Dst Port:"},
					LineEdit{
						AssignTo:      &filterDstPort,
						MaxSize:       Size{Width: 60},
						ToolTipText:   `Substring match (80 also matches 8080). Wrap in quotes for exact: "80" matches only port 80.`,
						OnTextChanged: func() { applyFilters() },
					},
					CheckBox{
						AssignTo:         &filterDstPortNot,
						Text:             "Not",
						OnCheckedChanged: func() { applyFilters() },
					},
					HSpacer{},
				},
			},

			// ---- Second filter row: PID / Process / Matched Rule ----
			Composite{
				Layout: HBox{Margins: Margins{Left: 8, Right: 8, Top: 0, Bottom: 6}, Spacing: 6},
				Children: []Widget{
					Label{Text: "PID:"},
					LineEdit{
						AssignTo:      &filterPID,
						MaxSize:       Size{Width: 70},
						OnTextChanged: func() { applyFilters() },
					},
					CheckBox{
						AssignTo:         &filterPIDNot,
						Text:             "Not",
						OnCheckedChanged: func() { applyFilters() },
					},
					Label{Text: "Process:"},
					LineEdit{
						AssignTo:      &filterProcess,
						MaxSize:       Size{Width: 160},
						OnTextChanged: func() { applyFilters() },
					},
					CheckBox{
						AssignTo:         &filterProcNot,
						Text:             "Not",
						OnCheckedChanged: func() { applyFilters() },
					},
					Label{Text: "Matched Rule:"},
					LineEdit{
						AssignTo:      &filterRule,
						MaxSize:       Size{Width: 260},
						OnTextChanged: func() { applyFilters() },
					},
					CheckBox{
						AssignTo:         &filterRuleNot,
						Text:             "Not",
						OnCheckedChanged: func() { applyFilters() },
					},
					CheckBox{
						AssignTo:         &filterHideNoMatch,
						Text:             "Hide (No matching rule)",
						OnCheckedChanged: func() { applyFilters() },
					},
					HSpacer{},
				},
			},

			// ---- Controls row ----
			Composite{
				Layout: HBox{Margins: Margins{Left: 8, Right: 8, Top: 0, Bottom: 4}, Spacing: 8},
				Children: []Widget{
					CheckBox{
						AssignTo: &liveTailCheck,
						Text:     "Live tail (auto-scroll)",
						Checked:  true,
					},
					CheckBox{
						AssignTo:         &onlyAfterCheck,
						Text:             "Only show events after launch",
						Checked:          true,
						OnCheckedChanged: func() { applyFilters() },
					},
					CheckBox{
						AssignTo:         &highlightICMPCheck,
						Text:             "Highlight ICMP",
						Checked:          true,
						OnCheckedChanged: func() { onHighlightICMPToggle() },
					},
					CheckBox{
						AssignTo:         &hideNoiseCheck,
						Text:             "Hide multicast/broadcast noise",
						Checked:          true,
						OnCheckedChanged: func() { onNoiseToggle() },
					},
					CheckBox{
						AssignTo:         &collapseCheck,
						Text:             "Collapse duplicates",
						Checked:          true,
						Enabled:          false, // only relevant when noise is shown
						OnCheckedChanged: func() { onCollapseToggle() },
					},
					CheckBox{
						AssignTo:         &hideLoopbackCheck,
						Text:             "Hide loopback traffic",
						Checked:          true,
						OnCheckedChanged: func() { applyFilters() },
					},
					PushButton{
						AssignTo:  &pauseBtn,
						Text:      "Pause",
						MaxSize:   Size{Width: 80},
						OnClicked: func() { togglePause() },
					},
					PushButton{
						Text:      "Export...",
						MaxSize:   Size{Width: 90},
						OnClicked: func() { exportVisible() },
					},
					PushButton{
						Text:    "Clear Log",
						MaxSize: Size{Width: 80},
						OnClicked: func() {
							app.model.clear()
							app.mu.Lock()
							app.totalCount = 0
							app.mu.Unlock()
							republishTable()
							updateCount()
						},
					},
					HSpacer{},
				},
			},

			// ---- Event table ----
			TableView{
				AssignTo:         &table,
				AlternatingRowBG: false,
				ColumnsOrderable: true,
				ColumnsSizable:   true,
				MultiSelection:   false,
				Model:            app.model,
				Columns:          columns,
				StyleCell:        func(style *walk.CellStyle) { app.model.StyleCell(style) },
				OnItemActivated: func() {
					idx := table.CurrentIndex()
					if idx < 0 {
						return
					}
					// Index the SAME slice the table paints from. RowCount/Value
					// operate on m.display (which may be a collapsed view of
					// m.visible), so the clicked row maps to display[idx]. Using
					// visible[idx] here is a bug: when noise-collapse is active,
					// display and visible diverge and the detail view would show a
					// different event than the one in the clicked row.
					app.model.mu.RLock()
					if idx < len(app.model.display) {
						e := app.model.display[idx]
						app.model.mu.RUnlock()
						showDetail(mw, e)
					} else {
						app.model.mu.RUnlock()
					}
				},
			},
		},

		StatusBarItems: []StatusBarItem{
			{AssignTo: &statusItem, Text: "Initializing...", Width: 500},
			{AssignTo: &countItem, Text: "0 events", Width: 120},
		},
	}.Create()

	if err != nil {
		return err
	}

	app.mw = mw
	app.table = table
	app.statusBar = statusItem
	app.countBar = countItem
	app.pauseBtn = pauseBtn
	app.startStopBtn = startStopBtn
	app.reloadBtn = reloadBtn
	app.reloadAction = reloadAction
	app.filterProto = filterProto
	app.filterProtoNot = filterProtoNot
	app.filterSrcIP = filterSrcIP
	app.filterDstIP = filterDstIP
	app.filterSrcPort = filterSrcPort
	app.filterDstPort = filterDstPort
	app.filterDirection = filterDirection
	app.filterAction = filterAction
	app.filterIPVersion = filterIPVersion
	app.filterPID = filterPID
	app.filterProcess = filterProcess
	app.filterRule = filterRule
	app.filterPIDNot = filterPIDNot
	app.filterProcNot = filterProcNot
	app.filterRuleNot = filterRuleNot
	app.filterSrcIPNot = filterSrcIPNot
	app.filterDstIPNot = filterDstIPNot
	app.filterSrcPortNot = filterSrcPortNot
	app.filterDstPortNot = filterDstPortNot
	app.filterHideNoMatch = filterHideNoMatch
	app.onlyAfterCheck = onlyAfterCheck
	app.hideNoiseCheck = hideNoiseCheck
	app.collapseCheck = collapseCheck
	app.hideLoopbackCheck = hideLoopbackCheck
	app.highlightICMPCheck = highlightICMPCheck
	app.liveTailCheck = liveTailCheck

	// Apply persisted checkbox states (set while uiReady is still false, so the
	// SetChecked calls do not trigger a premature applyFilters). Any field the
	// config did not specify keeps the declarative default already set above.
	cfg := app.loadedConfig
	if cfg.HideNoise != nil {
		hideNoiseCheck.SetChecked(*cfg.HideNoise)
	}
	if cfg.Collapse != nil {
		collapseCheck.SetChecked(*cfg.Collapse)
	}
	if cfg.OnlyAfter != nil {
		onlyAfterCheck.SetChecked(*cfg.OnlyAfter)
	}
	if cfg.LiveTail != nil {
		liveTailCheck.SetChecked(*cfg.LiveTail)
	}
	if cfg.HideNoMatch != nil {
		filterHideNoMatch.SetChecked(*cfg.HideNoMatch)
	}
	if cfg.HighlightICMP != nil {
		highlightICMPCheck.SetChecked(*cfg.HighlightICMP)
	}
	if cfg.HideLoopback != nil {
		hideLoopbackCheck.SetChecked(*cfg.HideLoopback)
	}
	// Keep the dependent control state consistent with the (possibly restored)
	// hide-noise value: collapse only applies when noise is shown.
	hideNoise := hideNoiseCheck.Checked()
	collapseCheck.SetEnabled(!hideNoise)
	app.model.setCollapse(!hideNoise && collapseCheck.Checked())
	// Sync the model's ICMP-highlight state to the (possibly restored) checkbox.
	app.model.setHighlightICMP(highlightICMPCheck.Checked())

	// Restore persisted column layout (visibility, width, visual order) and the
	// saved filter-bar state. Both run while uiReady is still false so the
	// SetText/SetVisible/SetCurrentIndex calls do not trigger a premature
	// applyFilters; the single applyFilters() below then picks up the restored
	// filter values once everything is wired.
	applyColumnLayout(cfg)
	restoreFilterControls(cfg.Filters)

	// In history mode there is no live monitoring, so the Start/Stop and Pause
	// buttons are disabled: the user cannot begin auditing/polling, and there is
	// no live event stream to pause or resume. The "Only show events after
	// launch" and "Live tail" toggles are likewise irrelevant (there is no live
	// stream and no launch boundary), so they are disabled too.
	//
	// IMPORTANT: these controls are only disabled, never unchecked. Their
	// checked state is left exactly as restored from config, so saveCurrentConfig
	// (which reads .Checked()) persists the user's real preferences unchanged —
	// running in history mode must not rewrite the saved toggles.
	if app.historyMode {
		if startStopBtn != nil {
			startStopBtn.SetEnabled(false)
		}
		if pauseBtn != nil {
			pauseBtn.SetEnabled(false)
		}
		if onlyAfterCheck != nil {
			onlyAfterCheck.SetEnabled(false)
		}
		if liveTailCheck != nil {
			liveTailCheck.SetEnabled(false)
		}
	}

	// All control refs are now wired; filter handlers may run safely.
	app.uiReady = true

	// Apply the initial filter immediately so the default "only after launch"
	// state takes effect on the model BEFORE the backlog arrives via uiPump.
	applyFilters()

	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		onExit()
	})

	go uiPump()

	// Run the startup logging check on the UI goroutine once the message
	// loop is running. Synchronize enqueues the callback and walk invokes it
	// on the first iteration of Run()'s message loop, by which point every
	// child HWND (status bar, table) is fully realised. This is walk's
	// documented mechanism for deferring work onto the GUI thread.
	mw.Synchronize(func() {
		checkAndPromptLogging()
	})

	mw.Run()
	return nil
}

// checkAndPromptLogging inspects the current WFP audit policy and either
// begins reading events immediately or prompts the user to enable auditing.
// Must be called on the UI goroutine.
func checkAndPromptLogging() {
	// Reading the Windows Security event log requires Administrator rights
	// (its ACL grants read access only to administrators), and enabling WFP
	// connection auditing does too. Without elevation the app cannot show any
	// events at all, so there is nothing useful it can do — tell the user
	// plainly and exit rather than presenting an empty, broken-looking window.
	if !isElevated() {
		walk.MsgBox(app.mw,
			"Administrator Rights Required",
			"WinFWMon must be run as Administrator.\n\n"+
				"Reading the Windows Security event log (and enabling WFP "+
				"connection auditing) requires Administrator rights. Without "+
				"them, no connection events can be shown.\n\n"+
				"Please re-launch WinFWMon as Administrator.",
			walk.MsgBoxIconError|walk.MsgBoxOK)
		dbg("checkAndPromptLogging: not elevated - exiting")
		app.mw.Close()
		return
	}

	// History mode: do not touch audit policy and do not poll. Ingest whatever
	// is already in the Security log once, then stop. The Start button is
	// disabled (set up in buildUI), so the user cannot begin live monitoring.
	if app.historyMode {
		setStatus(fmt.Sprintf("History mode - reading up to %d events...", effectiveWindowSize()))
		dbg("checkAndPromptLogging: history mode, one-shot backlog ingest")
		startHistoryIngest()
		return
	}

	state := readWFPAuditState()
	dbg("checkAndPromptLogging: audit state success=%v failure=%v", state.Success, state.Failure)

	if state.FullyEnabled() {
		setStatus("Reading Security log (WFP connection auditing already on)")
		app.auditingOn = true
		updateStartStopButton()
		startEventSource()
		return
	}

	// Running as admin: offer to enable WFP auditing. Pass the detected state so
	// the dialog can explain a partial (success-only / failure-only) situation.
	enable, restore := showEnableAuditingDialog(state)
	app.restoreOnExit = restore

	if enable {
		setStatus("Enabling WFP connection auditing...")
		prior, err := enableWFPAuditing()
		if err != nil {
			walk.MsgBox(app.mw,
				"Could Not Enable Auditing",
				fmt.Sprintf(
					"Failed to enable WFP connection auditing:\n\n%v\n\n"+
						"The app will continue but may show no new events.",
					err),
				walk.MsgBoxIconError|walk.MsgBoxOK)
			setStatus("WARNING: could not enable WFP auditing")
		} else {
			app.auditEnabledByUs = true
			app.auditingOn = true
			app.priorAuditState = prior
			setStatus("WFP auditing enabled - reading Security log")
		}
	} else {
		// Declined. If auditing is partially on, only half the events
		// (allowed-only or blocked-only) will appear; say so rather than implying
		// nothing or everything is recorded.
		switch {
		case state.Success && !state.Failure:
			setStatus("WARNING: only success (allowed) auditing on - blocked events (5157) will not appear")
		case state.Failure && !state.Success:
			setStatus("WARNING: only failure (blocked) auditing on - allowed events (5156) will not appear")
		default:
			setStatus("WARNING: WFP auditing not enabled - showing existing events only")
		}
	}

	updateStartStopButton()
	startEventSource()
}

// onExit stops the event source and pump, and restores the audit policy if we
// changed it and the user asked us to. Called on the UI goroutine from Closing.
func onExit() {
	// Persist current preferences before tearing down. Reading the checkboxes
	// is safe here: onExit runs on the UI goroutine (window Closing handler).
	saveCurrentConfig()

	// Stop the event source first so no new entries arrive.
	if app.eventSource != nil {
		app.eventSource.Stop()
	}

	// Stop the uiPump goroutine so it does not call Synchronize on the
	// dead window after mw.Run() returns. sync.Once makes this safe even
	// if onExit is somehow invoked more than once.
	app.pumpStopOnce.Do(func() {
		if app.pumpStop != nil {
			close(app.pumpStop)
		}
	})

	// Restore the prior audit policy if we changed it and the user asked us to.
	if app.restoreOnExit && app.auditEnabledByUs {
		restoreWFPAuditing(app.priorAuditState)
		dbg("onExit: restored prior WFP audit state")
	}

	dbg("onExit: complete")
	closeDebugLog()
}

// saveCurrentConfig captures the current UI preferences and writes them to the
// config file. Guards against nil controls in case it is ever called before
// the UI is fully built. Must run on the UI goroutine.
func saveCurrentConfig() {
	if !app.uiReady {
		return
	}
	c := config{NoisePorts: portsToSortedSlice(app.noisePorts)}
	if app.hideNoiseCheck != nil {
		c.HideNoise = boolPtr(app.hideNoiseCheck.Checked())
	}
	if app.collapseCheck != nil {
		c.Collapse = boolPtr(app.collapseCheck.Checked())
	}
	if app.onlyAfterCheck != nil {
		c.OnlyAfter = boolPtr(app.onlyAfterCheck.Checked())
	}
	if app.liveTailCheck != nil {
		c.LiveTail = boolPtr(app.liveTailCheck.Checked())
	}
	if app.filterHideNoMatch != nil {
		c.HideNoMatch = boolPtr(app.filterHideNoMatch.Checked())
	}
	if app.highlightICMPCheck != nil {
		c.HighlightICMP = boolPtr(app.highlightICMPCheck.Checked())
	}
	if app.hideLoopbackCheck != nil {
		c.HideLoopback = boolPtr(app.hideLoopbackCheck.Checked())
	}
	ws := effectiveWindowSize()
	c.WindowSize = &ws
	tp := app.timePrecision
	c.TimePrecision = &tp
	tz := app.timeZone
	c.TimeZone = &tz

	// Capture column layout (visibility, width, visual order) and the filter-bar
	// state so both persist between runs, mirroring WinFWRules.
	captureColumnLayout(&c)
	c.Filters = captureFilterState()

	c.save()
}

// captureColumnLayout records each column's visibility and width (title-keyed)
// and the current visual (drag) order into c. If the native order cannot be
// read it falls back to logical order, so a layout is always written.
func captureColumnLayout(c *config) {
	if app.table == nil || app.table.Columns() == nil {
		return
	}
	cols := app.table.Columns()
	order, ok := currentColumnOrder(app.table)
	if !ok || len(order) != cols.Len() {
		order = make([]int, 0, cols.Len())
		for i := 0; i < cols.Len(); i++ {
			order = append(order, i)
		}
		dbg("captureColumnLayout: column order unavailable; using logical order")
	}
	c.ColumnOrder = columnOrderTitleSlice(order)
	dbg("captureColumnLayout: order %v (%s)", order, columnOrderTitles(order))
	for i := range columnDefs {
		if i >= cols.Len() {
			break
		}
		col := cols.At(i)
		c.Columns = append(c.Columns, columnState{
			Title:   columnDefs[i].title,
			Visible: col.Visible(),
			Width:   col.Width(),
		})
	}
}

// captureFilterState snapshots the text/dropdown filter controls and their
// negate flags. Returns nil when no UI controls exist yet (so an early/partial
// save omits the block rather than writing zeroes).
func captureFilterState() *filterState {
	if app.filterProto == nil {
		return nil
	}
	chk := func(cb *walk.CheckBox) bool { return cb != nil && cb.Checked() }
	return &filterState{
		Protocol:    strings.TrimSpace(app.filterProto.Text()),
		SrcIP:       strings.TrimSpace(app.filterSrcIP.Text()),
		DstIP:       strings.TrimSpace(app.filterDstIP.Text()),
		SrcPort:     strings.TrimSpace(app.filterSrcPort.Text()),
		DstPort:     strings.TrimSpace(app.filterDstPort.Text()),
		Direction:   app.filterDirection.Text(),
		Action:      app.filterAction.Text(),
		IPVersion:   app.filterIPVersion.Text(),
		PID:         strings.TrimSpace(app.filterPID.Text()),
		Process:     strings.TrimSpace(app.filterProcess.Text()),
		MatchedRule: strings.TrimSpace(app.filterRule.Text()),

		ProtocolNot:    chk(app.filterProtoNot),
		SrcIPNot:       chk(app.filterSrcIPNot),
		DstIPNot:       chk(app.filterDstIPNot),
		SrcPortNot:     chk(app.filterSrcPortNot),
		DstPortNot:     chk(app.filterDstPortNot),
		PIDNot:         chk(app.filterPIDNot),
		ProcessNot:     chk(app.filterProcNot),
		MatchedRuleNot: chk(app.filterRuleNot),
	}
}

// applyColumnLayout restores persisted column visibility, width, and visual
// order from cfg onto the live table. Matching is by stable column title so a
// saved layout cannot drift onto the wrong column if columnDefs is reordered in
// a later version. Visibility/width are applied first, then the order, because
// only visible columns have native columns to reorder. Safe to call before
// uiReady (it touches only column objects, not filter handlers).
func applyColumnLayout(cfg config) {
	if app.table == nil || app.table.Columns() == nil {
		return
	}
	if len(cfg.Columns) == 0 && len(cfg.ColumnOrder) == 0 {
		return // nothing saved; keep declarative defaults
	}
	cols := app.table.Columns()

	byTitle := map[string]columnState{}
	for _, cs := range cfg.Columns {
		byTitle[cs.Title] = cs
	}
	for i := range columnDefs {
		if i >= cols.Len() {
			break
		}
		cs, found := byTitle[columnDefs[i].title]
		if !found {
			continue
		}
		_ = cols.At(i).SetVisible(cs.Visible)
		if cs.Width > 0 {
			_ = cols.At(i).SetWidth(cs.Width)
		}
	}

	if order := columnTitlesToCompleteOrder(cfg.ColumnOrder); len(order) == cols.Len() {
		dbg("applyColumnLayout: restoring column order %v (%s)", order, columnOrderTitles(order))
		if !setColumnOrder(app.table, order) {
			dbg("applyColumnLayout: could not restore column order")
		}
	}
}

// restoreFilterControls populates the filter-bar controls from a saved
// filterState. It must run while uiReady is false so the SetText/SetCurrentIndex
// calls do not trigger applyFilters mid-restore; the caller invokes applyFilters
// once afterward. A nil fs (no saved filters) leaves the declarative defaults.
func restoreFilterControls(fs *filterState) {
	if fs == nil {
		return
	}
	setText := func(le *walk.LineEdit, v string) {
		if le != nil {
			le.SetText(v)
		}
	}
	setChk := func(cb *walk.CheckBox, v bool) {
		if cb != nil {
			cb.SetChecked(v)
		}
	}
	// setCombo selects the entry in model whose text equals v (case-sensitive,
	// as these are fixed enum strings). An empty or unmatched value selects the
	// blank first entry (index 0 = "no filter"), matching clearFilters. Driving
	// the combo by index avoids relying on SetText semantics for the
	// dropdown-style (non-editable) combos this app uses.
	setCombo := func(cb *walk.ComboBox, model []string, v string) {
		if cb == nil {
			return
		}
		idx := 0
		for i, m := range model {
			if m == v {
				idx = i
				break
			}
		}
		_ = cb.SetCurrentIndex(idx)
	}

	setText(app.filterProto, fs.Protocol)
	setText(app.filterSrcIP, fs.SrcIP)
	setText(app.filterDstIP, fs.DstIP)
	setText(app.filterSrcPort, fs.SrcPort)
	setText(app.filterDstPort, fs.DstPort)
	setCombo(app.filterDirection, []string{"", "INBOUND", "OUTBOUND"}, fs.Direction)
	setCombo(app.filterAction, []string{"", "ALLOW", "DROP"}, fs.Action)
	setCombo(app.filterIPVersion, []string{"", "IPv4 only", "IPv6 only"}, fs.IPVersion)
	setText(app.filterPID, fs.PID)
	setText(app.filterProcess, fs.Process)
	setText(app.filterRule, fs.MatchedRule)

	setChk(app.filterProtoNot, fs.ProtocolNot)
	setChk(app.filterSrcIPNot, fs.SrcIPNot)
	setChk(app.filterDstIPNot, fs.DstIPNot)
	setChk(app.filterSrcPortNot, fs.SrcPortNot)
	setChk(app.filterDstPortNot, fs.DstPortNot)
	setChk(app.filterPIDNot, fs.PIDNot)
	setChk(app.filterProcNot, fs.ProcessNot)
	setChk(app.filterRuleNot, fs.MatchedRuleNot)
}

// ---- UI helpers — all called on the UI goroutine ----

// uiPump collects log entries from entryChan, resolves rule names off the UI
// goroutine, then batches model updates via mw.Synchronize every 250ms.
// It exits when pumpStop is closed.
func uiPump() {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var pending []*LogEntry

	for {
		select {
		case <-app.pumpStop:
			return

		case e := <-app.entryChan:
			pending = append(pending, e)

		case <-ticker.C:
			if len(pending) == 0 {
				continue
			}
			batch := pending
			pending = nil
			dbg("uiPump: received batch of %d entries", len(batch))

			// Resolve both columns here, off the UI goroutine:
			//   MatchedRuleName = recognizable Defender rule (attribute match)
			//   WFPFilterName   = the actual low-level filter that fired (by ID)
			// ProcessName is normally already set from the event's Application
			// field; fall back to the live PID snapshot only when absent.
			for _, e := range batch {
				e.MatchedRuleName = globalMatcher.Match(e)
				e.WFPFilterName = globalFilters.FilterName(e)
				if e.ProcessName == "" {
					e.ProcessName = globalProcResolver.Name(e.PID)
				}
			}

			if app.mw == nil {
				continue
			}
			app.mw.Synchronize(func() {
				app.mu.Lock()
				app.totalCount += len(batch)
				app.mu.Unlock()

				// Capture the paused state once for this batch (UI goroutine, so
				// it is stable for the duration of this closure).
				paused := app.paused

				// Always ingest entries so that pausing only freezes the
				// *display*, not data collection. While paused, addEntry appends
				// to the unfiltered set only and leaves the visible slice frozen,
				// so the TableView keeps painting exactly what it last showed
				// (mutating visible without publishing corrupts walk's view).
				visibleChanged := false
				for _, e := range batch {
					if app.model.addEntry(e, paused) {
						visibleChanged = true
					}
				}

				if paused {
					// Display frozen; only the total count advances.
					updateCount()
					return
				}

				if !visibleChanged {
					// Nothing the current filter shows changed; avoid a needless
					// repaint/scroll. The total count still moved, so refresh it.
					updateCount()
					return
				}

				// Rebuild the (possibly collapsed) display once for the whole
				// batch — not per entry — so a large burst stays O(n), not O(n²).
				app.model.refreshDisplay()

				dbg("uiPump: model now has %d visible rows (added batch of %d)",
					app.model.RowCount(), len(batch))

				// Issue a full reset rather than an incremental
				// PublishRowsInserted. The incremental path required computing
				// row indices (firstRow..newCount-1) that assumed nothing else
				// had changed the visible slice since firstRow was sampled — but
				// a filter change, trim, or interleaved batch could invalidate
				// that, leaving walk's cached row count out of sync with the
				// model. When walk then painted (on scroll or mouse-move) it
				// requested rows past the slice and Value() returned nil, which
				// showed as <nil> cells that "fixed themselves" on hover. A full
				// reset keeps walk's count exactly equal to len(visible) after
				// every mutation. It is cheap: walk only repaints the viewport
				// (tens of rows), not the whole window.
				app.model.PublishRowsReset()

				if app.liveTailCheck != nil && app.liveTailCheck.Checked() &&
					app.table != nil {
					if rc := app.model.RowCount(); rc > 0 {
						app.table.EnsureItemVisible(rc - 1)
					}
				}
				updateCount()
			})
		}
	}
}

// reloadRuleData reloads both the low-level WFP filter table and the Defender
// firewall rules in the background, updating the status bar with the result.
func reloadRuleData() {
	if !app.reloadingRules.CompareAndSwap(false, true) {
		return
	}
	setReloadRulesUI(true)
	setStatus("Reloading WFP filters and firewall rules...")

	go func() {
		ferr := globalFilters.Load()
		rerr := globalMatcher.LoadRules()
		app.mw.Synchronize(func() {
			defer func() {
				app.reloadingRules.Store(false)
				setReloadRulesUI(false)
			}()

			switch {
			case ferr != nil:
				setStatus("Filter reload failed: " + ferr.Error())
			case rerr != nil:
				setStatus("Rule reload failed: " + rerr.Error())
			default:
				setStatus("WFP filters and firewall rules reloaded")
			}
		})
	}()
}

func setReloadRulesUI(loading bool) {
	if app.reloadBtn != nil {
		if loading {
			app.reloadBtn.SetText("Reloading...")
			app.reloadBtn.SetEnabled(false)
		} else {
			app.reloadBtn.SetText("Reload Rules")
			app.reloadBtn.SetEnabled(true)
		}
	}
	if app.reloadAction != nil {
		app.reloadAction.SetEnabled(!loading)
	}
}

// showEventWindowDialog lets the user set the in-memory event-window size (the
// maximum number of events retained) at runtime, within [minWindowSize,
// maxWindowSize]. Applying it resizes the model immediately; if the new size is
// smaller than the current contents, the oldest events are trimmed. In history
// mode, shrinking has no re-pull but growing triggers a fresh backlog ingest to
// the new depth so the larger window is actually filled.
func showEventWindowDialog() {
	if app.mw == nil {
		return
	}
	current := float64(effectiveWindowSize())

	var dlg *walk.Dialog
	var edit *walk.NumberEdit
	var okPB, cancelPB *walk.PushButton

	_, err := Dialog{
		AssignTo:      &dlg,
		Title:         "Event Window",
		DefaultButton: &okPB,
		CancelButton:  &cancelPB,
		MinSize:       Size{Width: 420, Height: 200},
		Layout:        VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}, Spacing: 10},
		Children: []Widget{
			TextLabel{
				MinSize: Size{Width: 380, Height: 90},
				Text: fmt.Sprintf("Maximum number of events to keep in memory. "+
					"Older events are dropped once this limit is reached.\n\n"+
					"Allowed range: %d to %d. A larger window uses more memory and "+
					"makes filtering slightly slower.", minWindowSize, maxWindowSize),
			},
			Composite{
				Layout: HBox{Spacing: 8},
				Children: []Widget{
					Label{Text: "Events:"},
					NumberEdit{
						AssignTo: &edit,
						Decimals: 0,
						MinValue: float64(minWindowSize),
						MaxValue: float64(maxWindowSize),
						Value:    current,
						MinSize:  Size{Width: 100},
					},
					PushButton{
						Text: fmt.Sprintf("Reset to Default (%d)", defaultWindowSize),
						OnClicked: func() {
							edit.SetValue(float64(defaultWindowSize))
						},
					},
					HSpacer{},
				},
			},
			Composite{
				Layout: HBox{Spacing: 8},
				Children: []Widget{
					HSpacer{},
					PushButton{
						AssignTo: &okPB,
						Text:     "OK",
						OnClicked: func() {
							n := int(edit.Value())
							applyEventWindowSize(n)
							dlg.Accept()
						},
					},
					PushButton{
						AssignTo:  &cancelPB,
						Text:      "Cancel",
						OnClicked: func() { dlg.Cancel() },
					},
				},
			},
		},
	}.Run(app.mw)
	if err != nil {
		dbg("showEventWindowDialog: %v", err)
	}
}

// applyEventWindowSize sets the new window size, resizes the model, and updates
// the view. In history mode a grow re-pulls the backlog to fill the larger
// window. Runs on the UI goroutine.
func applyEventWindowSize(n int) {
	if n < minWindowSize {
		n = minWindowSize
	}
	if n > maxWindowSize {
		n = maxWindowSize
	}
	prev := effectiveWindowSize()
	app.windowSize = n
	changed := app.model.setWindowSize(n)
	dbg("applyEventWindowSize: %d -> %d (visible changed=%v)", prev, n, changed)

	if app.historyMode {
		// In history mode the window size simply means "show the most recent N
		// events from the Security log." Any change — grow OR shrink — is handled
		// by clearing and re-reading from the beginning at the new size, so the
		// displayed set always matches a clean read of N events and there is no
		// divergence between trimming the in-memory set and re-pulling. A shrink
		// therefore costs a fresh query (a brief delay) rather than being an
		// instant in-memory trim, which is an acceptable trade in this
		// non-realtime, forensic mode for fully consistent behaviour.
		//
		// KNOWN MINOR LIMITATION: a handful of events the previous one-shot pull
		// already handed to uiPump (in its channel buffer or pending batch) may
		// be applied just after this clear, briefly showing as duplicates until
		// the next trim/collapse/scroll. Fully preventing this would require a
		// generation handshake with uiPump; for a rare manual action whose only
		// symptom is a few transient duplicate rows, that machinery is not
		// worth the added concurrency surface.
		if n == prev {
			// No size change: nothing to re-read; just repaint.
			republishTable()
			updateCount()
		} else {
			setStatus(fmt.Sprintf("History mode - re-reading up to %d events", n))
			app.model.clear()
			republishTable()
			app.mu.Lock()
			app.totalCount = 0
			app.mu.Unlock()
			startHistoryIngest()
		}
	} else {
		republishTable()
		updateCount()
	}
	setStatusWindowSize(n)
}

// showTimeDialog lets the user choose the timestamp display precision (whole
// seconds, milliseconds, or microseconds) and the display zone (local or UTC),
// and shows the detected local timezone for reference. Changes apply
// immediately to the table and are persisted.
func showTimeDialog() {
	if app.mw == nil {
		return
	}

	// Detect the current local zone for the informational label.
	zoneName, offsetSec := time.Now().Zone()
	offMin := offsetSec / 60
	sign := "+"
	if offMin < 0 {
		sign = "-"
		offMin = -offMin
	}
	zoneInfo := fmt.Sprintf("Detected local time zone: %s (UTC%s%02d:%02d)",
		zoneName, sign, offMin/60, offMin%60)

	var dlg *walk.Dialog
	var okPB, cancelPB *walk.PushButton
	var secRB, msRB, usRB *walk.RadioButton
	var localRB, utcRB *walk.RadioButton

	err := Dialog{
		AssignTo:      &dlg,
		Title:         "Time Display",
		DefaultButton: &okPB,
		CancelButton:  &cancelPB,
		MinSize:       Size{Width: 380, Height: 320},
		Layout:        VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}, Spacing: 10},
		Children: []Widget{
			GroupBox{
				Title:  "Precision",
				Layout: VBox{Margins: Margins{Left: 10, Top: 6, Right: 10, Bottom: 8}, Spacing: 4},
				Children: []Widget{
					Composite{
						Layout:   HBox{MarginsZero: true, SpacingZero: true},
						Children: []Widget{RadioButton{AssignTo: &secRB, Text: "Whole seconds (HH:MM:SS)"}, HSpacer{}},
					},
					Composite{
						Layout:   HBox{MarginsZero: true, SpacingZero: true},
						Children: []Widget{RadioButton{AssignTo: &msRB, Text: "Milliseconds (HH:MM:SS.mmm)"}, HSpacer{}},
					},
					Composite{
						Layout:   HBox{MarginsZero: true, SpacingZero: true},
						Children: []Widget{RadioButton{AssignTo: &usRB, Text: "Microseconds (HH:MM:SS.mmmuuu)"}, HSpacer{}},
					},
				},
			},
			GroupBox{
				Title:  "Time zone",
				Layout: VBox{Margins: Margins{Left: 10, Top: 6, Right: 10, Bottom: 8}, Spacing: 4},
				Children: []Widget{
					RadioButton{AssignTo: &localRB, Text: "Local time"},
					RadioButton{AssignTo: &utcRB, Text: "UTC"},
					Label{Text: zoneInfo},
				},
			},
			Composite{
				Layout: HBox{Spacing: 8},
				Children: []Widget{
					HSpacer{},
					PushButton{
						AssignTo: &okPB,
						Text:     "OK",
						OnClicked: func() {
							prec := "seconds"
							switch {
							case msRB.Checked():
								prec = "millis"
							case usRB.Checked():
								prec = "micros"
							}
							zone := "local"
							if utcRB.Checked() {
								zone = "utc"
							}
							applyTimeSettings(prec, zone)
							dlg.Accept()
						},
					},
					PushButton{
						AssignTo:  &cancelPB,
						Text:      "Cancel",
						OnClicked: func() { dlg.Cancel() },
					},
				},
			},
		},
	}.Create(app.mw)
	if err != nil {
		dbg("showTimeDialog: create: %v", err)
		return
	}

	// Set initial selection to reflect current settings (done after Create,
	// before Run). The two groups live in separate GroupBoxes, so they toggle
	// independently.
	switch app.timePrecision {
	case "millis":
		msRB.SetChecked(true)
	case "micros":
		usRB.SetChecked(true)
	default:
		secRB.SetChecked(true)
	}
	if app.timeZone == "utc" {
		utcRB.SetChecked(true)
	} else {
		localRB.SetChecked(true)
	}

	if dlg.Run() < 0 {
		dbg("showTimeDialog: run aborted")
	}
}

// applyTimeSettings updates the time precision/zone, refreshes the Time column
// header (for the UTC annotation) and repaints the table so the new format
// takes effect immediately.
func applyTimeSettings(precision, zone string) {
	app.timePrecision = precision
	app.timeZone = zone
	// Update the Time column header to reflect the zone (e.g. "Time (UTC)").
	if app.table != nil {
		cols := app.table.Columns()
		for i := 0; i < cols.Len(); i++ {
			c := cols.At(i)
			if c.TitleEffective() == "Time" || c.TitleEffective() == "Time (UTC)" {
				_ = c.SetTitle(timeColumnTitle())
				break
			}
		}
	}
	if app.model != nil {
		republishTable()
	}
	dbg("applyTimeSettings: precision=%s zone=%s", precision, zone)
}

// setStatusWindowSize notes the active window size in the status bar briefly,
// without overwriting a more important message in history mode (handled by the
// caller above).
func setStatusWindowSize(n int) {
	if !app.historyMode {
		setStatus(fmt.Sprintf("Event window set to %d", n))
	}
}

func startEventSource() {
	dbg("startEventSource: starting")
	if app.eventSource != nil {
		app.eventSource.Stop()
	}
	app.eventSource = newEventSource(app.entryChan)
	app.eventSource.Start()
}

// effectiveWindowSize returns the configured maximum number of events to retain
// in memory, clamped to the supported range. It is the single source of truth
// for the window size used by the model trim logic and the history backlog.
func effectiveWindowSize() int {
	n := app.windowSize
	if n <= 0 {
		n = defaultWindowSize
	}
	if n < minWindowSize {
		n = minWindowSize
	}
	if n > maxWindowSize {
		n = maxWindowSize
	}
	return n
}

// startHistoryIngest performs a one-shot backlog read for --history mode: it
// pulls up to the window size of existing events, then stops. No auditing is
// changed and no recurring polling is started.
func startHistoryIngest() {
	if app.eventSource != nil {
		app.eventSource.Stop()
	}
	src := newEventSource(app.entryChan)
	src.backlog = effectiveWindowSize()
	app.eventSource = src
	go src.RunOnce(func(count int) {
		// Report the true number of events read from the log. Marshalled to the
		// UI goroutine because setStatus touches a walk control. The events may
		// still be rendering (they flow through uiPump in batches), but "read"
		// refers to ingestion from the Security log, which is complete here.
		if app.mw != nil {
			app.mw.Synchronize(func() {
				setStatus(fmt.Sprintf("History mode - successfully read %d events", count))
			})
		}
	})
}

// updateStartStopButton sets the button label to reflect the current auditing
// state: "Stop" when WFP connection auditing is on (clicking turns it off),
// "Start" when it is off (clicking turns it on). Must run on the UI goroutine.
func updateStartStopButton() {
	if app.startStopBtn == nil {
		return
	}
	if app.auditingOn {
		app.startStopBtn.SetText("Stop")
	} else {
		app.startStopBtn.SetText("Start")
	}
}

// onStartStopAuditing toggles WFP connection auditing at runtime. Both turning
// it on and off require administrative rights (auditpol), so it checks
// elevation first and reports clearly if it cannot comply. Starting also
// (re)starts the event source so new events flow immediately.
func onStartStopAuditing() {
	if app.historyMode {
		return // no live monitoring in history mode
	}
	if !isElevated() {
		walk.MsgBox(app.mw,
			"Administrator Required",
			"Changing WFP connection auditing requires administrative rights. "+
				"Please re-launch WinFWMon as Administrator.",
			walk.MsgBoxIconWarning|walk.MsgBoxOK)
		return
	}

	if app.auditingOn {
		// Currently on -> turn it off.
		if err := disableWFPAuditing(); err != nil {
			walk.MsgBox(app.mw,
				"Could Not Stop Auditing",
				fmt.Sprintf("Failed to disable WFP connection auditing:\n\n%v", err),
				walk.MsgBoxIconError|walk.MsgBoxOK)
			return
		}
		app.auditingOn = false
		// Auditing is no longer active because of us; nothing to restore on exit
		// beyond what the user now sees. Leave priorAuditState intact so a later
		// Start/Stop cycle still knows the original pre-app state.
		app.auditEnabledByUs = false
		setStatus("WFP connection auditing stopped")
		dbg("onStartStopAuditing: auditing disabled by user")
	} else {
		// Currently off -> turn it on.
		prior, err := enableWFPAuditing()
		if err != nil {
			walk.MsgBox(app.mw,
				"Could Not Start Auditing",
				fmt.Sprintf("Failed to enable WFP connection auditing:\n\n%v", err),
				walk.MsgBoxIconError|walk.MsgBoxOK)
			return
		}
		app.auditingOn = true
		// Capture the pre-app audit state only the first time we enable it, so a
		// Stop/Start cycle does not overwrite the original state with a state we
		// ourselves produced.
		if !app.auditEnabledByUs {
			app.priorAuditState = prior
		}
		app.auditEnabledByUs = true
		setStatus("WFP connection auditing started - reading Security log")
		dbg("onStartStopAuditing: auditing enabled by user")
		// Ensure the event source is running so new events flow.
		startEventSource()
	}

	updateStartStopButton()
}

func togglePause() {
	if app.historyMode {
		return // no live stream to pause/resume in history mode
	}
	app.paused = !app.paused
	if app.paused {
		app.pauseBtn.SetText("Resume")
		setStatus("PAUSED")
	} else {
		app.pauseBtn.SetText("Pause")
		setStatus(readingStatus())
		// Entries that arrived while paused went into the unfiltered set only;
		// the visible slice was frozen. Rebuild it from all (under the current
		// filter) so the table catches up, then publish once and scroll to end.
		app.model.rebuildVisible()
		republishTable()
		if app.liveTailCheck != nil && app.liveTailCheck.Checked() && app.table != nil {
			if rc := app.model.RowCount(); rc > 0 {
				app.table.EnsureItemVisible(rc - 1)
			}
		}
		updateCount()
	}
}

// readingStatus returns the status-bar message describing the current
// monitoring state, so that resuming from pause restores the same specificity
// the user saw before pausing (e.g. noting when WFP auditing was already on)
// rather than always falling back to a generic string.
func readingStatus() string {
	switch {
	case app.historyMode:
		return "History mode - showing existing events only, not monitoring"
	case app.auditingOn:
		return "Reading Security log (WFP connection auditing on)"
	default:
		return "WARNING: WFP auditing not enabled - showing existing events only"
	}
}

// selectedIPVersion maps the IP-version dropdown's display label to the filter
// value used by Filter.Matches ("" = all, "ipv4", "ipv6").
func selectedIPVersion() string {
	if app.filterIPVersion == nil {
		return ""
	}
	switch app.filterIPVersion.Text() {
	case "IPv4 only":
		return "ipv4"
	case "IPv6 only":
		return "ipv6"
	default:
		return ""
	}
}

func applyFilters() {
	// ComboBox/LineEdit change handlers fire during walk's Create() as each
	// control is initialised, before buildUI has assigned the app.* refs.
	// Ignore those early calls until the UI is fully wired.
	if !app.uiReady {
		return
	}
	f := Filter{
		Protocol:    strings.TrimSpace(app.filterProto.Text()),
		SourceIP:    strings.TrimSpace(app.filterSrcIP.Text()),
		DestIP:      strings.TrimSpace(app.filterDstIP.Text()),
		SourcePort:  strings.TrimSpace(app.filterSrcPort.Text()),
		DestPort:    strings.TrimSpace(app.filterDstPort.Text()),
		Direction:   app.filterDirection.Text(),
		Action:      app.filterAction.Text(),
		PID:         strings.TrimSpace(app.filterPID.Text()),
		Process:     strings.TrimSpace(app.filterProcess.Text()),
		MatchedRule: strings.TrimSpace(app.filterRule.Text()),

		PIDNegate:         app.filterPIDNot != nil && app.filterPIDNot.Checked(),
		ProcessNegate:     app.filterProcNot != nil && app.filterProcNot.Checked(),
		MatchedRuleNegate: app.filterRuleNot != nil && app.filterRuleNot.Checked(),
		ProtocolNegate:    app.filterProtoNot != nil && app.filterProtoNot.Checked(),
		SourceIPNegate:    app.filterSrcIPNot != nil && app.filterSrcIPNot.Checked(),
		DestIPNegate:      app.filterDstIPNot != nil && app.filterDstIPNot.Checked(),
		SourcePortNegate:  app.filterSrcPortNot != nil && app.filterSrcPortNot.Checked(),
		DestPortNegate:    app.filterDstPortNot != nil && app.filterDstPortNot.Checked(),
		HideNoMatch:       app.filterHideNoMatch != nil && app.filterHideNoMatch.Checked(),
	}
	// The launch-time cutoff is meaningless in history mode (the whole point is
	// to show events from before launch), so it is never applied there — even
	// though the checkbox may read as checked from the user's saved config. The
	// checkbox is disabled in history mode; we simply ignore its state here.
	if !app.historyMode && app.onlyAfterCheck != nil && app.onlyAfterCheck.Checked() {
		f.OnlyAfter = app.launchTime
	}
	// Always carry the configured noise-port set on the filter, even when
	// HideNoise is off: the collapse feature (active only when noise is shown)
	// reads it from the model's filter to classify noise the same way.
	f.NoisePorts = app.noisePorts
	if app.hideNoiseCheck != nil && app.hideNoiseCheck.Checked() {
		f.HideNoise = true
	}
	if app.hideLoopbackCheck != nil && app.hideLoopbackCheck.Checked() {
		f.HideLoopback = true
	}
	f.IPVersion = selectedIPVersion()
	app.model.applyFilter(f)
	republishTable()
	updateCount()
}

// onNoiseToggle responds to the "Hide multicast/broadcast noise" checkbox. The
// "Collapse duplicates" option only makes sense when noise is being shown, so
// it is enabled only when hide-noise is unchecked. Reapplies the filter either
// way.
func onNoiseToggle() {
	if !app.uiReady {
		return
	}
	hide := app.hideNoiseCheck.Checked()
	if app.collapseCheck != nil {
		app.collapseCheck.SetEnabled(!hide)
	}
	// When noise is hidden there are no noise rows to collapse, so the display
	// collapse state should follow: collapse only when noise is shown AND the
	// collapse box is checked.
	collapseActive := !hide && app.collapseCheck != nil && app.collapseCheck.Checked()
	app.model.setCollapse(collapseActive)
	applyFilters() // applyFilter rebuilds display+publishes; keeps both in sync
}

// onCollapseToggle responds to the "Collapse duplicates" checkbox. It only has
// effect while noise is shown (the box is disabled otherwise).
func onCollapseToggle() {
	if !app.uiReady {
		return
	}
	app.model.setCollapse(app.collapseCheck.Checked())
	republishTable()
	updateCount()
}

// onHighlightICMPToggle responds to the "Highlight ICMP" checkbox. It only
// changes row colouring, so it updates the model flag and repaints; no
// re-filtering is needed.
func onHighlightICMPToggle() {
	if !app.uiReady {
		return
	}
	app.model.setHighlightICMP(app.highlightICMPCheck.Checked())
	republishTable()
}

// showNoiseDialog lets the user edit which UDP ports are treated as
// multicast/broadcast noise. The set is entered as a comma-separated list of
// port numbers; the default is 5353 (mDNS) and 1900 (SSDP).
func showNoiseDialog() {
	if app.mw == nil {
		return
	}

	// Render the current set as a sorted comma-separated string.
	var current []int
	for p := range app.noisePorts {
		current = append(current, p)
	}
	sort.Ints(current)
	parts := make([]string, len(current))
	for i, p := range current {
		parts[i] = strconv.Itoa(p)
	}
	initial := strings.Join(parts, ", ")

	var dlg *walk.Dialog
	var edit *walk.LineEdit
	var okPB, cancelPB *walk.PushButton

	_, err := Dialog{
		AssignTo:      &dlg,
		Title:         "Noise Filter",
		DefaultButton: &okPB,
		CancelButton:  &cancelPB,
		MinSize:       Size{Width: 460, Height: 250},
		Layout:        VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}, Spacing: 10},
		Children: []Widget{
			TextLabel{
				MinSize: Size{Width: 420, Height: 130},
				Text: "\"Noise\" means multicast and broadcast traffic — " +
					"one-to-many chatter such as mDNS, SSDP, LLMNR, and " +
					"NetBIOS. It is identified by the ADDRESS (IPv4 224.0.0.0–" +
					"239.255.255.255 or x.x.x.255, and IPv6 ff00::/8), not by " +
					"port.\n\n" +
					"Leave the box below EMPTY to treat all multicast/broadcast " +
					"traffic as noise (recommended).\n\n" +
					"Optionally, enter a comma-separated list of ports to NARROW " +
					"the filter so that only multicast/broadcast traffic on those " +
					"ports counts as noise — e.g. enter 5353 to hide only mDNS.",
			},
			LineEdit{
				AssignTo:  &edit,
				Text:      initial,
				CueBanner: "empty = all multicast/broadcast (e.g. 5353, 1900)",
			},
			Composite{
				Layout: HBox{Spacing: 8},
				Children: []Widget{
					HSpacer{},
					PushButton{
						AssignTo: &okPB,
						Text:     "OK",
						OnClicked: func() {
							app.noisePorts = parseNoisePorts(edit.Text())
							dlg.Accept()
						},
					},
					PushButton{
						AssignTo:  &cancelPB,
						Text:      "Cancel",
						OnClicked: func() { dlg.Cancel() },
					},
				},
			},
		},
	}.Run(app.mw)
	if err != nil {
		dbg("showNoiseDialog: %v", err)
		return
	}
	// Reapply with the (possibly) updated set. setCollapse keeps display fresh.
	applyFilters()
}

// parseNoisePorts parses a comma-separated port list into a set. Invalid or
// out-of-range tokens are ignored. An empty/blank input yields an empty set,
// which the noise filter interprets as "no narrowing" — all multicast/
// broadcast traffic is treated as noise.
func parseNoisePorts(s string) map[int]bool {
	out := make(map[int]bool)
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if n, err := strconv.Atoi(tok); err == nil && n > 0 && n <= 65535 {
			out[n] = true
		}
	}
	return out
}

func clearFilters() {
	app.filterProto.SetText("")
	if app.filterProtoNot != nil {
		app.filterProtoNot.SetChecked(false)
	}
	app.filterSrcIP.SetText("")
	app.filterDstIP.SetText("")
	app.filterSrcPort.SetText("")
	app.filterDstPort.SetText("")
	app.filterDirection.SetCurrentIndex(0)
	app.filterAction.SetCurrentIndex(0)
	if app.filterIPVersion != nil {
		app.filterIPVersion.SetCurrentIndex(0) // blank = all versions
	}
	app.filterPID.SetText("")
	app.filterProcess.SetText("")
	app.filterRule.SetText("")
	if app.filterPIDNot != nil {
		app.filterPIDNot.SetChecked(false)
	}
	if app.filterProcNot != nil {
		app.filterProcNot.SetChecked(false)
	}
	if app.filterRuleNot != nil {
		app.filterRuleNot.SetChecked(false)
	}
	if app.filterSrcIPNot != nil {
		app.filterSrcIPNot.SetChecked(false)
	}
	if app.filterDstIPNot != nil {
		app.filterDstIPNot.SetChecked(false)
	}
	if app.filterSrcPortNot != nil {
		app.filterSrcPortNot.SetChecked(false)
	}
	if app.filterDstPortNot != nil {
		app.filterDstPortNot.SetChecked(false)
	}
	if app.filterHideNoMatch != nil {
		app.filterHideNoMatch.SetChecked(false)
	}
	applyFilters()
}

// updateCount refreshes the event-count status bar item.
// Must be called on the UI goroutine.
func updateCount() {
	app.mu.Lock()
	total := app.totalCount
	app.mu.Unlock()
	visible := app.model.RowCount()
	if visible == total {
		setCount(fmt.Sprintf("%d events", total))
	} else {
		setCount(fmt.Sprintf("%d / %d shown", visible, total))
	}
}

func showDetail(owner *walk.MainWindow, e *LogEntry) {
	srcPort := "-"
	dstPort := "-"
	if e.SrcPort > 0 {
		srcPort = strconv.Itoa(e.SrcPort)
	}
	if e.DstPort > 0 {
		dstPort = strconv.Itoa(e.DstPort)
	}
	timestamp := "-"
	if e.HasTimestamp {
		zone := "local"
		if app.timeZone == "utc" {
			zone = "UTC"
		}
		timestamp = eventTimeIn(e.Timestamp).Format("2006-01-02 "+timeLayout()) + " " + zone
	}
	srcIP := dashIfEmpty(e.SrcIP)
	dstIP := dashIfEmpty(e.DstIP)
	pid := "-"
	if e.PID > 0 {
		pid = strconv.Itoa(e.PID)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb,
		"Timestamp:    %s\nAction:       %s\nDirection:    %s\nProtocol:     %s\n\n"+
			"Source IP:    %s\nSource Port:  %s\n\n"+
			"Dest IP:      %s\nDest Port:    %s\n\n"+
			"PID:          %s\nProcess:      %s\n\n"+
			"Matched Rule: %s\nWFP Filter:   %s\n",
		timestamp,
		dashIfEmpty(e.Action), e.Direction, dashIfEmpty(e.Protocol),
		srcIP, srcPort,
		dstIP, dstPort,
		pid, dashIfEmpty(e.ProcessName),
		dashIfEmpty(e.MatchedRuleName), dashIfEmpty(e.WFPFilterName),
	)
	if e.Path != "" {
		fmt.Fprintf(&sb, "Process Path: %s\n", e.Path)
	}

	// Possible rule matches: the looser, attribute-based list (includes broad
	// rules that the Matched Rule column suppresses). These are rules whose
	// conditions are consistent with this packet — NOT proof of what WFP
	// evaluated. The WFP Filter field above is the ground-truth attribution.
	const maxPossible = 12
	lines, loaded := globalMatcher.PossibleMatches(e, maxPossible)
	sb.WriteString("\nPossible rule matches (heuristic, by attributes):\n")
	switch {
	case !loaded:
		sb.WriteString("  (rules not loaded yet)\n")
	case len(lines) == 0:
		sb.WriteString("  (none consistent with this connection)\n")
	default:
		for _, ln := range lines {
			sb.WriteString("  - " + ln + "\n")
		}
	}

	showReadOnlyTextDialog(owner, "Event Detail", sb.String())
}

func showReadOnlyTextDialog(owner walk.Form, title, body string) {
	showReadOnlyTextDialogWithScroll(owner, title, body, true)
}

func showReadOnlyWrappedTextDialog(owner walk.Form, title, body string) {
	showReadOnlyTextDialogWithScroll(owner, title, body, false)
}

func showReadOnlyTextDialogWithScroll(owner walk.Form, title, body string, hscroll bool) {
	var dlg *walk.Dialog
	var closePB *walk.PushButton
	var te *walk.TextEdit

	// The Win32 edit control used by walk.TextEdit expects CRLF line endings for
	// multiline display. The event-detail builder uses LF line endings, which
	// MsgBox handled, but TextEdit can collapse into a single line without this
	// normalization.
	body = strings.ReplaceAll(body, "\r\n", "\n")
	body = strings.ReplaceAll(body, "\n", "\r\n")

	d := Dialog{
		AssignTo:      &dlg,
		Title:         title,
		DefaultButton: &closePB,
		CancelButton:  &closePB,
		MinSize:       Size{Width: 760, Height: 560},
		Layout:        VBox{Margins: Margins{Left: 12, Top: 12, Right: 12, Bottom: 12}, Spacing: 10},
		Children: []Widget{
			TextEdit{
				AssignTo: &te,
				Text:     body,
				ReadOnly: true,
				VScroll:  true,
				HScroll:  hscroll,
				Font:     Font{Family: "Consolas", PointSize: 9},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{AssignTo: &closePB, Text: "Close", OnClicked: func() { dlg.Accept() }},
				},
			},
		},
	}
	if err := d.Create(owner); err != nil {
		dbg("showReadOnlyTextDialogWithScroll: %v", err)
		return
	}

	clearSelection := func() {
		if closePB != nil {
			_ = closePB.SetFocus()
		}
		if te != nil {
			te.SetTextSelection(0, 0)
		}
	}

	// TextEdit can receive initial dialog focus with the full body selected.
	// Focus the Close button first, then clear the text selection so the body is
	// readable immediately but remains selectable/copyable when the user clicks it.
	dlg.Starting().Attach(func() {
		dlg.Synchronize(clearSelection)
	})

	dlg.Run()
}

func showSecurityLogHelp(owner *walk.MainWindow) {
	const body = `Windows Security Log

The Windows Security log is the Windows event log that records security-related audit events, including sign-ins, policy changes, object access, and Windows Filtering Platform firewall/audit events when the relevant audit policy is enabled.

WinFWMon reads firewall connection events from the Security log. In particular, it uses Windows Filtering Platform connection auditing events such as allowed and blocked connection records. If the needed audit policy is disabled, those events may not be present for WinFWMon to display.

Clearing the Security log

If you want to clear the Security log, you can do it from an elevated account:

1. Open Event Viewer.
2. Go to Windows Logs > Security.
3. Choose Clear Log...
4. Optionally save the log before clearing it.

You can also run this from an elevated Command Prompt or PowerShell:

wevtutil cl Security

Consequences of clearing the Security log

Clearing the Security log removes existing security audit history from the local machine. That can make past sign-in, policy-change, firewall, and other security events unavailable for troubleshooting, compliance review, or incident investigation. Clearing the log may itself be recorded as an audit event depending on system policy, and in managed environments it may conflict with organizational retention or monitoring requirements.

Clearing the log does not disable auditing. New Security log events will continue to be recorded after the log is cleared, subject to the configured audit policy and log size/retention settings.`

	showReadOnlyWrappedTextDialog(owner, "About the Windows Security Log", body)
}

// dashIfEmpty returns "-" for an empty string, otherwise the string unchanged.
func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// aboutBody is the license/credits text shown in the About dialog, below a
// runtime-built header line carrying appName and appVersion.
const aboutBody = `Copyright (c) 2026 WinFWMon Contributors

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Third-party libraries used at build time (all MIT licensed):

  github.com/lxn/walk   Windows GUI toolkit
  github.com/lxn/win    Windows API bindings
  golang.org/x/sys      Go extended system library

Source and full license texts:
  https://github.com/lxn/walk
  https://github.com/lxn/win
  https://github.com/golang/sys`

func showAbout(owner *walk.MainWindow) {
	header := fmt.Sprintf("%s - Windows Firewall Monitor v%s\n\n", appName, appVersion)
	walk.MsgBox(owner, "About "+appName, header+aboutBody,
		walk.MsgBoxIconInformation|walk.MsgBoxOK)
}

// showColumnsDialog lets the user choose which table columns are visible. The
// checkboxes reflect the live column state; on Apply the visibility of each
// column is updated. Column order can additionally be changed at any time by
// dragging the column headers directly (ColumnsOrderable is enabled).
func showColumnsDialog() {
	if app.table == nil {
		return
	}
	cols := app.table.Columns()
	n := cols.Len()
	if n == 0 {
		return
	}

	var dlg *walk.Dialog
	var okPB, cancelPB *walk.PushButton
	boxes := make([]*walk.CheckBox, n)

	checkChildren := make([]Widget, 0, n)
	for i := 0; i < n; i++ {
		c := cols.At(i)
		checkChildren = append(checkChildren, CheckBox{
			AssignTo: &boxes[i],
			Text:     c.TitleEffective(),
			Checked:  c.Visible(),
		})
	}

	children := []Widget{
		Label{Text: "Show or hide columns. Drag column headers in the table to reorder them."},
		Composite{
			Layout:   Grid{Columns: 2, Spacing: 6},
			Children: checkChildren,
		},
		Composite{
			Layout: HBox{Spacing: 8},
			Children: []Widget{
				HSpacer{},
				PushButton{
					AssignTo: &okPB,
					Text:     "OK",
					OnClicked: func() {
						if applyColumnVisibility(boxes) {
							dlg.Accept()
						}
					},
				},
				PushButton{
					AssignTo:  &cancelPB,
					Text:      "Cancel",
					OnClicked: func() { dlg.Cancel() },
				},
			},
		},
	}

	Dialog{
		AssignTo:      &dlg,
		Title:         "Columns",
		DefaultButton: &okPB,
		CancelButton:  &cancelPB,
		MinSize:       Size{Width: 320, Height: 320},
		Layout:        VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}, Spacing: 10},
		Children:      children,
	}.Run(app.mw)
}

// applyColumnVisibility sets each column's visibility from the dialog
// checkboxes. At least one column is kept visible so the table is never blank.
// Returns true if applied, false if the request was rejected (all hidden).
func applyColumnVisibility(boxes []*walk.CheckBox) bool {
	if app.table == nil {
		return true
	}
	cols := app.table.Columns()

	anyVisible := false
	for _, b := range boxes {
		if b.Checked() {
			anyVisible = true
			break
		}
	}
	if !anyVisible {
		walk.MsgBox(app.mw, "Columns",
			"At least one column must remain visible.",
			walk.MsgBoxIconWarning|walk.MsgBoxOK)
		return false
	}

	for i := 0; i < cols.Len() && i < len(boxes); i++ {
		cols.At(i).SetVisible(boxes[i].Checked()) //nolint:errcheck
	}
	return true
}

// exportVisible writes the currently displayed rows (after filtering) to a
// tab-separated text file, including only the columns currently visible, in the
// current on-screen (visual) column order. A header block records which filters
// were active so the export is self-describing. The user picks the destination
// via a save dialog.
func exportVisible() {
	if app.table == nil || app.model == nil {
		return
	}

	// Determine which columns are visible, in the user's current visual (drag)
	// order, with their titles. Falls back to logical order if the native order
	// cannot be read (see visibleColumnIndicesInDisplayOrder).
	colIdx := visibleColumnIndicesInDisplayOrder()
	headers := make([]string, 0, len(colIdx))
	for _, i := range colIdx {
		headers = append(headers, columnDefs[i].title)
	}
	dbg("exportVisible: using visible column order %v (%s)", colIdx, columnOrderTitles(colIdx))
	if len(colIdx) == 0 {
		walk.MsgBox(app.mw, "Export",
			"There are no visible columns to export.",
			walk.MsgBoxIconWarning|walk.MsgBoxOK)
		return
	}

	dlg := new(walk.FileDialog)
	dlg.Title = "Export Displayed Events"
	dlg.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
	dlg.InitialDirPath, _ = os.UserHomeDir()
	ok, err := dlg.ShowSave(app.mw)
	if err != nil || !ok || dlg.FilePath == "" {
		return
	}
	path := dlg.FilePath
	if filepath.Ext(path) == "" {
		path += ".txt"
	}

	rows := app.model.visibleSnapshot()
	content := buildExport(headers, colIdx, rows)

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		walk.MsgBox(app.mw, "Export Failed",
			fmt.Sprintf("Could not write the file:\n\n%v", err),
			walk.MsgBoxIconError|walk.MsgBoxOK)
		return
	}

	setStatus(fmt.Sprintf("Exported %d events to %s", len(rows), path))
}

// buildExport formats the export file: a header block describing the active
// filters, then a tab-separated table with the given column headers and the
// values for each row's selected columns. Lines are CRLF-terminated since the
// output is a Windows text file consumed by Windows tools (Notepad, Excel).
func buildExport(headers []string, colIdx []int, rows []*LogEntry) string {
	const nl = "\r\n"
	var sb strings.Builder

	sb.WriteString(appName + " v" + appVersion + " event export" + nl)
	sb.WriteString("Generated: " + time.Now().Format("2006-01-02 15:04:05") + nl)
	zoneLabel := "local time"
	if app.timeZone == "utc" {
		zoneLabel = "UTC"
	}
	sb.WriteString(fmt.Sprintf("Times shown in: %s (precision: %s)%s", zoneLabel, app.timePrecision, nl))
	sb.WriteString(fmt.Sprintf("Rows: %d%s", len(rows), nl))

	filters := describeActiveFilters()
	if filters == "" {
		sb.WriteString("Filters: (none)" + nl)
	} else {
		sb.WriteString("Filters: " + filters + nl)
	}
	sb.WriteString(nl)

	// Tab-separated header and rows. Tabs/newlines within a value are replaced
	// with spaces so the row/column structure cannot be broken by the data.
	sb.WriteString(strings.Join(headers, "\t"))
	sb.WriteString(nl)

	for _, e := range rows {
		fields := make([]string, len(colIdx))
		for j, ci := range colIdx {
			fields[j] = sanitizeField(columnDefs[ci].value(e))
		}
		sb.WriteString(strings.Join(fields, "\t"))
		sb.WriteString(nl)
	}

	return sb.String()
}

// sanitizeField replaces tab and newline characters so a single value cannot
// disrupt the tab-separated layout.
func sanitizeField(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// describeActiveFilters returns a human-readable summary of the filters that
// are currently applied, or "" if none are set. Read on the UI goroutine.
func describeActiveFilters() string {
	var parts []string
	add := func(label, val string) {
		if strings.TrimSpace(val) != "" {
			parts = append(parts, label+"="+strings.TrimSpace(val))
		}
	}
	addNeg := func(label, val string, neg bool) {
		if strings.TrimSpace(val) == "" {
			return
		}
		op := "="
		if neg {
			op = "!="
		}
		parts = append(parts, label+op+strings.TrimSpace(val))
	}
	addNeg("Protocol", app.filterProto.Text(), app.filterProtoNot != nil && app.filterProtoNot.Checked())
	addNeg("SrcIP", app.filterSrcIP.Text(), app.filterSrcIPNot != nil && app.filterSrcIPNot.Checked())
	addNeg("DstIP", app.filterDstIP.Text(), app.filterDstIPNot != nil && app.filterDstIPNot.Checked())
	addNeg("SrcPort", app.filterSrcPort.Text(), app.filterSrcPortNot != nil && app.filterSrcPortNot.Checked())
	addNeg("DstPort", app.filterDstPort.Text(), app.filterDstPortNot != nil && app.filterDstPortNot.Checked())
	add("Direction", app.filterDirection.Text())
	add("Action", app.filterAction.Text())
	if app.filterIPVersion != nil && app.filterIPVersion.Text() != "" {
		parts = append(parts, "IP="+app.filterIPVersion.Text())
	}
	addNeg("PID", app.filterPID.Text(), app.filterPIDNot != nil && app.filterPIDNot.Checked())
	addNeg("Process", app.filterProcess.Text(), app.filterProcNot != nil && app.filterProcNot.Checked())
	addNeg("MatchedRule", app.filterRule.Text(), app.filterRuleNot != nil && app.filterRuleNot.Checked())
	if app.filterHideNoMatch != nil && app.filterHideNoMatch.Checked() {
		parts = append(parts, "HideNoMatch=true")
	}
	if !app.historyMode && app.onlyAfterCheck != nil && app.onlyAfterCheck.Checked() {
		parts = append(parts, "OnlyAfterLaunch=true")
	}
	if app.hideNoiseCheck != nil && app.hideNoiseCheck.Checked() {
		parts = append(parts, "HideNoise=true")
	} else if app.collapseCheck != nil && app.collapseCheck.Checked() {
		parts = append(parts, "CollapseDuplicates=true")
	}
	if app.hideLoopbackCheck != nil && app.hideLoopbackCheck.Checked() {
		parts = append(parts, "HideLoopback=true")
	}
	return strings.Join(parts, ", ")
}

// showEnableAuditingDialog presents the startup prompt offering to enable WFP
// connection auditing (Security log events 5156/5157), with a checkbox
// controlling whether to restore the prior audit policy on exit.
// Returns:
//   - enable:  true if the user chose to enable auditing
//   - restore: true if the "restore prior audit policy on exit" box was ticked
//
// If the user cancels, enable is false (restore still reflects the checkbox).
func showEnableAuditingDialog(state wfpAuditState) (enable, restore bool) {
	var dlg *walk.Dialog
	var enablePB, cancelPB *walk.PushButton
	var restoreCB *walk.CheckBox

	// Describe the current state explicitly. A partial state (one of
	// success/failure on, the other off) is easy to misread as "off", so call
	// it out: in that state only half the connection events are recorded
	// (allowed-only or blocked-only).
	var statusLine string
	switch {
	case state.Success && !state.Failure:
		statusLine = "Current state: PARTIAL - success (allowed) auditing is on, " +
			"but failure (blocked) auditing is off, so blocked-connection events " +
			"(5157) are not being recorded.\n\n"
	case state.Failure && !state.Success:
		statusLine = "Current state: PARTIAL - failure (blocked) auditing is on, " +
			"but success (allowed) auditing is off, so allowed-connection events " +
			"(5156) are not being recorded.\n\n"
	default:
		statusLine = "Current state: WFP connection auditing is off.\n\n"
	}

	intro := statusLine +
		"WinFWMon reads allowed and blocked connection events " +
		"(5156/5157) from the Windows Security log. This requires the " +
		"\"Filtering Platform Connection\" audit policy to be enabled.\n\n" +
		"WinFWMon can enable it now (success + failure auditing).\n\n" +
		"WARNING: this audit category is high-volume and can write a very large " +
		"number of events to the Security log while it is enabled.\n\n" +
		"You may want to clear the Security log afterward. To do so: open Event " +
		"Viewer > Windows Logs > Security > Clear Log, or run 'wevtutil cl " +
		"Security' from an elevated Command Prompt."

	_, err := Dialog{
		AssignTo:      &dlg,
		Title:         "Enable WFP Connection Auditing?",
		DefaultButton: &enablePB,
		CancelButton:  &cancelPB,
		MinSize:       Size{Width: 520, Height: 400},
		Layout:        VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}, Spacing: 10},
		Children: []Widget{
			TextLabel{
				Text:    intro,
				MinSize: Size{Width: 480, Height: 240},
			},
			CheckBox{
				AssignTo: &restoreCB,
				Text:     "Restore the prior audit policy when WinFWMon exits",
				Checked:  true,
			},
			Composite{
				Layout: HBox{Spacing: 8},
				Children: []Widget{
					HSpacer{},
					PushButton{
						AssignTo: &enablePB,
						Text:     "Enable Auditing",
						OnClicked: func() {
							enable = true
							restore = restoreCB.Checked()
							dlg.Accept()
						},
					},
					PushButton{
						AssignTo: &cancelPB,
						Text:     "Skip",
						OnClicked: func() {
							enable = false
							restore = restoreCB.Checked()
							dlg.Cancel()
						},
					},
				},
			},
		},
	}.Run(app.mw)

	if err != nil {
		return false, false
	}
	return enable, restore
}
