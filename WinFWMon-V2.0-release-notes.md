# WinFWMon V2.0 — Release Notes

WinFWMon V2.0 replaces how the application captures firewall events. Live
monitoring now uses a Windows Event Log **push subscription** instead of repeated
PowerShell polling, and history mode reads its backlog through a **native query
API** instead of building an XML document per event in PowerShell. The result is
that events surface in well under a second instead of several, and loading
existing history is near-instant even for tens of thousands of events. The
change in how events are fetched is significant enough to warrant a new major
version; all V1.0 functionality is retained.

---

## Highlights

- **Live events are now sub-second.** The live source uses a `wevtapi`
  `EvtSubscribe` push subscription that delivers connection events (5156/5157) as
  they are written, rather than polling on a timer. Measured on real hardware,
  this is roughly 3–4× faster to surface an event than the previous polling
  approach (about 1 second or less, versus around 4 seconds).
- **History mode is dramatically faster.** Reading the existing backlog now uses
  the `EvtQuery` API. In testing, tens of thousands of events load in a few
  seconds or less, where the previous PowerShell approach could take minutes —
  e.g. ~27,000 events read in just over 3 seconds, and 2,000 events essentially
  instantly.
- **PowerShell polling is retained as a fallback**, so the proven V1.0 event path
  is still available if the push subscription cannot start.
- **All V1.0 features are preserved** — column layout and filter-state
  persistence, the full filter set, noise handling, rule attribution, export,
  history mode, audit management, and so on.

---

## New

- **EvtSubscribe live event source** (new `evtsubscribe.go`). A push subscription
  to the Security log, with no new third-party dependency (it binds `wevtapi`
  through the existing `golang.org/x/sys/windows`). Events are parsed into the
  same internal records the polling path produced — field-for-field identical,
  confirmed by a parity test against thousands of real events — so rule
  attribution, filtering, and display behave exactly as before regardless of
  which source produced an event.
- **EvtQuery history backlog reader.** History mode (`--history`) reads existing
  events through the native query API and shares the same parser as the live
  source, so history and live records are identical by construction.
- **New command-line switches for source selection:**
  - `--powershell` — use the PowerShell (`Get-WinEvent`) source instead of the
    default EvtSubscribe source. Applies to both live monitoring and the
    history-mode backlog read.
  - `--no-fallback` — if the EvtSubscribe source fails to start, exit with an
    error instead of falling back to PowerShell. Cannot be combined with
    `--powershell` (doing so reports an error and exits).
- **Status bar now shows the active event source and its state** — e.g.
  "EvtSubscribe: Running", "PowerShell: Running (EvtSubscribe failed; fell back)",
  or, in history mode, which reader was used ("History mode (snapshot, EvtQuery)"
  vs "… PowerShell"). It also reflects Running/Stopped and history state.
- **Testing aid included.** `testing/generate_traffic.ps1` opens short-lived TCP
  connections at a steady rate to produce a reliable stream of 5156 events for
  watching live monitoring (TCP is used because Windows under-logs ICMP/ping).

---

## Behavior and selection rules

- **Source selection happens once, at startup, and is fixed for the session** —
  there is no mid-run switching. By default WinFWMon tries EvtSubscribe and falls
  back to PowerShell polling if it cannot start, noting the fallback in the
  status bar.
- The event source is **source-agnostic downstream**: both sources feed the same
  pipeline, so all filtering, rule/WFP-filter resolution, and display are
  unchanged.
- Memory remains **bounded by the event-window cap** (default 2,000, max 50,000);
  the model trims oldest events. A sustained run shows memory plateau rather than
  unbounded growth.

---

## Fixes and refinements

- **The "WFP filters and firewall rules reloaded" status message now clears
  itself** after about 5 seconds, reverting to the normal program-state message
  rather than persisting. A generation counter ensures this revert never
  overwrites a newer, more important status (e.g. if you pause during the
  interval), and the reverted message correctly reflects the true state
  including paused / auditing-off / history mode.
- **The paused state is now reflected accurately** anywhere the program returns
  to its "normal" status — it will no longer briefly claim it is reading the
  Security log while actually paused.
- **The PAUSED message is clearer**, indicating that events are still being
  collected while the display is frozen and will catch up on resume.
- **`--history --powershell` is honored** — history mode now correctly uses the
  PowerShell backlog read when PowerShell is forced (previously it always used
  the fast native path regardless of the switch).
- **Cleared a stale internal fallback note** on an audit stop/start cycle that
  re-establishes the EvtSubscribe source (found during code review; was not
  user-visible but is now correct).

---

## Requirements and notes

- **Windows. Administrator required** for live monitoring (reading the Security
  log and enabling WFP connection auditing both require elevation). History mode
  reading also requires Administrator.
- **WFP connection auditing must be on** for connection events to exist;
  WinFWMon can enable it and restores the prior state on exit.
- **No new dependencies.** WinFWMon still uses only the Go standard library, the
  walk GUI stack, and `golang.org/x/sys`. The `wevtapi` bindings are loaded
  dynamically and add nothing to the dependency set.
- **First build needs internet once.** `build.bat` runs `go mod tidy` to fetch
  dependencies and generate `go.sum`; subsequent builds work offline.

---

## Upgrading from V1.0

No action required. V2.0 is a drop-in replacement: the configuration file format
is unchanged, all V1.0 settings (column layout, filters, window size, time
display) carry over, and the user interface and existing command-line switches
are the same. The only additions are the new `--powershell` and `--no-fallback`
switches and the status-bar source indicator. If the new event source ever
misbehaves on a particular machine, `--powershell` reverts to the exact V1.0
event path.
