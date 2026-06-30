# WinFWMon

**Version 2.0**

A native Windows 11 application that watches Windows Filtering Platform (WFP)
connection events in real time, displays allowed and blocked connections
color-coded, and resolves each event to the exact firewall filter that made the
decision.

## Features

- **Live event stream** — new connection events appear automatically; pause/resume at any time. By default events arrive via a low-latency **EvtSubscribe** push subscription (typically sub-second); if that cannot start, the app automatically falls back to **PowerShell** polling and notes this in the status bar. The status bar always shows the active source and whether it is Running or Stopped (or History mode).
- **Color-coded rows** — green for ALLOW (5156), red for DROP (5157)
- **Two-level rule attribution**:
  - **Matched Rule** — the recognizable Windows Defender Firewall rule, found by
    matching the connection's attributes (program, direction, protocol, ports).
    Double-click a row to see all possible rule matches, ranked.
  - **WFP Filter** (hidden by default) — the exact low-level WFP filter that made
    the decision, resolved from the event's filter run-time ID. This is ground
    truth, but is often a system/infrastructure filter rather than a UI rule.
- **Columns** — Date (hidden), Time, Action, Count (hidden), Direction, Protocol,
  Source IP/Port, Dest IP/Port, PID, Process, Matched Rule, WFP Filter (hidden);
  reorder by dragging headers and show/hide via the Columns… dialog
- **Filters** — protocol (free-text, matches any IP protocol name), source/dest
  IP, source/dest port, direction, action, PID, process name (partial), and
  matched rule (partial), each with a "Not" option to invert the match; plus a
  "Hide (No matching rule)" option to show only events that resolved to a
  recognizable firewall rule
- **Full IP protocol recognition** — TCP, UDP, ICMP, ICMPv6, IGMP, GRE, ESP, AH,
  SCTP, OSPF, EIGRP, and other IANA protocols are shown by name; unrecognised
  numbers appear as `proto N`
- **Highlight ICMP** — on by default; ICMP/ICMPv6 rows use a paler shade (pale
  green if allowed, pale red if dropped) so control messages stand out
- **Hide multicast/broadcast noise** — on by default. "Noise" is defined by the
  ADDRESS — IPv4 multicast (224–239.x) and broadcast (x.x.x.255), and IPv6
  multicast (ff00::/8) — not by port, so all such chatter (mDNS, SSDP, LLMNR,
  NetBIOS, etc.) is caught. Untick it to show that traffic, with an optional
  **Collapse duplicates** mode that merges identical multicast events into one
  row with a count. The Noise… button lets you optionally NARROW the filter to
  specific ports (e.g. enter 5353 to hide only mDNS); leave it empty to treat
  all multicast/broadcast as noise.
- **Start / Stop button** — to the right of Clear Log. If WFP connection
  auditing is on (because you enabled it at startup, or it was already on), the
  button reads "Stop" and turns auditing off; otherwise it reads "Start" and
  turns it on. Changing the audit policy requires running as Administrator.
- **Only show events after launch** — on by default; hides the historical backlog
- **Export…** — writes the currently displayed rows (respecting visible columns,
  active filters, and the current visual column order) to a tab-separated text file
- **Double-click any row** for full event detail, including possible rule matches
- **Help → About the Windows Security Log...** explains what the Windows
  Security log is, how WinFWMon uses it to read firewall events, how the log can
  be cleared, and the consequences of clearing it.
- **Preferences menu** — Columns…, Noise Filter…, Event Window…, and Time Display…
  live under the Preferences menu
- **Reload Rules** button — located beside the Start/Stop button; refreshes the
  WFP filter table and firewall rules. During a reload the button is disabled,
  displays "Reloading...", and is re-enabled when the reload completes.
- **Hide loopback traffic** — on by default; hides purely local traffic where
  BOTH endpoints are loopback (IPv4 127.0.0.0/8 or IPv6 ::1). Traffic with only
  one loopback endpoint is kept.
- **Time display** — Preferences → Time Display lets you choose timestamp
  precision (whole seconds, milliseconds, or microseconds) and zone (local or
  UTC); the dialog also shows the detected local time zone. When UTC is
  selected the Time column header reads "Time (UTC)".
- **Configurable event window** — set how many events are kept in memory
  (100–50,000) via Preferences → Event Window, with a "Reset to Default" button.
  Changes apply immediately; shrinking trims the oldest events, and the setting
  is remembered between runs
- **Remembers your settings** — saved to `WinFWMon.json` beside the executable
  (or the location given with `--config`) and restored on the next launch:
  the noise port list; the event-window size; the time-display precision and
  zone; the Hide noise, Collapse, Highlight ICMP, Hide-no-match,
  Only-after-launch, Hide-loopback, and Live-tail toggles; the column layout
  (which columns are visible, their widths, and their visual order); and the
  filter bar (Protocol, Src/Dst IP, Src/Dst Port, Direction, Action, IP version,
  PID, Process, and Matched Rule, including each field's "Not" state).
  - Note: the **Only-after-launch** *checkbox state* is remembered, but its
    cutoff is intentionally **not** stored as a timestamp. The option means
    "hide events from before this run started," so the cutoff is recomputed from
    the current launch time every run — a saved timestamp would be meaningless.
  - Because filters are restored, the app may open already filtered (the
    `N / M shown` count reflects this); use **Clear Filters** to reset.
- Keeps a configurable rolling window of events in memory (default 2,000) to
  avoid unbounded growth

---

## Command-line options

WinFWMon is a GUI program but accepts a few command-line switches. The
informational ones attach to the console of the shell that launched them, print
their output there, and exit without opening a window.

- `--help`, `-h` — show version and the list of options, then exit.
- `--debug` — write a debug log (`WinFWMon_debug.log`) beside the executable.
- `--history` — show only events already in the Security log; do not enable WFP
  auditing or poll for new events. The Start button is disabled in this mode.
  Growing the event window in this mode re-reads a deeper backlog.
- `--powershell` — use the PowerShell (`Get-WinEvent`) polling event source
  instead of the default low-latency EvtSubscribe source. Applies to both live
  monitoring and the history-mode backlog read.
- `--no-fallback` — if the EvtSubscribe source fails to start, exit with an error
  instead of falling back to PowerShell polling. Cannot be combined with
  `--powershell` (doing so is reported as an error and the app exits).
- `--wfp` — print the current WFP connection-auditing status and exit.
- `--wfp=on` / `--wfp=off` — turn WFP connection auditing on/off and exit.
  Requires an elevated (Administrator) console; returns a non-zero exit code if
  it cannot comply, so it is scriptable.
- `--config=<path>` — use `<path>` as the configuration file instead of the
  default. If the path is not usable the app reports the problem and exits
  rather than silently falling back.
- `--license` — print the MIT license text and exit.

Note: because WinFWMon is a GUI-subsystem binary, console output may appear
after the shell prompt returns. This is normal on Windows. For the same reason,
after a command-line option prints its output the shell may not immediately draw
a fresh prompt; the prompt is fully functional (typed commands run normally) and
pressing Enter redraws it. This is a cosmetic quirk only.

---

## Requirements

| Tool | Where to get it |
|------|----------------|
| **Go 1.22+** | https://golang.org/dl/ |
| Internet access (first build only) | To download Go modules |

No C compiler, no Visual Studio, no .NET runtime needed.

---

## Build

```
build.bat
```

The output is a single `WinFWMon.exe` with no external dependencies.

---

## How it works

WinFWMon reads **Windows Security log** events 5156 (the Windows
Filtering Platform allowed a connection) and 5157 (a connection was blocked).
Each event includes a **Filter Run-Time ID** identifying the exact WFP filter
that made the decision. The app dumps the active filters with
`netsh wfp show filters` and maps that ID to the filter's display name, which
for firewall rules is the rule name shown in Windows Defender Firewall.

This is precise attribution: it reports the filter that actually handled the
packet, rather than guessing from direction/protocol/port as a text-log reader
must.

### Event sources

For **live monitoring**, WinFWMon subscribes to the Security log through the
Windows Event Log API (`EvtSubscribe`), which pushes 5156/5157 events as they
are written — typically surfacing them in well under a second. If the
subscription cannot start, the app automatically falls back to **PowerShell**
(`Get-WinEvent`) polling and notes this in the status bar. The `--powershell`
switch forces the polling source from the start; `--no-fallback` makes an
EvtSubscribe failure fatal instead of falling back.

For **history mode** (`--history`), the existing backlog is read through the
companion `EvtQuery` API, which is dramatically faster than the previous
PowerShell approach — tens of thousands of events load near-instantly. (Under
`--powershell`, history uses the slower PowerShell backlog read instead.)

Both sources produce identical event records and feed the same downstream
rule-attribution and display logic, so the active source does not change how any
event appears.

### WFP connection auditing

Events 5156/5157 are only recorded when the **"Filtering Platform Connection"**
audit subcategory is enabled. This is **off by default** because it is
high-volume. When run as Administrator, WinFWMon offers to enable it
automatically (success + failure) at startup, and can restore the prior audit
policy on exit. You can also enable it yourself:

```
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
```

and check the current state with:

```
auditpol /get /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}"
```

---

## Running

Run as Administrator (right-click → "Run as administrator"). Administrator
rights are required to read the Security log, to enable WFP auditing, and to
dump the WFP filter table. Without elevation the app shows only events already
present in the Security log and cannot enable auditing.

---

## Filters

| Field | Notes |
|-------|-------|
| IP version | IPv4 only / IPv6 only / all |
| Protocol | TCP, UDP, ICMP, ICMPv6, or blank for all |
| Src/Dst IP | Substring match — enter `192.168` to match any 192.168.x.x address; wrap in quotes for an exact match (`"192.168.1.1"`) |
| Src/Dst Port | Substring match against the port number — `80` matches 80, 800, and 8080; wrap in quotes for an exact match (`"80"` matches only 80) |
| Direction | Inbound / Outbound / all |
| Action | Allow / Drop / all |
| PID | Exact process ID |
| Process | Substring match against the resolved process name |
| Matched Rule | Substring match against the resolved filter/rule name |

Text filters (IP, port, process, matched rule) are case-insensitive substring
matches by default; wrap a value in double quotes for an exact, whole-value
match.

Filters apply instantly to the current view. Incoming events are also filtered
in real time, and the total count reflects every event received.

---

## File Structure

```
WinFWMon/
├── main.go          — UI, table model, event pump, dialogs
├── args.go          — Command-line parsing and headless (--help/--wfp) commands
├── console.go       — Parent-console attach + output for headless modes
├── config.go        — Settings persistence (WinFWMon.json) and --config handling
├── eventlog.go      — Security-log event source (Get-WinEvent 5156/5157)
├── evtsubscribe.go  — Low-latency EvtSubscribe push event source (wevtapi)
├── wfpfilters.go    — WFP filter table (netsh wfp show filters) and ID→name resolution
├── rules.go         — Defender firewall rule matcher (attribute-based attribution)
├── parser.go        — Shared LogEntry event record type
├── filter.go        — Filter logic
├── process.go       — PID → process-name resolver (toolhelp snapshot)
├── helpers.go       — Process-exec helpers and auditpol WFP audit management
├── debuglog.go      — Optional --debug logging
├── syscall_windows.go — Windows process attribute helper
├── winfwmon.manifest — DPI and common-controls manifest
├── go.mod
├── build.bat
└── testing/
    └── generate_traffic.ps1 — optional helper to generate steady firewall events
```

---

## Testing

The `testing/` folder contains an optional helper for exercising the monitor:

**`generate_traffic.ps1`** — produces a steady, dense stream of outbound firewall
events so you can watch WinFWMon surface live connections without waiting for
incidental network activity. It opens short-lived TCP connections (to Google
public DNS, `8.8.8.8:53`, by default) a few times per second. TCP connections
are logged far more reliably as 5156 events than ICMP echoes (ping), which
Windows under-logs, which is why this uses TCP rather than a simple ping loop.

Run it in a separate elevated PowerShell window while WinFWMon is monitoring:

```
powershell -ExecutionPolicy Bypass -File testing\generate_traffic.ps1
```

Stop it with Ctrl+C when finished. The script makes real outbound connection
attempts but sends no data; if you prefer to avoid sustained external
connections, edit the `$target` variable to point at a LAN address (such as your
router) — the firewall event fires on the local connection attempt regardless of
the destination. The connection rate is set by `$perSecond` near the top of the
script.

---

## Limitations

- **Event window vs. performance**: a larger event window (up to 50,000) keeps
  more history but uses more memory and makes each filter change slightly slower,
  since the full retained set is re-filtered. The default of 2,000 is a balance;
  raise it if you need more scrollback and have the memory to spare.
- **PID reuse**: the resolved process name comes from a live snapshot; Windows
  recycles PIDs, so an event's PID may occasionally map to a different process
  than the one that actually generated it.
- **Many events have no matched rule, and that is usually correct**: Windows
  allows outbound traffic by a global default policy rather than a per-app rule,
  and most inbound drops come from the default block policy. Such events
  genuinely are not governed by a named rule, so they show `(No matching rule)`.
  Use the "Hide (No matching rule)" option to focus on rule-governed events. The
  "Matched Rule" column is an attribute-based heuristic; the "WFP Filter" column
  (hidden by default) is the ground-truth filter that made the decision.
- **Unnamed filters**: some low-level platform filters have no display name, so
  their events show `(Unnamed filter)` rather than a friendly rule name.
- **High volume**: WFP connection auditing can add many events per second to the
  Security log while enabled. Disable it (or let the app restore it on exit)
  when you are done monitoring.
