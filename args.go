// Copyright (c) 2026 WinFWMon Contributors
// SPDX-License-Identifier: MIT
//
// Command-line argument parsing. All arguments are parsed once, up front, in
// main() before any GUI is created. Some switches (--help, --wfp[=on|off]) are
// "headless": they attach to the parent console, print a result, and exit
// without ever building a window. Others (--debug, --history, --config) modify
// how the GUI then runs.
// See LICENSE for full license text.

package main

import (
	"strings"
)

// cliArgs holds the parsed command-line configuration that influences the GUI
// run. Headless switches are handled entirely within parseAndDispatchArgs and
// never surface here.
type cliArgs struct {
	debug      bool
	history    bool   // --history: ingest existing events only; no auditing, no polling
	configPath string // --config=<path>: override the config file location ("" = default)
}

// parseAndDispatchArgs parses os.Args. If a headless command is present it runs
// it (attaching to the parent console), and returns exitNow=true with the exit
// code the process should use. Otherwise it returns the parsed GUI args with
// exitNow=false.
//
// Headless commands are mutually exclusive with launching the GUI; the first
// one encountered wins and the process exits after running it.
func parseAndDispatchArgs(argv []string) (args cliArgs, exitNow bool, code int) {
	for _, raw := range argv {
		arg := strings.TrimSpace(raw)
		lower := strings.ToLower(arg)

		switch {
		case lower == "--debug" || lower == "-debug" || lower == "/debug":
			args.debug = true

		case lower == "--history" || lower == "/history":
			args.history = true

		case lower == "--help" || lower == "-h" || lower == "/help" || lower == "/?":
			attachParentConsole()
			printHelp()
			return args, true, finishHeadless(0)

		case lower == "--license" || lower == "/license":
			attachParentConsole()
			printLicense()
			return args, true, finishHeadless(0)

		case lower == "--wfp" || lower == "/wfp":
			attachParentConsole()
			return args, true, finishHeadless(runWFPStatus())

		case lower == "--wfp=on" || lower == "/wfp=on":
			attachParentConsole()
			return args, true, finishHeadless(runWFPSet(true))

		case lower == "--wfp=off" || lower == "/wfp=off":
			attachParentConsole()
			return args, true, finishHeadless(runWFPSet(false))

		case strings.HasPrefix(lower, "--config=") || strings.HasPrefix(lower, "/config="):
			// Preserve original case of the path value (file systems may care).
			eq := strings.IndexByte(arg, '=')
			val := strings.TrimSpace(arg[eq+1:])
			// Strip surrounding quotes if the shell passed them through.
			val = strings.Trim(val, `"`)
			if val == "" {
				// The user explicitly asked for a config path but gave none.
				// Fail loudly rather than silently using the default.
				attachParentConsole()
				consoleErr("WinFWMon: --config= requires a file path.")
				return args, true, finishHeadless(2)
			}
			args.configPath = val

		default:
			if strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "/") {
				// Unknown switch: report to console and exit non-zero so typos
				// are not silently ignored.
				attachParentConsole()
				consoleErr("WinFWMon: unknown option %q", arg)
				consoleErr("Run WinFWMon --help for usage.")
				return args, true, finishHeadless(2)
			}
			// Non-switch bare argument: ignore (no positional args are defined).
		}
	}
	return args, false, 0
}

// finishHeadless performs the common end-of-command console flourish (a
// trailing blank line and a one-second pause so output settles before the
// prompt redraws) and returns the exit code unchanged, so it can wrap a return
// expression directly.
func finishHeadless(code int) int {
	finishConsole()
	return code
}

// printHelp writes the version banner and the list of supported switches.
func printHelp() {
	consoleOut("%s %s", appName, appVersion)
	consoleOut("A live Windows Firewall / WFP connection-event monitor.")
	consoleOut("")
	consoleOut("Usage: WinFWMon [options]")
	consoleOut("")
	consoleOut("Options:")
	consoleOut("  --help, -h           Show this help and exit.")
	consoleOut("  --debug              Write a debug log (WinFWMon_debug.log) beside the exe.")
	consoleOut("  --history            Show only events already in the Security log; do not")
	consoleOut("                       enable WFP auditing or poll for new events. The Start")
	consoleOut("                       button is disabled in this mode.")
	consoleOut("  --wfp                Print the current WFP connection-auditing status and exit.")
	consoleOut("  --wfp=on             Turn WFP connection auditing on and exit (needs Administrator).")
	consoleOut("  --wfp=off            Turn WFP connection auditing off and exit (needs Administrator).")
	consoleOut("  --config=<path>      Use <path> as the configuration file instead of the")
	consoleOut("                       default (WinFWMon.json beside the executable).")
	consoleOut("  --license            Show the MIT license text and exit.")
	consoleOut("")
	consoleOut("Note: console output from a GUI program may appear after the shell prompt")
	consoleOut("returns; this is normal on Windows.")
}

// printLicense writes the MIT license text for WinFWMon to the console.
func printLicense() {
	consoleOut("%s %s", appName, appVersion)
	consoleOut("")
	consoleOut("MIT License")
	consoleOut("")
	consoleOut("Copyright (c) 2026 WinFWMon Contributors")
	consoleOut("")
	consoleOut("Permission is hereby granted, free of charge, to any person obtaining a copy")
	consoleOut("of this software and associated documentation files (the \"Software\"), to deal")
	consoleOut("in the Software without restriction, including without limitation the rights")
	consoleOut("to use, copy, modify, merge, publish, distribute, sublicense, and/or sell")
	consoleOut("copies of the Software, and to permit persons to whom the Software is")
	consoleOut("furnished to do so, subject to the following conditions:")
	consoleOut("")
	consoleOut("The above copyright notice and this permission notice shall be included in all")
	consoleOut("copies or substantial portions of the Software.")
	consoleOut("")
	consoleOut("THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR")
	consoleOut("IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,")
	consoleOut("FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE")
	consoleOut("AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER")
	consoleOut("LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,")
	consoleOut("OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE")
	consoleOut("SOFTWARE.")
}

// runWFPStatus prints the current auditing state. Returns 0 always (reading
// status needs no elevation).
func runWFPStatus() int {
	state, err := readWFPAuditStateErr()
	if err != nil {
		consoleErr("WinFWMon: could not read WFP connection-auditing status: %v", err)
		consoleErr("(reading the audit policy may require an elevated console)")
		return 1
	}
	switch {
	case state.FullyEnabled():
		consoleOut("WFP connection auditing: ON (success and failure)")
	case state.Success || state.Failure:
		consoleOut("WFP connection auditing: PARTIAL (success=%v, failure=%v)",
			state.Success, state.Failure)
	default:
		consoleOut("WFP connection auditing: OFF")
	}
	return 0
}

// runWFPSet turns auditing on or off. Requires elevation; if not elevated it
// prints an error to stderr and returns a non-zero code so scripts can detect
// the failure.
func runWFPSet(on bool) int {
	if !isElevated() {
		consoleErr("WinFWMon: changing WFP connection auditing requires an " +
			"elevated (Administrator) console.")
		return 1
	}
	if on {
		if _, err := enableWFPAuditing(); err != nil {
			consoleErr("WinFWMon: failed to enable WFP auditing: %v", err)
			return 1
		}
		consoleOut("WFP connection auditing turned ON.")
		return 0
	}
	if err := disableWFPAuditing(); err != nil {
		consoleErr("WinFWMon: failed to disable WFP auditing: %v", err)
		return 1
	}
	consoleOut("WFP connection auditing turned OFF.")
	return 0
}
