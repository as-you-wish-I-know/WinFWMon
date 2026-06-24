// Copyright (c) 2026 WinFWMon Contributors
// SPDX-License-Identifier: MIT
//
// Lightweight debug logging to a file next to the executable.
// See LICENSE for full license text.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	debugEnabled bool
	debugFile    *os.File
	debugMu      sync.Mutex
	debugInit    bool
)

// enableDebugLogging turns on debug logging. Call once at startup (e.g. when
// the --debug command-line flag is present) before any dbg call matters.
func enableDebugLogging() {
	debugMu.Lock()
	debugEnabled = true
	debugMu.Unlock()
}

// debugLogPath returns the path for the debug log: same directory as the exe,
// named WinFWMon_debug.log.
func debugLogPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "WinFWMon_debug.log"
	}
	return filepath.Join(filepath.Dir(exe), "WinFWMon_debug.log")
}

// dbg writes a timestamped line to the debug log, but only if debug logging was
// enabled via --debug. It is safe for concurrent use and never panics; logging
// failures are silently ignored.
func dbg(format string, args ...interface{}) {
	debugMu.Lock()
	defer debugMu.Unlock()

	if !debugEnabled {
		return
	}

	// Lazily open the file on first use, under the same lock that guards all
	// access to debugFile, so initialisation cannot race with closeDebugLog.
	if !debugInit {
		debugInit = true
		if f, err := os.OpenFile(debugLogPath(),
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); err == nil {
			debugFile = f
		}
	}

	if debugFile == nil {
		return
	}
	line := fmt.Sprintf("%s  %s\n",
		time.Now().Format("15:04:05.000"),
		fmt.Sprintf(format, args...))
	debugFile.WriteString(line)
}

// closeDebugLog flushes and closes the debug log. After this, further dbg calls
// are no-ops (debugFile stays nil and debugInit stays true).
func closeDebugLog() {
	debugMu.Lock()
	defer debugMu.Unlock()
	if debugFile != nil {
		debugFile.Close()
		debugFile = nil
	}
}
