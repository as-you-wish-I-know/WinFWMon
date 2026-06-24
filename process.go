// Copyright (c) 2026 WinFWMon Contributors
// SPDX-License-Identifier: MIT
//
// Resolves process IDs (PIDs) to process names via the Windows toolhelp
// snapshot API, with a short-lived cache. Best-effort: a PID logged by the
// firewall may already have exited, in which case the name is unknown.
// See LICENSE for full license text.

package main

import (
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// processResolver maps PIDs to process names using periodic snapshots of the
// running process list. Snapshots are taken at most once per refreshInterval,
// so a burst of lookups (e.g. resolving a 500-entry backlog) shares a single
// snapshot rather than triggering one per entry.
//
// Limitation: Windows recycles PIDs, and the firewall logs a PID at the time of
// the packet, which may have been reused by the time we snapshot. Resolution is
// therefore best-effort and can occasionally attribute a name to the wrong
// process; there is no way to do better from the log alone.
type processResolver struct {
	mu          sync.Mutex
	names       map[uint32]string
	lastRefresh time.Time
	refreshing  bool
}

var globalProcResolver = &processResolver{names: make(map[uint32]string)}

// refreshInterval is the minimum time between process-list snapshots.
const refreshInterval = 3 * time.Second

// Name returns the process name for pid, or "" if it cannot be resolved.
// pid 0 returns "" (the firewall logs 0 when no PID is associated).
//
// If the cache is older than refreshInterval, Name refreshes it at most once
// per interval (guarded so concurrent callers do not each take a snapshot).
func (pr *processResolver) Name(pid int) string {
	if pid <= 0 {
		return ""
	}
	upid := uint32(pid)

	pr.mu.Lock()
	name := pr.names[upid]
	// Refresh only when the cache is stale and no other caller is already
	// doing so. A burst of lookups within one interval shares one snapshot.
	if !pr.refreshing && time.Since(pr.lastRefresh) > refreshInterval {
		pr.refreshing = true
		pr.mu.Unlock()

		names, err := snapshotProcessNames()

		pr.mu.Lock()
		if err == nil {
			pr.names = names
		}
		pr.lastRefresh = time.Now()
		pr.refreshing = false
		name = pr.names[upid]
	}
	pr.mu.Unlock()
	return name
}

// snapshotProcessNames returns a map of PID to executable name for all
// currently running processes.
func snapshotProcessNames() (map[uint32]string, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	result := make(map[uint32]string, 256)

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, err
	}
	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		result[entry.ProcessID] = name

		if err := windows.Process32Next(snapshot, &entry); err != nil {
			// ERROR_NO_MORE_FILES signals the end of enumeration.
			break
		}
	}
	return result, nil
}
