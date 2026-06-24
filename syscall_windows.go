// Copyright (c) 2026 WinFWMon Contributors
// SPDX-License-Identifier: MIT
//
// Windows-specific syscall helpers.
// See LICENSE for full license text.

package main

import (
	"syscall"
)

func hiddenWindow() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true}
}
