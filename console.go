// Copyright (c) 2026 WinFWMon Contributors
// SPDX-License-Identifier: MIT
//
// Console support for the command-line (headless) switches. WinFWMon is built
// as a Windows GUI-subsystem binary, so it has no console of its own and Go's
// os.Stdout/os.Stderr are bound to invalid handles at startup. When a headless
// switch like --help or --wfp is used, the app attaches to the console of the
// process that launched it (cmd.exe / PowerShell) AND re-binds the standard
// output handles to that console (via CONOUT$), so fmt output is actually
// visible. Without the re-bind, AttachConsole alone succeeds but every write
// still goes nowhere.
//
// A cosmetic quirk of GUI-subsystem binaries is well known and accepted: the
// launching shell does not wait for the process, so its prompt may have
// already returned, and the output can appear interleaved with that prompt.
// See LICENSE for full license text.

package main

import (
	"fmt"
	"os"
	"syscall"
)

const attachParentProcess = ^uint32(0) // ATTACH_PARENT_PROCESS (DWORD -1)

// consoleAttached records whether we successfully bound to a parent console,
// so callers can decide how to behave when no console is present.
var consoleAttached bool

// attachParentConsole attaches to the parent's console (if any) and re-points
// stdout and stderr at it so Go's fmt package writes are visible. It is
// best-effort: with no parent console (e.g. launched from Explorer) it does
// nothing and leaves consoleAttached false.
func attachParentConsole() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	attach := kernel32.NewProc("AttachConsole")
	r, _, _ := attach.Call(uintptr(attachParentProcess))
	if r == 0 {
		return // no parent console available
	}

	// Re-open the console's active screen buffer and re-bind the standard
	// handles. os.Stdout/os.Stderr captured at program init point at invalid
	// handles under the GUI subsystem, so without this the writes are lost.
	if h, err := openConsoleHandle("CONOUT$"); err == nil {
		setStdHandle(stdOutputHandle, h)
		setStdHandle(stdErrorHandle, h)
		os.Stdout = os.NewFile(uintptr(h), "/dev/stdout")
		os.Stderr = os.NewFile(uintptr(h), "/dev/stderr")
		consoleAttached = true
		// Because a GUI-subsystem binary does not block the shell, the prompt
		// has already been printed and the cursor sits right after it. Emit two
		// blank lines so command output starts cleanly on its own line below the
		// prompt instead of being appended to it (e.g. "C:\dir>WFP ... : OFF").
		consoleOut("")
		consoleOut("")
	}
}

const (
	// STD_OUTPUT_HANDLE (-11) and STD_ERROR_HANDLE (-12) as unsigned DWORDs.
	// Windows truncates the uintptr to its low 32 bits, giving the documented
	// (DWORD)-11 / (DWORD)-12 values.
	stdOutputHandle = uintptr(4294967285) // 0xFFFFFFF5 == (DWORD)-11
	stdErrorHandle  = uintptr(4294967284) // 0xFFFFFFF4 == (DWORD)-12
)

// openConsoleHandle opens CONOUT$ for writing and returns the resulting
// handle, used to re-bind the standard output streams. CONOUT$ is a screen
// buffer, so it is opened GENERIC_WRITE only (requesting GENERIC_READ on it can
// fail on some configurations); FILE_SHARE_READ|WRITE matches how the console
// host shares the buffer.
func openConsoleHandle(name string) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	return syscall.CreateFile(
		p,
		syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
}

// setStdHandle binds a standard handle (stdout/stderr) to h via the Win32
// SetStdHandle API, so child/console APIs and re-derived os.File objects agree.
func setStdHandle(which uintptr, h syscall.Handle) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("SetStdHandle")
	proc.Call(which, uintptr(h))
}

// consoleOut writes a line to stdout (for normal command output).
func consoleOut(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, format+"\r\n", args...)
}

// consoleErr writes a line to stderr (for error/diagnostic output).
func consoleErr(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\r\n", args...)
}

// finishConsole is called at the end of every headless command, just before
// the process exits. It prints one trailing blank line so there is a clean gap
// between the command output and the shell prompt that the user is returned to.
// The leading separation is emitted by attachParentConsole. No-op if no console
// was attached (e.g. launched from Explorer).
func finishConsole() {
	if !consoleAttached {
		return
	}
	consoleOut("")
}
