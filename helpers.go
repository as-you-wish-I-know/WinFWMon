// Copyright (c) 2026 WinFWMon Contributors
// SPDX-License-Identifier: MIT
//
// Process-execution helpers and WFP connection-audit policy management.
// Auditing is controlled via auditpol; enabling it causes the Security event
// log to record WFP 5156 (allow) and 5157 (block) connection events.
// See LICENSE for full license text.

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// runCommand runs a command line through cmd.exe and returns its stdout.
func runCommand(cmdStr string) (string, error) {
	cmd := exec.Command("cmd", "/C", cmdStr)
	cmd.SysProcAttr = hiddenWindow()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("command failed: %w", err)
	}
	return string(out), nil
}

// runPowerShell runs a PowerShell script directly via powershell.exe, WITHOUT
// going through cmd.exe. This avoids the nested-quoting corruption that occurs
// when a complex -Command string is passed through `cmd /C "powershell ..."`,
// where cmd.exe mangles the inner quotes and truncates the script.
func runPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell",
		"-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = hiddenWindow()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("powershell failed: %w", err)
	}
	return string(out), nil
}

// isElevated returns true if Windows reports that the current process token is
// elevated. This asks the OS for token state directly instead of inferring
// elevation from access to a particular registry key, which can be affected by
// policy or ACL hardening unrelated to administrator status.
func isElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()

	var elevation struct {
		TokenIsElevated uint32
	}
	var outLen uint32
	if err := windows.GetTokenInformation(
		token,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)),
		uint32(unsafe.Sizeof(elevation)),
		&outLen,
	); err != nil {
		return false
	}
	return elevation.TokenIsElevated != 0
}

// wfpAuditSubcategory is the GUID of the "Filtering Platform Connection" audit
// subcategory, used with auditpol. The GUID is locale-independent, unlike the
// display name, so we always use it.
const wfpAuditSubcategory = "{0CCE9226-69AE-11D9-BED3-505054503030}"

// wfpAuditState describes whether WFP connection auditing is on.
type wfpAuditState struct {
	Success bool
	Failure bool
}

// FullyEnabled reports whether both success and failure auditing are on, which
// is required to capture both allowed (5156) and blocked (5157) events.
func (s wfpAuditState) FullyEnabled() bool { return s.Success && s.Failure }

// readWFPAuditState queries the current auditing state for the WFP connection
// subcategory via auditpol.
func readWFPAuditState() wfpAuditState {
	st, _ := readWFPAuditStateErr()
	return st
}

// readWFPAuditStateErr is like readWFPAuditState but reports whether the query
// itself failed, so callers (e.g. the headless --wfp status) can distinguish
// "auditing is off" from "could not read the policy" rather than misreporting
// an unreadable state as OFF.
func readWFPAuditStateErr() (wfpAuditState, error) {
	out, err := runCommand(`auditpol /get /subcategory:` + wfpAuditSubcategory)
	if err != nil {
		dbg("readWFPAuditState: auditpol error: %v", err)
		return wfpAuditState{}, err
	}
	// The subcategory line ends with one of:
	//   "No Auditing" | "Success" | "Failure" | "Success and Failure"
	lower := strings.ToLower(out)
	return wfpAuditState{
		Success: strings.Contains(lower, "success"),
		Failure: strings.Contains(lower, "failure"),
	}, nil
}

// enableWFPAuditing turns on success+failure auditing for WFP connections.
// Returns the prior state so it can be restored on exit.
func enableWFPAuditing() (prior wfpAuditState, err error) {
	prior = readWFPAuditState()
	_, err = runCommand(
		`auditpol /set /subcategory:` + wfpAuditSubcategory +
			` /success:enable /failure:enable`)
	if err != nil {
		return prior, fmt.Errorf("auditpol enable failed: %w", err)
	}
	return prior, nil
}

// disableWFPAuditing turns off both success and failure auditing for the WFP
// connection subcategory. Returns an error if auditpol fails.
func disableWFPAuditing() error {
	_, err := runCommand(
		`auditpol /set /subcategory:` + wfpAuditSubcategory +
			` /success:disable /failure:disable`)
	if err != nil {
		return fmt.Errorf("auditpol disable failed: %w", err)
	}
	return nil
}

// restoreWFPAuditing sets WFP connection auditing back to the given state.
// Best-effort: errors are logged, not returned, since this runs at exit.
func restoreWFPAuditing(state wfpAuditState) {
	successFlag := "disable"
	if state.Success {
		successFlag = "enable"
	}
	failureFlag := "disable"
	if state.Failure {
		failureFlag = "enable"
	}
	_, err := runCommand(
		`auditpol /set /subcategory:` + wfpAuditSubcategory +
			` /success:` + successFlag + ` /failure:` + failureFlag)
	if err != nil {
		dbg("restoreWFPAuditing: %v", err)
	}
}
