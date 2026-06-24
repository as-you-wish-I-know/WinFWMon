// Copyright (c) 2026 WinFWMon Contributors
// SPDX-License-Identifier: MIT
//
// Windows list-view column-order helpers. walk exposes column visibility and
// width directly, but the visual header order (after the user drags column
// headers) is held only in the native ListView/Header controls. These helpers
// read that order (so export and config save can capture it) and write it back
// (so a saved layout reapplies on the next launch), via the documented
// ListView/Header messages.
// See LICENSE for full license text.

package main

import (
	"strings"
	"syscall"
	"unsafe"

	"github.com/lxn/walk"
)

const (
	lvmFirst     = 0x1000
	lvmGetHeader = lvmFirst + 31
	// lvmGetColumnOrderArray retrieves, and lvmSetColumnOrderArray sets, the
	// current left-to-right order of the native ListView columns.
	lvmSetColumnOrderArray = lvmFirst + 58
	lvmGetColumnOrderArray = lvmFirst + 59

	hdmFirst         = 0x1200
	hdmGetItemCount  = hdmFirst + 0
	hdmOrderToIndex  = hdmFirst + 15
	hdmGetOrderArray = hdmFirst + 17
	hdmSetOrderArray = hdmFirst + 18

	maxClassNameLen = 256
)

var (
	user32             = syscall.NewLazyDLL("user32.dll")
	user32SendMessage  = user32.NewProc("SendMessageW")
	user32FindWindowEx = user32.NewProc("FindWindowExW")
	user32GetClassName = user32.NewProc("GetClassNameW")
)

// visibleColumnIndicesInDisplayOrder returns the logical indices of the visible
// columns, ordered to match their on-screen left-to-right position. If the
// native order cannot be read it falls back to logical (model) order, so export
// always produces a sensible result.
func visibleColumnIndicesInDisplayOrder() []int {
	if app.table == nil || app.table.Columns() == nil {
		return nil
	}
	cols := app.table.Columns()
	order, ok := currentColumnOrder(app.table)
	if !ok || len(order) != cols.Len() {
		order = make([]int, 0, cols.Len())
		for i := 0; i < cols.Len(); i++ {
			order = append(order, i)
		}
	}
	out := make([]int, 0, len(order))
	for _, i := range order {
		if i >= 0 && i < cols.Len() && i < len(columnDefs) && cols.At(i).Visible() {
			out = append(out, i)
		}
	}
	return out
}

// currentColumnOrder returns the table's columns in visual (left-to-right)
// order as logical indices, completed with any not-yet-seen columns appended in
// logical order. ok is false only when no native order source could be read.
func currentColumnOrder(table *walk.TableView) ([]int, bool) {
	if table == nil || table.Columns() == nil {
		return nil, false
	}
	cols := table.Columns()
	n := cols.Len()
	if n == 0 {
		return nil, false
	}

	visible := visibleColumnIndices(table)
	if len(visible) == 0 {
		return defaultColumnOrder(n), true
	}

	lv := listViewHandle(table)
	header := headerHandle(table)

	// Walk only creates native ListView/Header columns for VISIBLE TableView
	// columns. The native order APIs must therefore be called with the visible
	// count, not the full logical count; native indices are translated back to
	// logical columnDefs indices via the visible slice.
	if lv != 0 {
		if order, ok := visibleColumnOrderFromMessage(lv, lvmGetColumnOrderArray, visible); ok {
			return completeColumnOrder(order, n), true
		}
	}

	if header != 0 {
		if order, ok := visibleColumnOrderFromMessage(header, hdmGetOrderArray, visible); ok {
			return completeColumnOrder(order, n), true
		}
		if order, ok := headerVisibleOrderByPosition(header, visible); ok {
			return completeColumnOrder(order, n), true
		}
	}

	return nil, false
}

func visibleColumnIndices(table *walk.TableView) []int {
	if table == nil || table.Columns() == nil {
		return nil
	}
	cols := table.Columns()
	visible := make([]int, 0, cols.Len())
	for i := 0; i < cols.Len(); i++ {
		if cols.At(i).Visible() {
			visible = append(visible, i)
		}
	}
	return visible
}

func defaultColumnOrder(n int) []int {
	order := make([]int, 0, n)
	for i := 0; i < n; i++ {
		order = append(order, i)
	}
	return order
}

// completeColumnOrder takes the visible columns' logical indices in visual
// order and appends any remaining (hidden) logical indices in their natural
// order, yielding a full permutation of all column indices 0..n-1.
func completeColumnOrder(visibleOrder []int, n int) []int {
	seen := make([]bool, n)
	out := make([]int, 0, n)
	for _, idx := range visibleOrder {
		if idx >= 0 && idx < n && !seen[idx] {
			seen[idx] = true
			out = append(out, idx)
		}
	}
	for i := 0; i < n; i++ {
		if !seen[i] {
			out = append(out, i)
		}
	}
	return out
}

func visibleColumnOrderFromMessage(hwnd uintptr, msg uintptr, visible []int) ([]int, bool) {
	if hwnd == 0 || len(visible) == 0 {
		return nil, false
	}
	nativeOrder, ok := columnOrderFromMessage(hwnd, msg, len(visible))
	if !ok {
		return nil, false
	}
	logicalOrder := make([]int, 0, len(nativeOrder))
	for _, nativeIdx := range nativeOrder {
		if nativeIdx < 0 || nativeIdx >= len(visible) {
			return nil, false
		}
		logicalOrder = append(logicalOrder, visible[nativeIdx])
	}
	return logicalOrder, true
}

func headerVisibleOrderByPosition(header uintptr, visible []int) ([]int, bool) {
	if header == 0 || len(visible) == 0 {
		return nil, false
	}
	logicalOrder := make([]int, 0, len(visible))
	for visualPos := 0; visualPos < len(visible); visualPos++ {
		nativeIdx, _, _ := user32SendMessage.Call(header, hdmOrderToIndex, uintptr(visualPos), 0)
		idx := int(nativeIdx)
		if idx < 0 || idx >= len(visible) {
			return nil, false
		}
		logicalOrder = append(logicalOrder, visible[idx])
	}
	return logicalOrder, true
}

func columnOrderFromMessage(hwnd uintptr, msg uintptr, n int) ([]int, bool) {
	if hwnd == 0 || n <= 0 {
		return nil, false
	}
	order32 := make([]int32, n)
	ret, _, _ := user32SendMessage.Call(
		hwnd,
		msg,
		uintptr(n),
		uintptr(unsafe.Pointer(&order32[0])),
	)
	if ret == 0 {
		return nil, false
	}
	order := make([]int, 0, n)
	for _, v := range order32 {
		order = append(order, int(v))
	}
	if !validColumnOrder(order, n) {
		return nil, false
	}
	return order, true
}

func validColumnOrder(order []int, n int) bool {
	if len(order) != n {
		return false
	}
	seen := make([]bool, n)
	for _, v := range order {
		if v < 0 || v >= n || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

func listViewHandle(table *walk.TableView) uintptr {
	if table == nil {
		return 0
	}
	hwnd := uintptr(table.Handle())
	if hwnd == 0 {
		return 0
	}
	if windowClassName(hwnd) == "SysListView32" {
		return hwnd
	}
	visibleCount := 0
	if table.Columns() != nil {
		visibleCount = len(visibleColumnIndices(table))
	}
	return bestListViewDescendant(hwnd, visibleCount, 6)
}

func headerHandle(table *walk.TableView) uintptr {
	if table == nil {
		return 0
	}
	if lv := listViewHandle(table); lv != 0 {
		header, _, _ := user32SendMessage.Call(lv, uintptr(lvmGetHeader), 0, 0)
		if header != 0 {
			return header
		}
		if child := findDescendantWindowByClass(lv, "SysHeader32", 6); child != 0 {
			return child
		}
	}
	hwnd := uintptr(table.Handle())
	if hwnd == 0 {
		return 0
	}
	if windowClassName(hwnd) == "SysHeader32" {
		return hwnd
	}
	return findDescendantWindowByClass(hwnd, "SysHeader32", 6)
}

func bestListViewDescendant(parent uintptr, visibleCount int, maxDepth int) uintptr {
	if parent == 0 || maxDepth <= 0 {
		return 0
	}
	var best uintptr
	bestCount := -1
	for _, hwnd := range descendantWindowsByClass(parent, "SysListView32", maxDepth) {
		count := listViewHeaderItemCount(hwnd)
		if visibleCount > 0 && count == visibleCount {
			return hwnd
		}
		if count > bestCount {
			best = hwnd
			bestCount = count
		}
	}
	return best
}

func listViewHeaderItemCount(lv uintptr) int {
	if lv == 0 {
		return -1
	}
	header, _, _ := user32SendMessage.Call(lv, uintptr(lvmGetHeader), 0, 0)
	if header == 0 {
		return -1
	}
	ret, _, _ := user32SendMessage.Call(header, hdmGetItemCount, 0, 0)
	return int(ret)
}

func descendantWindowsByClass(parent uintptr, className string, maxDepth int) []uintptr {
	if parent == 0 || maxDepth <= 0 {
		return nil
	}
	var out []uintptr
	for child, _, _ := user32FindWindowEx.Call(parent, 0, 0, 0); child != 0; child, _, _ = user32FindWindowEx.Call(parent, child, 0, 0) {
		if windowClassName(child) == className {
			out = append(out, child)
		}
		out = append(out, descendantWindowsByClass(child, className, maxDepth-1)...)
	}
	return out
}

func findDescendantWindowByClass(parent uintptr, className string, maxDepth int) uintptr {
	wins := descendantWindowsByClass(parent, className, maxDepth)
	if len(wins) == 0 {
		return 0
	}
	return wins[0]
}

func windowClassName(hwnd uintptr) string {
	if hwnd == 0 {
		return ""
	}
	buf := make([]uint16, maxClassNameLen)
	ret, _, _ := user32GetClassName.Call(
		hwnd,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:ret])
}

// columnOrderTitles renders a column-order slice as a human-readable list of
// titles for debug logging.
func columnOrderTitles(order []int) string {
	titles := make([]string, 0, len(order))
	for _, i := range order {
		if i >= 0 && i < len(columnDefs) {
			titles = append(titles, columnDefs[i].title)
		} else {
			titles = append(titles, "?")
		}
	}
	return strings.Join(titles, " | ")
}

// setColumnOrder applies a full logical column order (a permutation of all
// column indices) to the table's native controls, so a saved layout reapplies
// on launch. order must be a complete, valid permutation of all column indices
// 0..n-1; only the visible columns are reordered natively (hidden columns have
// no native column), so the visible subset of order is translated to native
// positions. Returns true if at least one native control accepted the order.
func setColumnOrder(table *walk.TableView, order []int) bool {
	if table == nil || table.Columns() == nil {
		return false
	}
	cols := table.Columns()
	n := cols.Len()
	if len(order) != n || n == 0 || !validColumnOrder(order, n) {
		return false
	}
	visible := visibleColumnIndices(table)
	if len(visible) == 0 {
		return true
	}
	visiblePos := make(map[int]int, len(visible))
	for pos, logical := range visible {
		visiblePos[logical] = pos
	}
	visibleDisplayOrder := make([]int, 0, len(visible))
	for _, logical := range order {
		if _, ok := visiblePos[logical]; ok {
			visibleDisplayOrder = append(visibleDisplayOrder, logical)
		}
	}
	if len(visibleDisplayOrder) != len(visible) {
		return false
	}

	// The set-order message wants an array indexed by visual position containing
	// the current native ListView index of the column. Native ListView indices
	// are only among visible columns, so translate logical indices to visible
	// positions.
	nativeOrder := make([]int, len(visibleDisplayOrder))
	for visual, logical := range visibleDisplayOrder {
		nativeOrder[visual] = visiblePos[logical]
	}

	ok := false
	if hwnd := listViewHandle(table); hwnd != 0 {
		lvOK := setColumnOrderByMessage(hwnd, lvmSetColumnOrderArray, nativeOrder)
		dbg("setColumnOrder: LVM_SETCOLUMNORDERARRAY native=%v visible=%v (%s) ok=%v", nativeOrder, visibleDisplayOrder, columnOrderTitles(visibleDisplayOrder), lvOK)
		ok = lvOK || ok
	}
	if header := headerHandle(table); header != 0 {
		hOK := setColumnOrderByMessage(header, hdmSetOrderArray, nativeOrder)
		dbg("setColumnOrder: HDM_SETORDERARRAY native=%v visible=%v (%s) ok=%v", nativeOrder, visibleDisplayOrder, columnOrderTitles(visibleDisplayOrder), hOK)
		ok = hOK || ok
	}
	return ok
}

func setColumnOrderByMessage(hwnd uintptr, msg uintptr, order []int) bool {
	if hwnd == 0 || len(order) == 0 {
		return false
	}
	order32 := make([]int32, len(order))
	for i, v := range order {
		order32[i] = int32(v)
	}
	ret, _, _ := user32SendMessage.Call(
		hwnd,
		msg,
		uintptr(len(order)),
		uintptr(unsafe.Pointer(&order32[0])),
	)
	return ret != 0
}
