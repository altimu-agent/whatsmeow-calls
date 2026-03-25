// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeowcalls

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	waBinary "go.mau.fi/whatsmeow/binary"
)

func TestDumpNode_Nil(t *testing.T) {
	result := DumpNode(nil)
	if result != "<nil>" {
		t.Errorf("DumpNode(nil) = %q, want %q", result, "<nil>")
	}
}

func TestDumpNode_Simple(t *testing.T) {
	node := &waBinary.Node{
		Tag:   "offer",
		Attrs: waBinary.Attrs{"call-id": "abc123", "call-creator": "user@s.whatsapp.net"},
	}
	result := DumpNode(node)
	if !strings.Contains(result, "<offer") {
		t.Errorf("expected <offer tag, got: %s", result)
	}
	if !strings.Contains(result, "call-id") {
		t.Errorf("expected call-id attr, got: %s", result)
	}
}

func TestDumpNode_WithChildren(t *testing.T) {
	node := &waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": "msg1"},
		Content: []waBinary.Node{
			{Tag: "offer", Attrs: waBinary.Attrs{"call-id": "c1"}},
		},
	}
	result := DumpNode(node)
	if !strings.Contains(result, "<call") {
		t.Errorf("expected <call, got: %s", result)
	}
	if !strings.Contains(result, "<offer") {
		t.Errorf("expected nested <offer, got: %s", result)
	}
	if !strings.Contains(result, "</call>") {
		t.Errorf("expected closing </call>, got: %s", result)
	}
}

func TestDumpNode_WithBinaryContent(t *testing.T) {
	node := &waBinary.Node{
		Tag:     "enc",
		Content: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	result := DumpNode(node)
	if !strings.Contains(result, "deadbeef") {
		t.Errorf("expected hex content, got: %s", result)
	}
	if !strings.Contains(result, "4 bytes") {
		t.Errorf("expected byte count, got: %s", result)
	}
}

func TestSaveDump(t *testing.T) {
	dir := t.TempDir()
	node := &waBinary.Node{
		Tag:   "offer",
		Attrs: waBinary.Attrs{"call-id": "test-call-1"},
	}

	err := SaveDump(dir, "test-call-1", "offer", node)
	if err != nil {
		t.Fatalf("SaveDump failed: %v", err)
	}

	// Verify directory was created
	callDir := filepath.Join(dir, "test-call-1")
	entries, err := os.ReadDir(callDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 file, got %d", len(entries))
	}
	if !strings.HasPrefix(entries[0].Name(), "offer_") {
		t.Errorf("expected file starting with offer_, got: %s", entries[0].Name())
	}
}

func TestSaveDump_EmptyDir(t *testing.T) {
	node := &waBinary.Node{Tag: "test"}
	err := SaveDump("", "call1", "offer", node)
	if err != nil {
		t.Errorf("SaveDump with empty dir should be no-op, got: %v", err)
	}
}

func TestSaveDump_NilNode(t *testing.T) {
	err := SaveDump("/tmp", "call1", "offer", nil)
	if err != nil {
		t.Errorf("SaveDump with nil node should be no-op, got: %v", err)
	}
}
