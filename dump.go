// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeowcalls

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
)

// DumpNode serializes a binary node to a human-readable indented string.
// Binary content is displayed as hex. Useful for inspecting call signaling.
func DumpNode(node *waBinary.Node) string {
	if node == nil {
		return "<nil>"
	}
	var b strings.Builder
	dumpNodeIndent(&b, node, 0)
	return b.String()
}

func dumpNodeIndent(b *strings.Builder, node *waBinary.Node, depth int) {
	indent := strings.Repeat("  ", depth)
	fmt.Fprintf(b, "%s<%s", indent, node.Tag)

	for k, v := range node.Attrs {
		fmt.Fprintf(b, " %s=%q", k, fmt.Sprint(v))
	}

	children := node.GetChildren()
	if children != nil {
		b.WriteString(">\n")
		for i := range children {
			dumpNodeIndent(b, &children[i], depth+1)
		}
		fmt.Fprintf(b, "%s</%s>\n", indent, node.Tag)
		return
	}

	if node.Content != nil {
		if data, ok := node.Content.([]byte); ok {
			if len(data) <= 64 {
				fmt.Fprintf(b, "> [%d bytes: %s]\n", len(data), hex.EncodeToString(data))
			} else {
				fmt.Fprintf(b, "> [%d bytes: %s...]\n", len(data), hex.EncodeToString(data[:64]))
			}
			return
		}
	}

	b.WriteString(" />\n")
}

// SaveDump writes a call event's raw node to disk as JSON for later analysis.
// Files are saved as: {dir}/{callID}/{eventType}_{timestamp}.json
func SaveDump(dir, callID, eventType string, node *waBinary.Node) error {
	if dir == "" || node == nil {
		return nil
	}

	callDir := filepath.Join(dir, sanitizeFilename(callID))
	if err := os.MkdirAll(callDir, 0755); err != nil {
		return fmt.Errorf("create dump dir: %w", err)
	}

	ts := time.Now().Format("20060102-150405.000")
	filename := filepath.Join(callDir, fmt.Sprintf("%s_%s.json", eventType, ts))

	data, err := json.MarshalIndent(node, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal node: %w", err)
	}

	// Also include the human-readable dump
	readable := DumpNode(node)
	envelope := map[string]interface{}{
		"event_type": eventType,
		"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
		"call_id":    callID,
		"node_json":  json.RawMessage(data),
		"node_text":  readable,
	}

	envelopeData, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	return os.WriteFile(filename, envelopeData, 0644)
}

// dumpBytesAsNode wraps raw bytes in a Node for saving via SaveDump.
func dumpBytesAsNode(tag string, data []byte) *waBinary.Node {
	return &waBinary.Node{
		Tag:     tag,
		Content: data,
	}
}

func sanitizeFilename(s string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_")
	return replacer.Replace(s)
}
