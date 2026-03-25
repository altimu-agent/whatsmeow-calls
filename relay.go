// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeowcalls

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	waBinary "go.mau.fi/whatsmeow/binary"
)

// ParseRelay extracts relay server info from a <relay> node.
func ParseRelay(node *waBinary.Node) (*RelayInfo, error) {
	if node == nil {
		return nil, fmt.Errorf("nil relay node")
	}

	ag := node.AttrGetter()
	relay := &RelayInfo{
		UUID:       ag.String("uuid"),
		PeerPID:    ag.String("peer_pid"),
		SelfPID:    ag.String("self_pid"),
		Tokens:     make(map[string][]byte),
		AuthTokens: make(map[string][]byte),
	}

	for _, child := range node.GetChildren() {
		switch child.Tag {
		case "token":
			id := child.AttrGetter().String("id")
			if data := decodeNodeContent(child); data != nil {
				relay.Tokens[id] = data
			}

		case "auth_token":
			id := child.AttrGetter().String("id")
			if data := decodeNodeContent(child); data != nil {
				relay.AuthTokens[id] = data
			}

		case "key":
			relay.Key = decodeDoubleBase64(child)

		case "hbh_key":
			relay.HBHKey = decodeDoubleBase64(child)

		case "te2":
			ep := parseTE2(child)
			if ep != nil {
				relay.Endpoints = append(relay.Endpoints, *ep)
			}
		}
	}

	return relay, nil
}

// parseTE2 decodes a <te2> node into a RelayEndpoint.
// Content is either 6 bytes (IPv4 + port) or 18 bytes (IPv6 + port).
func parseTE2(node waBinary.Node) *RelayEndpoint {
	data := decodeNodeContent(node)
	if data == nil {
		return nil
	}

	ag := node.AttrGetter()
	ep := &RelayEndpoint{
		RelayID:     ag.String("relay_id"),
		RelayName:   ag.String("relay_name"),
		Protocol:    ag.String("protocol"),
		TokenID:     ag.String("token_id"),
		AuthTokenID: ag.String("auth_token_id"),
	}

	if rttStr := ag.String("c2r_rtt"); rttStr != "" {
		ep.RTT, _ = strconv.Atoi(rttStr)
	}

	switch len(data) {
	case 6: // IPv4 (4 bytes) + port (2 bytes big-endian)
		ep.IP = net.IP(data[:4])
		ep.Port = binary.BigEndian.Uint16(data[4:6])
	case 18: // IPv6 (16 bytes) + port (2 bytes big-endian)
		ep.IP = net.IP(data[:16])
		ep.Port = binary.BigEndian.Uint16(data[16:18])
	default:
		return nil
	}

	return ep
}

// decodeNodeContent extracts []byte from a node's content, handling base64 if needed.
func decodeNodeContent(node waBinary.Node) []byte {
	if node.Content == nil {
		return nil
	}
	switch v := node.Content.(type) {
	case []byte:
		return v
	case string:
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return []byte(v)
		}
		return decoded
	default:
		return nil
	}
}

// decodeDoubleBase64 handles keys that are base64-encoded ASCII base64 strings.
// Outer decode gives ASCII text that is itself a base64 string → decode again.
func decodeDoubleBase64(node waBinary.Node) []byte {
	data := decodeNodeContent(node)
	if data == nil {
		return nil
	}
	// First decode gave us bytes — check if they're ASCII (another base64 string)
	inner, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		// Try RawStdEncoding (no padding)
		inner, err = base64.RawStdEncoding.DecodeString(string(data))
		if err != nil {
			return data // not double-encoded, return as-is
		}
	}
	return inner
}
