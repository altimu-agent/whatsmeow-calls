// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeowcalls

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// STUN constants
const (
	stunMagicCookie = 0x2112A442

	// Standard STUN message types
	stunAllocateRequest = 0x0003 // TURN Allocate

	// WhatsApp custom STUN attributes
	stunAttrWAToken   = 0x4000 // Relay authentication token
	stunAttrWASession = 0x4002 // Session/routing identifier (in response)

	// Standard STUN attributes
	stunAttrXORMappedAddr = 0x0020

	// WhatsApp custom message type for teardown
	stunMsgTeardown = 0x0800
)

// STUNResult holds the result of a relay STUN binding.
type STUNResult struct {
	RelayName   string
	RelayAddr   string // IP:port we sent to
	RTT         time.Duration
	MappedIP    net.IP // Our public IP as seen by the relay (XOR-MAPPED-ADDR)
	MappedPort  uint16
	SessionData []byte // 0x4002 attribute from response
}

// PingRelay sends a STUN Allocate request with a WhatsApp token to a relay server.
// Returns the result including our mapped address and RTT.
func PingRelay(endpoint RelayEndpoint, token []byte, timeout time.Duration) (*STUNResult, error) {
	if token == nil {
		return nil, fmt.Errorf("nil token for relay %s", endpoint.RelayName)
	}

	addr := net.JoinHostPort(endpoint.IP.String(), fmt.Sprintf("%d", endpoint.Port))
	conn, err := net.DialTimeout("udp4", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial relay %s (%s): %w", endpoint.RelayName, addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Build STUN Allocate request with 0x4000 token
	txID := make([]byte, 12)
	rand.Read(txID)

	msg := buildSTUNMessage(stunAllocateRequest, txID, []stunAttribute{
		{Type: stunAttrWAToken, Value: token},
	})

	start := time.Now()
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("write to relay %s: %w", endpoint.RelayName, err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read from relay %s: %w", endpoint.RelayName, err)
	}
	rtt := time.Since(start)

	// Parse response
	result := &STUNResult{
		RelayName: endpoint.RelayName,
		RelayAddr: addr,
		RTT:       rtt,
	}

	attrs, err := parseSTUNResponse(buf[:n], txID)
	if err != nil {
		return result, fmt.Errorf("parse response from %s: %w", endpoint.RelayName, err)
	}

	for _, attr := range attrs {
		switch attr.Type {
		case stunAttrXORMappedAddr:
			result.MappedIP, result.MappedPort = decodeXORMappedAddr(attr.Value, txID)
		case stunAttrWASession:
			result.SessionData = attr.Value
		}
	}

	return result, nil
}

// PingRelays sends STUN Allocate requests to multiple relay endpoints in parallel.
func PingRelays(endpoints []RelayEndpoint, tokens map[string][]byte, timeout time.Duration) []*STUNResult {
	type result struct {
		res *STUNResult
		err error
	}

	ch := make(chan result, len(endpoints))

	// Deduplicate by relay name — only ping one endpoint per relay
	seen := make(map[string]bool)
	for _, ep := range endpoints {
		if seen[ep.RelayName] || ep.IP == nil {
			continue
		}
		seen[ep.RelayName] = true

		token := tokens[ep.TokenID]
		if token == nil {
			continue
		}

		go func(ep RelayEndpoint, tok []byte) {
			res, err := PingRelay(ep, tok, timeout)
			ch <- result{res, err}
		}(ep, token)
	}

	var results []*STUNResult
	for range seen {
		r := <-ch
		if r.res != nil {
			results = append(results, r.res)
		}
	}
	return results
}

// stunAttribute is a STUN TLV attribute.
type stunAttribute struct {
	Type  uint16
	Value []byte
}

// buildSTUNMessage constructs a STUN message with the given type, transaction ID, and attributes.
func buildSTUNMessage(msgType uint16, txID []byte, attrs []stunAttribute) []byte {
	// Calculate body length
	bodyLen := 0
	for _, attr := range attrs {
		bodyLen += 4 + len(attr.Value)
		// Pad to 4-byte boundary
		if pad := len(attr.Value) % 4; pad != 0 {
			bodyLen += 4 - pad
		}
	}

	msg := make([]byte, 20+bodyLen)

	// Header: type (2) + length (2) + magic cookie (4) + txID (12)
	binary.BigEndian.PutUint16(msg[0:2], msgType)
	binary.BigEndian.PutUint16(msg[2:4], uint16(bodyLen))
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], txID)

	// Attributes
	offset := 20
	for _, attr := range attrs {
		binary.BigEndian.PutUint16(msg[offset:offset+2], attr.Type)
		binary.BigEndian.PutUint16(msg[offset+2:offset+4], uint16(len(attr.Value)))
		copy(msg[offset+4:], attr.Value)
		offset += 4 + len(attr.Value)
		// Pad
		if pad := len(attr.Value) % 4; pad != 0 {
			offset += 4 - pad
		}
	}

	return msg
}

// parseSTUNResponse validates a STUN response and extracts its attributes.
func parseSTUNResponse(data []byte, expectedTxID []byte) ([]stunAttribute, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("response too short: %d bytes", len(data))
	}

	// Check magic cookie
	cookie := binary.BigEndian.Uint32(data[4:8])
	if cookie != stunMagicCookie {
		return nil, fmt.Errorf("invalid magic cookie: 0x%08x", cookie)
	}

	// Check transaction ID matches
	for i := 0; i < 12; i++ {
		if data[8+i] != expectedTxID[i] {
			return nil, fmt.Errorf("transaction ID mismatch")
		}
	}

	bodyLen := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < 20+bodyLen {
		return nil, fmt.Errorf("body truncated: have %d, need %d", len(data)-20, bodyLen)
	}

	// Parse attributes
	var attrs []stunAttribute
	offset := 20
	for offset+4 <= 20+bodyLen {
		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if offset+4+attrLen > len(data) {
			break
		}
		attrs = append(attrs, stunAttribute{
			Type:  attrType,
			Value: data[offset+4 : offset+4+attrLen],
		})
		offset += 4 + attrLen
		// Skip padding
		if pad := attrLen % 4; pad != 0 {
			offset += 4 - pad
		}
	}

	return attrs, nil
}

// decodeXORMappedAddr decodes a STUN XOR-MAPPED-ADDRESS attribute.
func decodeXORMappedAddr(data []byte, txID []byte) (net.IP, uint16) {
	if len(data) < 8 {
		return nil, 0
	}
	// data[0] = reserved, data[1] = family (0x01=IPv4, 0x02=IPv6)
	family := data[1]
	xPort := binary.BigEndian.Uint16(data[2:4])
	port := xPort ^ uint16(stunMagicCookie>>16)

	if family == 0x01 && len(data) >= 8 {
		// IPv4: XOR with magic cookie
		ip := make(net.IP, 4)
		cookieBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(cookieBytes, stunMagicCookie)
		for i := 0; i < 4; i++ {
			ip[i] = data[4+i] ^ cookieBytes[i]
		}
		return ip, port
	}

	return nil, 0
}
