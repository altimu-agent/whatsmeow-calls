// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeowcalls

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	waLog "go.mau.fi/whatsmeow/util/log"
)

// STUN constants
const (
	stunMagicCookie = 0x2112A442

	// STUN message types
	stunBindingRequest = 0x0001 // STUN Binding Request

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
	RelayName    string
	RelayAddr    string // IP:port we sent to
	RTT          time.Duration
	ResponseType uint16 // STUN response message type
	ResponseSize int    // total response bytes
	MappedIP     net.IP // Our public IP as seen by the relay (XOR-MAPPED-ADDR)
	MappedPort   uint16
	SessionData  []byte          // 0x4002 attribute from response
	OtherAttrs   []stunAttribute // any other attributes in the response
}

// PingRelay sends a STUN Binding request with a WhatsApp token to a relay server.
// If hmacKey is provided, MESSAGE-INTEGRITY (HMAC-SHA1) is appended.
// Returns the result including our mapped address and RTT.
func PingRelay(endpoint RelayEndpoint, token, hmacKey []byte, timeout time.Duration) (*STUNResult, error) {
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

	// Build STUN Binding request with 0x4000 token
	txID := make([]byte, 12)
	rand.Read(txID)

	reqAttrs := []stunAttribute{
		{Type: stunAttrWAToken, Value: token},
	}
	msg := buildSTUNMessage(stunBindingRequest, txID, reqAttrs)

	// Add MESSAGE-INTEGRITY if we have a key
	if len(hmacKey) > 0 {
		msg = appendMessageIntegrity(msg, hmacKey)
	}

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
	respType := binary.BigEndian.Uint16(buf[0:2])
	result := &STUNResult{
		RelayName:    endpoint.RelayName,
		RelayAddr:    addr,
		RTT:          rtt,
		ResponseType: respType,
		ResponseSize: n,
	}

	respAttrs, err := parseSTUNResponse(buf[:n], txID)
	if err != nil {
		return result, fmt.Errorf("parse response from %s: %w", endpoint.RelayName, err)
	}

	for _, attr := range respAttrs {
		switch attr.Type {
		case stunAttrXORMappedAddr:
			result.MappedIP, result.MappedPort = decodeXORMappedAddr(attr.Value, txID)
		case stunAttrWASession:
			result.SessionData = attr.Value
		default:
			result.OtherAttrs = append(result.OtherAttrs, attr)
		}
	}

	return result, nil
}

// PingRelays sends STUN Allocate requests to multiple relay endpoints in parallel.
func PingRelays(endpoints []RelayEndpoint, tokens, authTokens map[string][]byte, relayKey []byte, timeout time.Duration) []*STUNResult {
	return PingRelaysWithLog(endpoints, tokens, authTokens, relayKey, timeout, nil)
}

// PingRelaysWithLog is like PingRelays but logs errors via the provided logger.
func PingRelaysWithLog(endpoints []RelayEndpoint, tokens, authTokens map[string][]byte, relayKey []byte, timeout time.Duration, log waLog.Logger) []*STUNResult {
	type result struct {
		res *STUNResult
		err error
		ep  RelayEndpoint
	}

	ch := make(chan result, len(endpoints))

	// Deduplicate by relay name — only ping one endpoint per relay
	seen := make(map[string]bool)
	launched := 0
	for _, ep := range endpoints {
		if seen[ep.RelayName] || ep.IP == nil {
			continue
		}
		seen[ep.RelayName] = true

		// Use regular token for STUN binding (auth_token causes timeout)
		token := tokens[ep.TokenID]
		if token == nil {
			if log != nil {
				log.Warnf("No token for relay %s (auth_token_id=%s, token_id=%s)", ep.RelayName, ep.AuthTokenID, ep.TokenID)
			}
			continue
		}

		launched++
		go func(ep RelayEndpoint, tok []byte) {
			res, err := PingRelay(ep, tok, relayKey, timeout)
			ch <- result{res, err, ep}
		}(ep, token)
	}

	var results []*STUNResult
	for i := 0; i < launched; i++ {
		r := <-ch
		if r.err != nil {
			if log != nil {
				log.Warnf("STUN ping failed for %s (%s:%d): %v", r.ep.RelayName, r.ep.IP, r.ep.Port, r.err)
			}
		}
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

// appendMessageIntegrity adds a MESSAGE-INTEGRITY attribute (HMAC-SHA1) to a STUN message.
// Per RFC 5389: HMAC is computed over the message up to (but not including) the
// MESSAGE-INTEGRITY attribute itself, with the length field adjusted to include it.
func appendMessageIntegrity(msg []byte, key []byte) []byte {
	const miAttrType = 0x0008
	const miAttrLen = 20 // SHA1 = 20 bytes
	const miTotalLen = 4 + miAttrLen // type(2) + length(2) + value(20)

	// Update the STUN header length to include MESSAGE-INTEGRITY
	currentBodyLen := binary.BigEndian.Uint16(msg[2:4])
	binary.BigEndian.PutUint16(msg[2:4], currentBodyLen+miTotalLen)

	// Compute HMAC-SHA1 over the message with the updated length
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	digest := mac.Sum(nil)

	// Append the attribute
	attr := make([]byte, miTotalLen)
	binary.BigEndian.PutUint16(attr[0:2], miAttrType)
	binary.BigEndian.PutUint16(attr[2:4], miAttrLen)
	copy(attr[4:], digest)

	return append(msg, attr...)
}
