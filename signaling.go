// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeowcalls

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

// RejectCall declines an incoming call by its call ID.
func (cb *CallBridge) RejectCall(ctx context.Context, callID string) error {
	session := cb.GetSession(callID)
	if session == nil {
		return fmt.Errorf("no session found for call %s", callID)
	}

	session.mu.RLock()
	from := session.From
	session.mu.RUnlock()

	if err := cb.client.RejectCall(ctx, from, callID); err != nil {
		return fmt.Errorf("reject call %s: %w", callID, err)
	}

	session.mu.Lock()
	session.State = StateRejected
	session.mu.Unlock()

	cb.log.Infof("Rejected call %s from %s", callID, from)
	return nil
}

// AcceptCall answers an incoming call using the full signaling flow:
// receipt → preaccept → relaylatency → accept.
//
// The caller should see the call transition to "connected" state.
// Without relay binding and SRTP (Phase 3), no audio will flow.
func (cb *CallBridge) AcceptCall(ctx context.Context, callID string) error {
	session := cb.GetSession(callID)
	if session == nil {
		return fmt.Errorf("no session found for call %s", callID)
	}

	// Step 1: Decrypt the call key (32-byte SRTP master secret)
	callKey, err := cb.DecryptCallOffer(ctx, session)
	if err != nil {
		cb.log.Warnf("Failed to decrypt call key for %s: %v (continuing anyway)", callID, err)
	} else {
		session.mu.Lock()
		session.CallKey = callKey
		session.mu.Unlock()
		cb.log.Infof("Decrypted call key for %s: %d bytes", callID, len(callKey))
	}

	// Step 2: Send receipt (ACK for the offer)
	if err := cb.sendReceipt(ctx, session); err != nil {
		return fmt.Errorf("send receipt: %w", err)
	}

	// Step 3: Send preaccept (audio codec + capability)
	if err := cb.sendPreAccept(ctx, session); err != nil {
		return fmt.Errorf("send preaccept: %w", err)
	}

	// Step 4: Ping relay servers with STUN and send relaylatency
	var stunResults []*STUNResult
	session.mu.RLock()
	offer := session.Offer
	session.mu.RUnlock()

	if offer != nil && offer.Relay != nil {
		cb.log.Infof("Pinging %d relay endpoints with %d tokens...",
			len(offer.Relay.Endpoints), len(offer.Relay.Tokens))
		for id, tok := range offer.Relay.Tokens {
			cb.log.Debugf("  Token %s: %d bytes", id, len(tok))
		}
		stunResults = PingRelaysWithLog(offer.Relay.Endpoints, offer.Relay.Tokens, 3*time.Second, cb.log)
		for _, r := range stunResults {
			cb.log.Infof("STUN relay %s: type=0x%04x size=%d RTT=%v mapped=%s:%d session=%x otherAttrs=%d",
				r.RelayName, r.ResponseType, r.ResponseSize, r.RTT, r.MappedIP, r.MappedPort, r.SessionData, len(r.OtherAttrs))
			for _, a := range r.OtherAttrs {
				cb.log.Infof("  attr 0x%04x: %d bytes = %x", a.Type, len(a.Value), a.Value)
			}
		}
		if len(stunResults) == 0 {
			cb.log.Warnf("All STUN relay pings failed for call %s", callID)
		}
	}

	// Send relaylatency with real STUN RTT data
	if err := cb.sendRelayLatencyFromSTUN(ctx, session, stunResults); err != nil {
		cb.log.Warnf("Failed to send relaylatency for %s: %v (falling back to offer data)", callID, err)
		_ = cb.sendRelayLatency(ctx, session)
	}

	time.Sleep(200 * time.Millisecond)

	// Step 5: Send transport with our mapped IPs
	if err := cb.sendTransport(ctx, session, stunResults); err != nil {
		cb.log.Warnf("Failed to send transport for %s: %v", callID, err)
	}

	time.Sleep(200 * time.Millisecond)

	// Step 6: Send accept (audio + capability + net + encopt + te with mapped addr)
	if err := cb.sendAccept(ctx, session, stunResults); err != nil {
		return fmt.Errorf("send accept: %w", err)
	}

	session.mu.Lock()
	session.State = StateAccepted
	session.AcceptedAt = time.Now()
	session.mu.Unlock()

	cb.log.Infof("Call %s accepted (full flow: receipt→preaccept→relaylatency→accept)", callID)
	return nil
}

func (cb *CallBridge) sendReceipt(ctx context.Context, s *CallSession) error {
	ownID := cb.client.Store.ID.ToNonAD()
	s.mu.RLock()
	from := s.From
	creator := s.Creator
	s.mu.RUnlock()

	err := cb.internals.SendNode(ctx, waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cb.client.GenerateMessageID(), "from": ownID, "to": from.ToNonAD()},
		Content: []waBinary.Node{{
			Tag:   "receipt",
			Attrs: waBinary.Attrs{"call-id": s.CallID, "call-creator": creator.ToNonAD()},
		}},
	})
	if err != nil {
		return err
	}
	cb.log.Infof("Sent receipt for call %s", s.CallID)
	return nil
}

func (cb *CallBridge) sendPreAccept(ctx context.Context, s *CallSession) error {
	ownID := cb.client.Store.ID.ToNonAD()
	s.mu.RLock()
	from := s.From
	creator := s.Creator
	s.mu.RUnlock()

	err := cb.internals.SendNode(ctx, waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cb.client.GenerateMessageID(), "from": ownID, "to": from.ToNonAD()},
		Content: []waBinary.Node{{
			Tag:   "preaccept",
			Attrs: waBinary.Attrs{"call-id": s.CallID, "call-creator": creator.ToNonAD()},
			Content: []waBinary.Node{
				{Tag: "audio", Attrs: waBinary.Attrs{"enc": "opus", "rate": "16000"}},
				{Tag: "audio", Attrs: waBinary.Attrs{"enc": "opus", "rate": "8000"}},
				{Tag: "capability", Attrs: waBinary.Attrs{"ver": "1"}, Content: []byte{1, 4, 247, 11, 206, 3}},
				{Tag: "encopt", Attrs: waBinary.Attrs{"keygen": "2"}},
				{Tag: "net", Attrs: waBinary.Attrs{"medium": "3"}},
			},
		}},
	})
	if err != nil {
		return err
	}
	cb.log.Infof("Sent preaccept for call %s", s.CallID)
	return nil
}

func (cb *CallBridge) sendRelayLatency(ctx context.Context, s *CallSession) error {
	s.mu.RLock()
	from := s.From
	creator := s.Creator
	offer := s.Offer
	s.mu.RUnlock()

	if offer == nil || offer.Relay == nil {
		return fmt.Errorf("no relay info in offer")
	}

	ownID := cb.client.Store.ID.ToNonAD()

	// Deduplicate endpoints by relay name and build te nodes
	seen := make(map[string]bool)
	var teNodes []waBinary.Node
	for _, ep := range offer.Relay.Endpoints {
		if seen[ep.RelayName] || ep.IP == nil || len(ep.IP) < 4 {
			continue
		}
		seen[ep.RelayName] = true

		// Encode IP:port as 6 bytes (IPv4)
		ipPort := make([]byte, 6)
		copy(ipPort[:4], ep.IP.To4())
		binary.BigEndian.PutUint16(ipPort[4:], ep.Port)

		// Latency format: 0x2000000 + actual_ms (observed in captures)
		latency := fmt.Sprintf("%d", 33554432+ep.RTT)

		teNodes = append(teNodes, waBinary.Node{
			Tag:     "te",
			Attrs:   waBinary.Attrs{"latency": latency, "relay_name": ep.RelayName},
			Content: ipPort,
		})
	}

	err := cb.internals.SendNode(ctx, waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cb.client.GenerateMessageID(), "from": ownID, "to": from.ToNonAD()},
		Content: []waBinary.Node{{
			Tag:     "relaylatency",
			Attrs:   waBinary.Attrs{"call-id": s.CallID, "call-creator": creator.ToNonAD()},
			Content: teNodes,
		}},
	})
	if err != nil {
		return err
	}
	cb.log.Infof("Sent relaylatency for call %s (%d relays)", s.CallID, len(teNodes))
	return nil
}

// sendRelayLatencyFromSTUN sends relaylatency with actual STUN RTT measurements.
func (cb *CallBridge) sendRelayLatencyFromSTUN(ctx context.Context, s *CallSession, results []*STUNResult) error {
	if len(results) == 0 {
		return fmt.Errorf("no STUN results")
	}

	ownID := cb.client.Store.ID.ToNonAD()
	s.mu.RLock()
	from := s.From
	creator := s.Creator
	s.mu.RUnlock()

	var teNodes []waBinary.Node
	for _, r := range results {
		if r.MappedIP == nil {
			continue
		}
		// Parse relay addr to get IP:port for the te content
		host, portStr, _ := net.SplitHostPort(r.RelayAddr)
		relayIP := net.ParseIP(host)
		if relayIP == nil {
			continue
		}
		var port uint16
		fmt.Sscanf(portStr, "%d", &port)

		ipPort := make([]byte, 6)
		copy(ipPort[:4], relayIP.To4())
		binary.BigEndian.PutUint16(ipPort[4:], port)

		rttMs := int(r.RTT.Milliseconds())
		latency := fmt.Sprintf("%d", 33554432+rttMs)

		teNodes = append(teNodes, waBinary.Node{
			Tag:     "te",
			Attrs:   waBinary.Attrs{"latency": latency, "relay_name": r.RelayName},
			Content: ipPort,
		})
	}

	if len(teNodes) == 0 {
		return fmt.Errorf("no valid STUN results for relaylatency")
	}

	err := cb.internals.SendNode(ctx, waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cb.client.GenerateMessageID(), "from": ownID, "to": from.ToNonAD()},
		Content: []waBinary.Node{{
			Tag:     "relaylatency",
			Attrs:   waBinary.Attrs{"call-id": s.CallID, "call-creator": creator.ToNonAD()},
			Content: teNodes,
		}},
	})
	if err != nil {
		return err
	}
	cb.log.Infof("Sent relaylatency (STUN) for call %s (%d relays)", s.CallID, len(teNodes))
	return nil
}

// sendTransport sends our transport endpoint information to the caller.
func (cb *CallBridge) sendTransport(ctx context.Context, s *CallSession, stunResults []*STUNResult) error {
	ownID := cb.client.Store.ID.ToNonAD()
	s.mu.RLock()
	from := s.From
	creator := s.Creator
	s.mu.RUnlock()

	teNodes := cb.buildTENodes(stunResults)
	if len(teNodes) == 0 {
		return fmt.Errorf("no te nodes for transport")
	}

	content := append(teNodes, waBinary.Node{
		Tag: "net", Attrs: waBinary.Attrs{"medium": "3"},
	})

	err := cb.internals.SendNode(ctx, waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cb.client.GenerateMessageID(), "from": ownID, "to": from.ToNonAD()},
		Content: []waBinary.Node{{
			Tag:     "transport",
			Attrs:   waBinary.Attrs{"call-id": s.CallID, "call-creator": creator.ToNonAD()},
			Content: content,
		}},
	})
	if err != nil {
		return err
	}
	cb.log.Infof("Sent transport for call %s (%d te nodes)", s.CallID, len(teNodes))
	return nil
}

func (cb *CallBridge) sendAccept(ctx context.Context, s *CallSession, stunResults []*STUNResult) error {
	ownID := cb.client.Store.ID.ToNonAD()
	s.mu.RLock()
	from := s.From
	creator := s.Creator
	s.mu.RUnlock()

	// Build child nodes for accept
	content := []waBinary.Node{
		{Tag: "audio", Attrs: waBinary.Attrs{"enc": "opus", "rate": "16000"}},
		{Tag: "audio", Attrs: waBinary.Attrs{"enc": "opus", "rate": "8000"}},
		{Tag: "net", Attrs: waBinary.Attrs{"medium": "3"}},
		{Tag: "encopt", Attrs: waBinary.Attrs{"keygen": "2"}},
		{Tag: "capability", Attrs: waBinary.Attrs{"ver": "1"}, Content: []byte{1, 4, 247, 11, 206, 3}},
	}

	// Add te nodes with our IPs (required for caller to route media)
	// Prefer STUN-mapped addresses from relay binding
	teNodes := cb.buildTENodes(stunResults)
	content = append(content, teNodes...)

	err := cb.internals.SendNode(ctx, waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cb.client.GenerateMessageID(), "from": ownID, "to": from.ToNonAD()},
		Content: []waBinary.Node{{
			Tag: "accept",
			Attrs: waBinary.Attrs{
				"call-id":      s.CallID,
				"call-creator": creator.ToNonAD(),
			},
			Content: content,
		}},
	})
	if err != nil {
		return err
	}
	cb.log.Infof("Sent accept for call %s (with %d te nodes)", s.CallID, len(teNodes))
	return nil
}

// buildTENodes creates transport endpoint nodes with our IPs.
// Prefers STUN-mapped addresses from relay binding if available.
func (cb *CallBridge) buildTENodes(stunResults []*STUNResult) []waBinary.Node {
	var nodes []waBinary.Node

	// Use STUN-mapped address (server-reflexive) if available
	for _, r := range stunResults {
		if r.MappedIP != nil {
			if ipPort := encodeIPPort(r.MappedIP.String(), r.MappedPort); ipPort != nil {
				nodes = append(nodes, waBinary.Node{
					Tag:     "te",
					Attrs:   waBinary.Attrs{"priority": "2"},
					Content: ipPort,
				})
				break // one reflexive address is enough
			}
		}
	}

	// Fallback: configured public IP
	if len(nodes) == 0 && cb.opts.PublicIP != "" {
		if ipPort := encodeIPPort(cb.opts.PublicIP, 0); ipPort != nil {
			nodes = append(nodes, waBinary.Node{
				Tag:     "te",
				Attrs:   waBinary.Attrs{"priority": "2"},
				Content: ipPort,
			})
		}
	}

	// Local IP (priority 0 = host candidate)
	if cb.opts.LocalIP != "" {
		if ipPort := encodeIPPort(cb.opts.LocalIP, 0); ipPort != nil {
			nodes = append(nodes, waBinary.Node{
				Tag:     "te",
				Attrs:   waBinary.Attrs{"priority": "0"},
				Content: ipPort,
			})
		}
	}

	return nodes
}

// encodeIPPort encodes an IP:port pair as 6 bytes (4 bytes IPv4 + 2 bytes port big-endian).
func encodeIPPort(ip string, port uint16) []byte {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}
	ipv4 := parsed.To4()
	if ipv4 == nil {
		return nil
	}
	buf := make([]byte, 6)
	copy(buf[:4], ipv4)
	binary.BigEndian.PutUint16(buf[4:], port)
	return buf
}

// OfferCall initiates an outgoing call to the specified JID.
// NOTE: Not yet implemented.
func (cb *CallBridge) OfferCall(ctx context.Context, to types.JID) error {
	_ = ctx
	_ = to
	return ErrNotImplemented
}
