// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeowcalls

import (
	"context"
	"fmt"

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

// AcceptCall answers an incoming call.
//
// This sends an accept signaling node to the caller. The first iteration
// sends a minimal accept (modeled after RejectCall's node structure).
// The caller should briefly see "connected" even without media flowing.
//
// Phase 2: basic signaling accept.
// Phase 3: will add relay binding + SRTP media.
func (cb *CallBridge) AcceptCall(ctx context.Context, callID string) error {
	session := cb.GetSession(callID)
	if session == nil {
		return fmt.Errorf("no session found for call %s", callID)
	}

	session.mu.RLock()
	from := session.From
	creator := session.Creator
	offer := session.Offer
	session.mu.RUnlock()

	// Step 1: Decrypt the Signal payload (SRTP key material)
	plaintext, err := cb.DecryptCallOffer(ctx, session)
	if err != nil {
		cb.log.Warnf("Failed to decrypt call offer %s: %v (continuing with accept anyway)", callID, err)
	} else {
		cb.log.Infof("Decrypted call offer %s: %d bytes of key material", callID, len(plaintext))
	}

	// Step 2: Send accept node
	ownID := cb.client.Store.ID.ToNonAD()

	// Build accept content — include relay selection if we have offer data
	var acceptContent []waBinary.Node
	if offer != nil && offer.Relay != nil && len(offer.Relay.Endpoints) > 0 {
		// Select the lowest-RTT relay
		best := offer.Relay.Endpoints[0]
		for _, ep := range offer.Relay.Endpoints[1:] {
			if ep.RTT < best.RTT {
				best = ep
			}
		}
		cb.log.Infof("Selected relay %s (%s:%d, RTT=%dms) for call %s",
			best.RelayName, best.IP, best.Port, best.RTT, callID)
	}

	acceptNode := waBinary.Node{
		Tag: "call",
		Attrs: waBinary.Attrs{
			"id":   cb.client.GenerateMessageID(),
			"from": ownID,
			"to":   from.ToNonAD(),
		},
		Content: []waBinary.Node{{
			Tag: "accept",
			Attrs: waBinary.Attrs{
				"call-id":      callID,
				"call-creator": creator.ToNonAD(),
				"count":        "0",
			},
			Content: acceptContent,
		}},
	}

	cb.log.Infof("Sending accept for call %s to %s", callID, from)

	if err := cb.internals.SendNode(ctx, acceptNode); err != nil {
		return fmt.Errorf("send accept for call %s: %w", callID, err)
	}

	session.mu.Lock()
	session.State = StateAccepted
	session.mu.Unlock()

	cb.log.Infof("Accepted call %s", callID)
	return nil
}

// OfferCall initiates an outgoing call to the specified JID.
//
// NOTE: Not yet implemented. Requires building a full offer node with
// relay allocation, Signal encryption, and codec negotiation.
func (cb *CallBridge) OfferCall(ctx context.Context, to types.JID) error {
	_ = ctx
	_ = to
	return ErrNotImplemented
}
