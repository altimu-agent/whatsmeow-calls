// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeowcalls

import (
	"context"
	"encoding/hex"
	"fmt"
)

// DecryptCallOffer decrypts the Signal-encrypted payload from a call offer.
// The decrypted content contains SRTP key material for the call's media stream.
//
// This consumes a Signal prekey (for PreKey messages), so it should only be
// called once per call. The result is stored in session.DecryptedPayload.
func (cb *CallBridge) DecryptCallOffer(ctx context.Context, session *CallSession) ([]byte, error) {
	if session == nil {
		return nil, fmt.Errorf("nil session")
	}

	session.mu.RLock()
	offer := session.Offer
	creator := session.Creator
	startedAt := session.StartedAt
	existing := session.DecryptedPayload
	session.mu.RUnlock()

	// Don't decrypt twice
	if existing != nil {
		return existing, nil
	}

	offerNode := session.OfferNode
	if offer == nil || offer.EncNode == nil || offerNode == nil {
		return nil, fmt.Errorf("no enc node in offer for call %s", session.CallID)
	}

	// whatsmeow convention: "pkmsg" = PreKey message, "msg" = normal Signal message
	isPreKey := offer.EncType == "pkmsg"

	// Get the enc node from the raw offer node (preserves original []byte content)
	encNode := offer.EncNode
	for _, child := range offerNode.GetChildren() {
		if child.Tag == "enc" {
			encNode = &child
			break
		}
	}

	cb.log.Infof("Decrypting call offer %s (type=%s, isPreKey=%v, from=%s)",
		session.CallID, offer.EncType, isPreKey, creator)

	plaintext, _, err := cb.internals.DecryptDM(ctx, encNode, creator, isPreKey, startedAt)
	if err != nil {
		return nil, fmt.Errorf("decrypt call offer: %w", err)
	}

	cb.log.Infof("Decrypted call offer %s: %d bytes", session.CallID, len(plaintext))
	cb.log.Debugf("Decrypted payload hex: %s", hex.EncodeToString(plaintext))

	// Store in session
	session.mu.Lock()
	session.DecryptedPayload = plaintext
	session.mu.Unlock()

	// Dump the decrypted content for analysis
	if cb.opts.LogDir != "" {
		dumpNode := dumpBytesAsNode("decrypted_offer", plaintext)
		_ = SaveDump(cb.opts.LogDir, session.CallID, "decrypted_offer", dumpNode)
	}

	return plaintext, nil
}
