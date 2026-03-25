// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeowcalls

import (
	"context"
	"fmt"

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
// NOTE: This is not yet implemented. WhatsApp call acceptance requires
// sending specific signaling nodes whose format must be reverse-engineered
// from captured call dumps. Use the sniffer example to capture call data,
// then contribute the protocol details to implement this method.
//
// The implementation will use DangerousInternals().SendNode() to send
// the accept and transport nodes.
func (cb *CallBridge) AcceptCall(ctx context.Context, callID string) error {
	_ = ctx
	_ = callID
	return ErrNotImplemented
}

// OfferCall initiates an outgoing call to the specified JID.
//
// NOTE: This is not yet implemented. See AcceptCall for details.
func (cb *CallBridge) OfferCall(ctx context.Context, to types.JID) error {
	_ = ctx
	_ = to
	return ErrNotImplemented
}
