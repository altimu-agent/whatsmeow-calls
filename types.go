// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeowcalls

import (
	"context"
	"errors"
	"sync"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

var ErrNotImplemented = errors.New("whatsmeow-calls: not implemented yet — waiting for protocol analysis")

// CallState represents the current state of a call session.
type CallState int

const (
	StateRinging    CallState = iota // Offer received, not yet answered
	StatePreAccept                   // Pre-accept sent/received
	StateAccepted                    // Call accepted
	StateRejected                    // Call rejected by either party
	StateTerminated                  // Call ended
)

func (s CallState) String() string {
	switch s {
	case StateRinging:
		return "ringing"
	case StatePreAccept:
		return "pre-accept"
	case StateAccepted:
		return "accepted"
	case StateRejected:
		return "rejected"
	case StateTerminated:
		return "terminated"
	default:
		return "unknown"
	}
}

// CallSession tracks the state of a single call throughout its lifecycle.
type CallSession struct {
	mu sync.RWMutex

	CallID     string
	From       types.JID
	Creator    types.JID
	CreatorAlt types.JID
	GroupJID   types.JID
	State      CallState

	// Remote party info
	Platform string
	Version  string

	// Media type (from offer_notice)
	Media string // "audio" or "video"

	// Timestamps
	StartedAt    time.Time
	AcceptedAt   time.Time
	TerminatedAt time.Time

	// Termination reason (from CallTerminate)
	TerminateReason string

	// Raw signaling nodes — essential for protocol reverse-engineering
	OfferNode     *waBinary.Node
	TransportNode *waBinary.Node
	AcceptNode    *waBinary.Node
	AllNodes      []TimestampedNode
}

// TimestampedNode is a captured binary node with metadata.
type TimestampedNode struct {
	EventType string        `json:"event_type"`
	Timestamp time.Time     `json:"timestamp"`
	Node      *waBinary.Node `json:"node"`
}

// IncomingCall wraps a CallSession with actions the user can take.
type IncomingCall struct {
	*CallSession
	bridge *CallBridge
	ctx    context.Context
}

// Reject declines the incoming call.
func (ic *IncomingCall) Reject(ctx context.Context) error {
	return ic.bridge.RejectCall(ctx, ic.CallID)
}

// Accept answers the incoming call.
// NOTE: Not yet implemented — requires protocol analysis from call dumps.
func (ic *IncomingCall) Accept(ctx context.Context) error {
	return ic.bridge.AcceptCall(ctx, ic.CallID)
}

// Options configures the CallBridge behavior.
type Options struct {
	// LogDir enables dumping raw call nodes to disk for analysis.
	// Each call gets a subdirectory: {LogDir}/{callID}/
	// Leave empty to disable dumping.
	LogDir string

	// AllowedNumbers is a whitelist of phone numbers (without "+" prefix)
	// that are permitted to call. Calls from numbers not in this list are
	// automatically rejected. If empty, all calls are allowed through.
	AllowedNumbers []string

	// OnIncomingCall is invoked when a new call offer is received.
	// The callback receives an IncomingCall that can be used to accept or reject.
	OnIncomingCall func(call *IncomingCall)

	// OnCallRejected is invoked when a call is auto-rejected (e.g. not whitelisted).
	OnCallRejected func(from types.JID, callID, reason string)

	// OnCallTerminated is invoked when a call ends (by either party).
	OnCallTerminated func(session *CallSession)

	// Logger for call bridge events. If nil, a no-op logger is used.
	Logger waLog.Logger
}
