// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package whatsmeowcalls provides call signaling support for whatsmeow.
//
// It captures, logs, and manages WhatsApp call events (offers, accepts,
// transports, terminations) with the goal of enabling full VoIP bridging.
//
// Phase 1 (current): Event capture and protocol reverse-engineering via node dumps.
// Phase 2 (planned): Call accept/initiate using DangerousInternals().SendNode().
// Phase 3 (planned): Audio media bridge (SRTP/WebRTC).
// Phase 4 (planned): Real-time AI voice agent integration.
package whatsmeowcalls

import (
	"context"
	"strings"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// CallBridge manages WhatsApp call signaling on top of a whatsmeow client.
type CallBridge struct {
	client    *whatsmeow.Client
	internals *whatsmeow.DangerousInternalClient
	opts      Options
	allowed   map[string]bool // phone number -> true
	sessions  map[string]*CallSession
	mu        sync.RWMutex
	log       waLog.Logger
}

// NewCallBridge creates a new CallBridge attached to a whatsmeow client.
func NewCallBridge(client *whatsmeow.Client, opts Options) *CallBridge {
	log := opts.Logger
	if log == nil {
		log = waLog.Noop
	}
	allowed := make(map[string]bool, len(opts.AllowedNumbers))
	for _, num := range opts.AllowedNumbers {
		allowed[strings.TrimPrefix(num, "+")] = true
	}
	return &CallBridge{
		client:    client,
		internals: client.DangerousInternals(),
		opts:      opts,
		allowed:   allowed,
		sessions:  make(map[string]*CallSession),
		log:       log,
	}
}

// HandleEvent routes a whatsmeow event to the appropriate call handler.
// Register this with client.AddEventHandler(bridge.HandleEvent).
func (cb *CallBridge) HandleEvent(evt interface{}) {
	switch v := evt.(type) {
	case *events.CallOffer:
		cb.handleOffer(v)
	case *events.CallOfferNotice:
		cb.handleOfferNotice(v)
	case *events.CallAccept:
		cb.handleAccept(v)
	case *events.CallPreAccept:
		cb.handlePreAccept(v)
	case *events.CallTransport:
		cb.handleTransport(v)
	case *events.CallRelayLatency:
		cb.handleRelayLatency(v)
	case *events.CallTerminate:
		cb.handleTerminate(v)
	case *events.CallReject:
		cb.handleReject(v)
	case *events.UnknownCallEvent:
		cb.handleUnknown(v)
	}
}

// GetSession returns the call session for a given call ID, or nil.
func (cb *CallBridge) GetSession(callID string) *CallSession {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.sessions[callID]
}

// ActiveSessions returns all call sessions that haven't terminated.
func (cb *CallBridge) ActiveSessions() []*CallSession {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	var active []*CallSession
	for _, s := range cb.sessions {
		s.mu.RLock()
		state := s.State
		s.mu.RUnlock()
		if state != StateTerminated && state != StateRejected {
			active = append(active, s)
		}
	}
	return active
}

func (cb *CallBridge) getOrCreateSession(callID string) *CallSession {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if s, ok := cb.sessions[callID]; ok {
		return s
	}
	s := &CallSession{
		CallID:    callID,
		State:     StateRinging,
		StartedAt: time.Now(),
	}
	cb.sessions[callID] = s
	return s
}

// isAllowed checks if a JID's phone number is in the whitelist.
// If the whitelist is empty, all numbers are allowed.
func (cb *CallBridge) isAllowed(jid types.JID) bool {
	if len(cb.allowed) == 0 {
		return true
	}
	phone := jid.User
	if cb.opts.ResolvePhone != nil {
		if resolved := cb.opts.ResolvePhone(jid); resolved != "" {
			phone = resolved
		}
	}
	return cb.allowed[phone]
}

func (cb *CallBridge) recordNode(session *CallSession, eventType string, node *waBinary.Node) {
	session.mu.Lock()
	session.AllNodes = append(session.AllNodes, TimestampedNode{
		EventType: eventType,
		Timestamp: time.Now(),
		Node:      node,
	})
	session.mu.Unlock()

	cb.log.Debugf("Call %s: %s node captured (%d total)", session.CallID, eventType, len(session.AllNodes))

	if err := SaveDump(cb.opts.LogDir, session.CallID, eventType, node); err != nil {
		cb.log.Warnf("Failed to save %s dump for call %s: %v", eventType, session.CallID, err)
	}
}

func (cb *CallBridge) handleOffer(evt *events.CallOffer) {
	// Always dump the offer node first (even if we'll reject)
	_ = SaveDump(cb.opts.LogDir, evt.CallID, "offer", evt.Data)

	if !cb.isAllowed(evt.From) {
		cb.log.Infof("Rejecting call from non-whitelisted number %s (id=%s)", evt.From, evt.CallID)
		_ = cb.client.RejectCall(context.Background(), evt.From, evt.CallID)
		if cb.opts.OnCallRejected != nil {
			cb.opts.OnCallRejected(evt.From, evt.CallID, "not_whitelisted")
		}
		return
	}

	session := cb.getOrCreateSession(evt.CallID)
	session.mu.Lock()
	session.From = evt.From
	session.Creator = evt.CallCreator
	session.CreatorAlt = evt.CallCreatorAlt
	session.GroupJID = evt.GroupJID
	session.Platform = evt.RemotePlatform
	session.Version = evt.RemoteVersion
	session.OfferNode = evt.Data
	session.mu.Unlock()

	cb.log.Infof("Incoming call from %s (id=%s, platform=%s, version=%s)",
		evt.From, evt.CallID, evt.RemotePlatform, evt.RemoteVersion)

	cb.recordNode(session, "offer", evt.Data)

	if cb.opts.OnIncomingCall != nil {
		cb.opts.OnIncomingCall(&IncomingCall{
			CallSession: session,
			bridge:      cb,
			ctx:         context.Background(),
		})
	}
}

func (cb *CallBridge) handleOfferNotice(evt *events.CallOfferNotice) {
	_ = SaveDump(cb.opts.LogDir, evt.CallID, "offer_notice", evt.Data)

	if !cb.isAllowed(evt.From) {
		cb.log.Infof("Rejecting group call from non-whitelisted number %s (id=%s)", evt.From, evt.CallID)
		_ = cb.client.RejectCall(context.Background(), evt.From, evt.CallID)
		if cb.opts.OnCallRejected != nil {
			cb.opts.OnCallRejected(evt.From, evt.CallID, "not_whitelisted")
		}
		return
	}

	session := cb.getOrCreateSession(evt.CallID)
	session.mu.Lock()
	session.From = evt.From
	session.Creator = evt.CallCreator
	session.CreatorAlt = evt.CallCreatorAlt
	session.GroupJID = evt.GroupJID
	session.Media = evt.Media
	session.mu.Unlock()

	cb.log.Infof("Group call notice from %s (id=%s, media=%s, type=%s)",
		evt.From, evt.CallID, evt.Media, evt.Type)

	cb.recordNode(session, "offer_notice", evt.Data)

	if cb.opts.OnIncomingCall != nil {
		cb.opts.OnIncomingCall(&IncomingCall{
			CallSession: session,
			bridge:      cb,
			ctx:         context.Background(),
		})
	}
}

func (cb *CallBridge) handleAccept(evt *events.CallAccept) {
	session := cb.getOrCreateSession(evt.CallID)
	session.mu.Lock()
	session.State = StateAccepted
	session.AcceptedAt = time.Now()
	session.AcceptNode = evt.Data
	session.mu.Unlock()

	cb.log.Infof("Call %s accepted (platform=%s)", evt.CallID, evt.RemotePlatform)
	cb.recordNode(session, "accept", evt.Data)
}

func (cb *CallBridge) handlePreAccept(evt *events.CallPreAccept) {
	session := cb.getOrCreateSession(evt.CallID)
	session.mu.Lock()
	session.State = StatePreAccept
	session.mu.Unlock()

	cb.log.Debugf("Call %s pre-accept (platform=%s)", evt.CallID, evt.RemotePlatform)
	cb.recordNode(session, "preaccept", evt.Data)
}

func (cb *CallBridge) handleTransport(evt *events.CallTransport) {
	session := cb.getOrCreateSession(evt.CallID)
	session.mu.Lock()
	session.TransportNode = evt.Data
	session.mu.Unlock()

	cb.log.Debugf("Call %s transport update (platform=%s)", evt.CallID, evt.RemotePlatform)
	cb.recordNode(session, "transport", evt.Data)
}

func (cb *CallBridge) handleRelayLatency(evt *events.CallRelayLatency) {
	session := cb.getOrCreateSession(evt.CallID)
	cb.log.Debugf("Call %s relay latency", evt.CallID)
	cb.recordNode(session, "relaylatency", evt.Data)
}

func (cb *CallBridge) handleTerminate(evt *events.CallTerminate) {
	session := cb.getOrCreateSession(evt.CallID)
	session.mu.Lock()
	session.State = StateTerminated
	session.TerminatedAt = time.Now()
	session.TerminateReason = evt.Reason
	session.mu.Unlock()

	cb.log.Infof("Call %s terminated (reason=%s)", evt.CallID, evt.Reason)
	cb.recordNode(session, "terminate", evt.Data)

	if cb.opts.OnCallTerminated != nil {
		cb.opts.OnCallTerminated(session)
	}
}

func (cb *CallBridge) handleReject(evt *events.CallReject) {
	session := cb.getOrCreateSession(evt.CallID)
	session.mu.Lock()
	session.State = StateRejected
	session.TerminatedAt = time.Now()
	session.mu.Unlock()

	cb.log.Infof("Call %s rejected", evt.CallID)
	cb.recordNode(session, "reject", evt.Data)

	if cb.opts.OnCallTerminated != nil {
		cb.opts.OnCallTerminated(session)
	}
}

func (cb *CallBridge) handleUnknown(evt *events.UnknownCallEvent) {
	cb.log.Warnf("Unknown call event: %s", DumpNode(evt.Node))
	if cb.opts.LogDir != "" {
		_ = SaveDump(cb.opts.LogDir, "unknown", "unknown", evt.Node)
	}
}
