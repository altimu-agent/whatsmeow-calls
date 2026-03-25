# whatsmeow-calls

Call signaling library for [whatsmeow](https://github.com/tulir/whatsmeow) — capture, analyze, and handle WhatsApp calls programmatically.

## Status

**Phase 1: Protocol Discovery** — This library currently captures and logs all WhatsApp call signaling events for reverse-engineering. Call acceptance and initiation are planned for Phase 2.

## Features

- Capture all call signaling events (offer, accept, transport, terminate, etc.)
- Dump raw binary nodes to disk as JSON for protocol analysis
- Human-readable node visualization
- Track call sessions with full lifecycle management
- Reject incoming calls
- Clean callback API for integrating into your own whatsmeow project

## Installation

```bash
go get github.com/altimu-agent/whatsmeow-calls
```

## Quick Start

```go
package main

import (
    "fmt"
    "go.mau.fi/whatsmeow"
    calls "github.com/altimu-agent/whatsmeow-calls"
)

func setupCallBridge(client *whatsmeow.Client) {
    bridge := calls.NewCallBridge(client, calls.Options{
        LogDir: "./call-dumps",
        OnIncomingCall: func(call *calls.IncomingCall) {
            fmt.Printf("Call from %s (id: %s)\n", call.From, call.CallID)
            // call.Reject(ctx)  // to decline
            // call.Accept(ctx)  // Phase 2 — not yet implemented
        },
        OnCallTerminated: func(session *calls.CallSession) {
            fmt.Printf("Call %s ended: %s\n", session.CallID, session.TerminateReason)
        },
    })
    client.AddEventHandler(bridge.HandleEvent)
}
```

## Sniffer Example

A standalone tool to connect to WhatsApp and capture call signaling:

```bash
cd examples/sniffer
go run . -dump-dir ./call-dumps
# Scan QR code, then call the number from another phone
# All signaling nodes are saved to ./call-dumps/{callID}/
```

## Call Events Captured

| Event | Description |
|-------|-------------|
| `CallOffer` | Incoming 1:1 call |
| `CallOfferNotice` | Incoming group call |
| `CallAccept` | Call accepted |
| `CallPreAccept` | Pre-acceptance signal |
| `CallTransport` | Media transport/relay info |
| `CallRelayLatency` | Relay latency measurement |
| `CallTerminate` | Call ended (with reason) |
| `CallReject` | Call declined |

## Dump Format

Each call event is saved as a JSON file:

```
call-dumps/
  {callID}/
    offer_20260325-143052.123.json
    transport_20260325-143053.456.json
    terminate_20260325-143112.789.json
```

Each file contains:
- `event_type` — the signaling event name
- `timestamp` — when the event was captured
- `node_json` — raw binary node as JSON (parseable)
- `node_text` — human-readable representation

## Roadmap

- [x] **Phase 1** — Event capture & protocol logging
- [ ] **Phase 2** — Accept/initiate calls via `DangerousInternals().SendNode()`
- [ ] **Phase 3** — Audio media bridge (SRTP decode/encode)
- [ ] **Phase 4** — Real-time AI voice integration (Gemini Live, OpenAI Realtime, etc.)

## Contributing

The biggest contribution right now is **call dumps**. If you run the sniffer and capture call signaling data, please open an issue or PR with your (anonymized) dumps. This data is essential for implementing call acceptance in Phase 2.

## How It Works

WhatsApp calls use a proprietary binary XML signaling protocol (not SIP/SDP). The whatsmeow library parses these into Go events but only implements `RejectCall()`. This library:

1. Listens to all call events via `client.AddEventHandler`
2. Tracks call sessions through their lifecycle
3. Dumps the raw `*waBinary.Node` data that contains the actual signaling payload
4. Uses `DangerousInternals().SendNode()` for sending custom call responses

The signaling nodes contain relay server addresses, encryption keys, and transport parameters that need to be decoded to implement full call support.

## License

MPL 2.0 — same as whatsmeow.
