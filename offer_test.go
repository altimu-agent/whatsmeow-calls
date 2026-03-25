// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeowcalls

import (
	"encoding/base64"
	"encoding/binary"
	"testing"

	waBinary "go.mau.fi/whatsmeow/binary"
)

func makeTestOfferNode() *waBinary.Node {
	// Build a minimal offer node matching real captured structure
	// IPv4 endpoint: 181.39.187.227:3480
	ipPort := make([]byte, 6)
	copy(ipPort[:4], []byte{181, 39, 187, 227})
	binary.BigEndian.PutUint16(ipPort[4:], 3480)

	// Double-base64 key: inner = 16 bytes, encoded to base64 ASCII, then stored as bytes
	innerKey := []byte{0x3c, 0x32, 0x77, 0xd1, 0xf3, 0xf2, 0x65, 0xe1, 0x2a, 0xca, 0xe0, 0x81, 0x28, 0x69, 0x2a, 0xb7}
	keyB64 := base64.StdEncoding.EncodeToString(innerKey)

	// voip_settings as JSON bytes
	voipJSON := []byte(`{"encode":{"codec":"opus"},"options":{"disable_p2p":"1"}}`)

	return &waBinary.Node{
		Tag: "offer",
		Attrs: waBinary.Attrs{
			"call-id":      "TESTCALL123",
			"call-creator": "12345@s.whatsapp.net",
		},
		Content: []waBinary.Node{
			{Tag: "audio", Attrs: waBinary.Attrs{"enc": "opus", "rate": "16000"}},
			{Tag: "audio", Attrs: waBinary.Attrs{"enc": "opus", "rate": "8000"}},
			{Tag: "enc", Attrs: waBinary.Attrs{"type": "msg", "v": "2"}, Content: []byte{0x33, 0x0a}},
			{Tag: "net", Attrs: waBinary.Attrs{"medium": "3"}},
			{Tag: "voip_settings", Attrs: waBinary.Attrs{"uncompressed": "1"}, Content: voipJSON},
			{Tag: "relay", Attrs: waBinary.Attrs{"uuid": "testUUID", "peer_pid": "1", "self_pid": "2"},
				Content: []waBinary.Node{
					{Tag: "token", Attrs: waBinary.Attrs{"id": "0"}, Content: []byte{0x09, 0x0f, 0x01, 0x55}},
					{Tag: "auth_token", Attrs: waBinary.Attrs{"id": "0"}, Content: []byte{0x09, 0x03, 0x18}},
					{Tag: "key", Content: []byte(keyB64)},
					{Tag: "te2", Attrs: waBinary.Attrs{
						"relay_id": "0", "relay_name": "fuio1c01",
						"c2r_rtt": "6", "token_id": "0", "auth_token_id": "0",
					}, Content: ipPort},
				},
			},
		},
	}
}

func TestParseOffer(t *testing.T) {
	node := makeTestOfferNode()
	offer, err := ParseOffer(node)
	if err != nil {
		t.Fatalf("ParseOffer failed: %v", err)
	}

	// Audio codecs
	if len(offer.AudioCodecs) != 2 {
		t.Fatalf("expected 2 audio codecs, got %d", len(offer.AudioCodecs))
	}
	if offer.AudioCodecs[0].Enc != "opus" || offer.AudioCodecs[0].Rate != 16000 {
		t.Errorf("codec[0] = %+v, want opus@16000", offer.AudioCodecs[0])
	}
	if offer.AudioCodecs[1].Rate != 8000 {
		t.Errorf("codec[1].Rate = %d, want 8000", offer.AudioCodecs[1].Rate)
	}

	// Enc node
	if offer.EncNode == nil {
		t.Fatal("EncNode is nil")
	}
	if offer.EncType != "msg" {
		t.Errorf("EncType = %q, want %q", offer.EncType, "msg")
	}
	if offer.EncVersion != 2 {
		t.Errorf("EncVersion = %d, want 2", offer.EncVersion)
	}

	// Net
	if offer.NetMedium != "3" {
		t.Errorf("NetMedium = %q, want %q", offer.NetMedium, "3")
	}

	// VoIP settings
	if offer.VoIPSettings == nil {
		t.Fatal("VoIPSettings is nil")
	}
	if _, ok := offer.VoIPSettings["encode"]; !ok {
		t.Error("VoIPSettings missing 'encode' key")
	}
}

func TestParseOffer_Nil(t *testing.T) {
	_, err := ParseOffer(nil)
	if err == nil {
		t.Error("expected error for nil node")
	}
}

func TestParseRelay(t *testing.T) {
	node := makeTestOfferNode()
	offer, err := ParseOffer(node)
	if err != nil {
		t.Fatalf("ParseOffer failed: %v", err)
	}

	relay := offer.Relay
	if relay == nil {
		t.Fatal("Relay is nil")
	}

	if relay.UUID != "testUUID" {
		t.Errorf("UUID = %q, want %q", relay.UUID, "testUUID")
	}
	if relay.PeerPID != "1" {
		t.Errorf("PeerPID = %q, want %q", relay.PeerPID, "1")
	}

	// Tokens
	if len(relay.Tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(relay.Tokens))
	}
	if relay.Tokens["0"][0] != 0x09 {
		t.Errorf("token[0] first byte = %x, want 0x09", relay.Tokens["0"][0])
	}

	// Auth tokens
	if len(relay.AuthTokens) != 1 {
		t.Fatalf("expected 1 auth_token, got %d", len(relay.AuthTokens))
	}

	// Key (double-base64 decoded)
	if relay.Key == nil {
		t.Fatal("Key is nil")
	}
	if len(relay.Key) != 16 {
		t.Errorf("Key length = %d, want 16", len(relay.Key))
	}
	if relay.Key[0] != 0x3c {
		t.Errorf("Key[0] = %x, want 0x3c", relay.Key[0])
	}

	// Endpoints
	if len(relay.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(relay.Endpoints))
	}
	ep := relay.Endpoints[0]
	if ep.RelayName != "fuio1c01" {
		t.Errorf("RelayName = %q, want %q", ep.RelayName, "fuio1c01")
	}
	if ep.IP.String() != "181.39.187.227" {
		t.Errorf("IP = %s, want 181.39.187.227", ep.IP)
	}
	if ep.Port != 3480 {
		t.Errorf("Port = %d, want 3480", ep.Port)
	}
	if ep.RTT != 6 {
		t.Errorf("RTT = %d, want 6", ep.RTT)
	}
}
