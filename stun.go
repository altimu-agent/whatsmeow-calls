// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeowcalls

// WhatsApp uses a custom STUN-like protocol (WASP) for relay binding.
// Custom attributes:
//   0x4000: relay token (~182 bytes)
//   0x4002: PING request
//   0x4003: PING response
//   XOR-RELAYED-ADDRESS: relay server IP
//   MESSAGE-INTEGRITY: HMAC-SHA1

// PingRelay sends a custom STUN binding request to a relay server
// and returns the round-trip time. Not yet implemented — Phase 3.
func PingRelay(endpoint RelayEndpoint, token []byte) (rttMs int, err error) {
	return 0, ErrNotImplemented
}
