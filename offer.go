// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeowcalls

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	waBinary "go.mau.fi/whatsmeow/binary"
)

// ParseOffer extracts structured data from a raw call offer node.
func ParseOffer(node *waBinary.Node) (*OfferData, error) {
	if node == nil {
		return nil, fmt.Errorf("nil offer node")
	}

	offer := &OfferData{}

	for _, child := range node.GetChildren() {
		switch child.Tag {
		case "audio":
			codec := AudioCodec{
				Enc: child.AttrGetter().String("enc"),
			}
			if rateStr := child.AttrGetter().String("rate"); rateStr != "" {
				codec.Rate, _ = strconv.Atoi(rateStr)
			}
			offer.AudioCodecs = append(offer.AudioCodecs, codec)

		case "enc":
			encCopy := child
			offer.EncNode = &encCopy
			offer.EncType = child.AttrGetter().String("type")
			if vStr := child.AttrGetter().String("v"); vStr != "" {
				offer.EncVersion, _ = strconv.Atoi(vStr)
			}

		case "relay":
			relay, err := ParseRelay(&child)
			if err == nil {
				offer.Relay = relay
			}

		case "voip_settings":
			if content, ok := child.Content.([]byte); ok {
				decoded, err := base64.StdEncoding.DecodeString(string(content))
				if err == nil {
					content = decoded
				}
				var settings map[string]any
				if err := json.Unmarshal(content, &settings); err == nil {
					offer.VoIPSettings = settings
				}
			}

		case "capability":
			if content, ok := child.Content.([]byte); ok {
				decoded, err := base64.StdEncoding.DecodeString(string(content))
				if err == nil {
					offer.Capabilities = decoded
				} else {
					offer.Capabilities = content
				}
			}

		case "net":
			offer.NetMedium = child.AttrGetter().String("medium")
		}
	}

	return offer, nil
}
