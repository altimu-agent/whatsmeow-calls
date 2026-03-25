// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeowcalls

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DetectPublicIP returns the public IPv4 address by querying an external service.
// Returns empty string on failure.
func DetectPublicIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	for _, url := range []string{"https://ifconfig.me", "https://icanhazip.com", "https://api.ipify.org"} {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

// DetectLocalIP returns the preferred local/private IPv4 address.
// Returns empty string on failure.
func DetectLocalIP() string {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*net.UDPAddr)
	return addr.IP.String()
}
