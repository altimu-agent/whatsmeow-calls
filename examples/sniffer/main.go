// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Command sniffer is a standalone WhatsApp call event logger.
// It connects to WhatsApp (pairing via QR code if needed) and captures
// all call signaling nodes to disk for protocol analysis.
//
// Usage:
//
//	go run . [-dump-dir ./call-dumps] [-db ./whatsmeow.db]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store/sqlstore"
	waLog "go.mau.fi/whatsmeow/util/log"

	whatsmeowcalls "github.com/altimu-agent/whatsmeow-calls"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	dumpDir := flag.String("dump-dir", "./call-dumps", "Directory to save call node dumps")
	dbPath := flag.String("db", "file:whatsmeow.db?_foreign_keys=on", "SQLite database path for whatsmeow session")
	logLevel := flag.String("log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR)")
	flag.Parse()

	logger := waLog.Stdout("sniffer", *logLevel, true)

	container, err := sqlstore.New(context.Background(), "sqlite3", *dbPath, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open database: %v\n", err)
		os.Exit(1)
	}

	deviceStore, err := container.GetFirstDevice(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get device: %v\n", err)
		os.Exit(1)
	}

	client := whatsmeow.NewClient(deviceStore, logger)

	// Set up the call bridge with dump logging
	bridge := whatsmeowcalls.NewCallBridge(client, whatsmeowcalls.Options{
		LogDir: *dumpDir,
		Logger: waLog.Stdout("calls", *logLevel, true),
		OnIncomingCall: func(call *whatsmeowcalls.IncomingCall) {
			fmt.Printf("\n========================================\n")
			fmt.Printf("INCOMING CALL\n")
			fmt.Printf("  From:     %s\n", call.From)
			fmt.Printf("  Call ID:  %s\n", call.CallID)
			fmt.Printf("  Platform: %s\n", call.Platform)
			fmt.Printf("  Version:  %s\n", call.Version)
			if !call.GroupJID.IsEmpty() {
				fmt.Printf("  Group:    %s\n", call.GroupJID)
			}
			if call.Media != "" {
				fmt.Printf("  Media:    %s\n", call.Media)
			}
			fmt.Printf("  Dumps saved to: %s/%s/\n", *dumpDir, call.CallID)
			fmt.Printf("========================================\n\n")

			// Don't reject — let it ring so we capture all signaling nodes
			fmt.Println("Letting call ring to capture full signaling flow...")
			fmt.Println("(The caller will see it ringing until they hang up)")
		},
		OnCallTerminated: func(session *whatsmeowcalls.CallSession) {
			fmt.Printf("\n--- Call %s ended (reason: %s, nodes captured: %d) ---\n\n",
				session.CallID, session.TerminateReason, len(session.AllNodes))
		},
	})

	// Register both the call bridge and a basic message handler
	client.AddEventHandler(bridge.HandleEvent)

	// Connect
	if client.Store.ID == nil {
		// No session — need QR code pairing
		qrChan, _ := client.GetQRChannel(context.Background())
		if err := client.Connect(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect: %v\n", err)
			os.Exit(1)
		}
		for evt := range qrChan {
			if evt.Event == "code" {
				fmt.Println("Scan this QR code with WhatsApp:")
				fmt.Println(evt.Code)
			} else {
				fmt.Printf("QR event: %s\n", evt.Event)
			}
		}
	} else {
		if err := client.Connect(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("\nConnected! Waiting for incoming calls...")
	fmt.Printf("Call dumps will be saved to: %s/\n", *dumpDir)
	fmt.Println("Press Ctrl+C to exit.")

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")
	client.Disconnect()
}
