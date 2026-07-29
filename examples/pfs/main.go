package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	raw "github.com/mtgo-labs/raw"
	"github.com/mtgo-labs/raw/tl"
)

// PFS (Perfect Forward Secrecy) demo.
//
// Requires an existing authorized session string. The first RPC after Connect
// transparently negotiates a temporary auth key via DH exchange and binds it to
// the permanent key. All subsequent traffic is encrypted with the temporary key.
// When it expires (default 24h), the next RPC automatically negotiates a fresh one.
//
// Env:
//
//	TELEGRAM_API_ID       api_id from my.telegram.org
//	TELEGRAM_API_HASH     api_hash from my.telegram.org
//	TELEGRAM_SESSION      session string (mtcute/Pyrogram/Telethon/raw format)
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	client, err := raw.NewClient(raw.Config{
		APIID:         requiredInt32("TELEGRAM_API_ID"),
		APIHash:       required("TELEGRAM_API_HASH"),
		SessionString: required("TELEGRAM_SESSION"),
		InMemory:      true,
		PFS: raw.PFSPolicy{
			Enabled:  true,
			Lifetime: 24 * time.Hour,
		},
	})
	if err != nil {
		return err
	}
	defer client.Close()

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		return err
	}

	// First invoke triggers temp key negotiation + auth.bindTempAuthKey.
	// This adds ~1s latency (one DH round-trip). Subsequent calls are instant.
	users, err := raw.Invoke(ctx, client, &tl.UsersGetUsersRequest{
		ID: []tl.InputUserClass{&tl.InputUserSelf{}},
	})
	if err != nil {
		return err
	}
	if len(users) == 0 {
		return fmt.Errorf("no users returned")
	}
	me, ok := users[0].(*tl.User)
	if !ok {
		return fmt.Errorf("unexpected type %T", users[0])
	}
	fmt.Printf("authorized with PFS: id=%d username=%s\n", me.ID, *me.Username)

	// Second invoke uses the already-bound temp key — no negotiation overhead.
	users, err = raw.Invoke(ctx, client, &tl.UsersGetUsersRequest{
		ID: []tl.InputUserClass{&tl.InputUserSelf{}},
	})
	if err != nil {
		return err
	}
	fmt.Printf("verified PFS session: %d bytes response\n", len(users))

	return nil
}

func required(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}

func requiredInt32(name string) int32 {
	value, err := strconv.ParseInt(required(name), 0, 32)
	if err != nil {
		log.Fatalf("%s: %v", name, err)
	}
	return int32(value)
}
