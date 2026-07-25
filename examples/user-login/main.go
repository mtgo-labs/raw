package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strconv"

	raw "github.com/mtgo-labs/raw"
	"github.com/mtgo-labs/raw/session"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	store, err := session.NewFileStore(envOr("TELEGRAM_SESSION_FILE", "raw.session"))
	if err != nil {
		return err
	}
	client, err := raw.NewClient(raw.Config{
		APIID:   requiredInt32("TELEGRAM_API_ID"),
		APIHash: required("TELEGRAM_API_HASH"),
		Phone:   required("TELEGRAM_PHONE"),
		Store:   store,
	})
	if err != nil {
		return err
	}
	defer client.Close()

	user, err := client.Start(context.Background(), raw.StartOptions{
		Code: func(_ context.Context) (string, error) {
			fmt.Print("Telegram code: ")
			code, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil {
				return "", err
			}
			return code, nil
		},
	})
	if err != nil {
		return err
	}
	fmt.Printf("authorized user: id=%d username=%s\n", user.ID, *user.Username)
	return nil
}

func required(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func requiredInt32(name string) int32 {
	value, err := strconv.ParseInt(required(name), 0, 32)
	if err != nil {
		log.Fatalf("%s: %v", name, err)
	}
	return int32(value)
}
