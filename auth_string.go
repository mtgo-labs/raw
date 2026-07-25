package raw

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/mtgo-labs/raw/session"
)

func applySessionString(config *Config) error {
	if config == nil {
		return nil
	}
	if config.SessionString == "" {
		if len(config.SessionStringKey) != 0 {
			return fmt.Errorf("%w: session string key provided without an auth string", ErrInvalidConfig)
		}
		return nil
	}
	if len(config.SessionStringKey) != 0 && len(config.SessionStringKey) != 32 {
		return fmt.Errorf("%w: session string key must be 32 bytes", ErrInvalidConfig)
	}
	value, err := session.DecodeSessionString(config.SessionString, config.SessionStringKey)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	defer clear(value.AuthKey)
	if len(config.SessionStringKey) != 0 && value.Format != session.SessionStringFormatRaw {
		return fmt.Errorf("%w: session string key provided for an unencrypted format", ErrInvalidConfig)
	}
	if len(config.AuthKey) != 0 || config.AuthKeyID != 0 || config.AuthKeyTimeOffset != 0 ||
		config.Salt != 0 || config.SessionID != [8]byte{} ||
		config.DCID != 0 && config.DCID != value.Main.ID ||
		value.APIID != 0 && config.APIID != 0 && config.APIID != value.APIID ||
		value.TestModeKnown && config.TestMode && !value.Main.TestMode {
		return fmt.Errorf("%w: session string conflicts with explicit authorization or backend configuration", ErrInvalidConfig)
	}
	address := value.Main.Address
	if config.Address != "" {
		if value.AddressKnown && config.Address != address {
			return fmt.Errorf("%w: session string conflicts with primary DC address", ErrInvalidConfig)
		}
		address = config.Address
	}
	if configured, ok := config.DCAddresses[value.Main.ID]; ok {
		if value.AddressKnown && configured != address {
			return fmt.Errorf("%w: session string conflicts with primary DC address", ErrInvalidConfig)
		}
		address = configured
	}
	digest := sha1.Sum(value.AuthKey)
	authKeyID := binary.LittleEndian.Uint64(digest[12:20])
	if authKeyID == 0 {
		return fmt.Errorf("%w: session string has an invalid authorization key", ErrInvalidConfig)
	}
	if config.APIID == 0 {
		config.APIID = value.APIID
	}
	if value.TestModeKnown {
		config.TestMode = value.Main.TestMode
	}
	config.DCID = value.Main.ID
	config.Address = address
	config.AuthKey = append([]byte(nil), value.AuthKey...)
	config.AuthKeyID = authKeyID
	config.SessionString = ""
	config.SessionStringKey = nil
	return nil
}

// ExportSessionString encrypts the current permanent authorization into the
// mtgo-raw raw1 format with AES-256-GCM. encryptionKey must be a caller-owned
// 32-byte random key and is not embedded in the result.
func (client *Client) ExportSessionString(ctx context.Context, encryptionKey []byte) (string, error) {
	if client == nil {
		return "", ErrInvalidConfig
	}
	if ctx == nil {
		return "", context.Canceled
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}

	dcid := client.config.DCID
	authKey := client.exportAuthKeyLocked()
	if len(authKey) == 0 && client.config.Store != nil {
		data, err := client.config.Store.Load(ctx)
		if err != nil {
			if errors.Is(err, session.ErrSessionNotFound) {
				return "", ErrNoAuthKey
			}
			return "", err
		}
		if len(data) == 0 {
			return "", ErrNoAuthKey
		}
		snapshot, err := session.Decode(data)
		if err != nil {
			return "", err
		}
		dcid = snapshot.PrimaryDC
		stored, ok := snapshot.AuthKeyFor(dcid, "main")
		if !ok {
			return "", ErrNoAuthKey
		}
		authKey = stored.Key
	}
	if len(authKey) != 256 {
		return "", ErrNoAuthKey
	}
	defer clear(authKey)

	address := client.config.Address
	if endpoint, ok := client.endpoints.Get(dcid); ok {
		address = endpoint.Address
	} else if configured, ok := client.config.DCAddresses[dcid]; ok {
		address = configured
	} else if dcid != client.config.DCID {
		return "", ErrUnsupportedRoute
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("%w: invalid primary DC address", ErrInvalidConfig)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("%w: primary DC address is not an IP endpoint", ErrInvalidConfig)
	}
	primary := session.SessionStringDC{
		ID:       dcid,
		Address:  address,
		IPv6:     ip.To4() == nil,
		TestMode: client.config.TestMode,
	}
	return session.EncodeSessionString(session.SessionString{
		Format:        session.SessionStringFormatRaw,
		APIID:         client.config.APIID,
		Main:          primary,
		Media:         primary,
		AuthKey:       authKey,
		AddressKnown:  true,
		TestModeKnown: true,
	}, encryptionKey)
}

func (client *Client) exportAuthKeyLocked() []byte {
	if client.permanent.key.ID != 0 {
		return append([]byte(nil), client.permanent.key.Key[:]...)
	}
	if len(client.config.AuthKey) == 256 {
		return append([]byte(nil), client.config.AuthKey...)
	}
	return nil
}
