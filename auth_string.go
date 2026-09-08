package raw

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/mtgo-labs/raw/session"
	"github.com/mtgo-labs/raw/tl"
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
		config.Salt != 0 || config.SessionID != [8]byte{} {
		return fmt.Errorf("%w: session string conflicts with explicit auth key or salt", ErrInvalidConfig)
	}
	if config.DCID != 0 && config.DCID != value.Main.ID {
		return fmt.Errorf("%w: session string DC %d conflicts with config DC %d", ErrInvalidConfig, value.Main.ID, config.DCID)
	}
	if value.TestModeKnown && config.TestMode && !value.Main.TestMode {
		return fmt.Errorf("%w: session string is production but config is test mode", ErrInvalidConfig)
	}
	address := value.Main.Address
	if config.Address != "" {
		if value.AddressKnown && config.Address != address {
			return fmt.Errorf("%w: session string address %s conflicts with config address %s", ErrInvalidConfig, address, config.Address)
		}
		address = config.Address
	}
	if configured, ok := config.DCAddresses[value.Main.ID]; ok {
		if value.AddressKnown && configured != address {
			return fmt.Errorf("%w: session string address %s conflicts with DCAddresses[%d] %s", ErrInvalidConfig, address, value.Main.ID, configured)
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
	if config.APIHash == "" && value.APIHash != "" {
		config.APIHash = value.APIHash
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

// ExportSessionString exports the current authorization as a native mtgo MTGO1
// session string ("MTGO1.<payload>"). The payload is fully self-contained: it
// carries the phone number, user ID, API ID, API hash, data-center ID, and the
// 256-byte auth key, so a fresh Client can resume the session from the string
// alone (user ID and bot flag are fetched live via users.getUsers).
//
// ExportSessionString requires a live connection and a configured API hash.
func (client *Client) ExportSessionString(ctx context.Context) (string, error) {
	if client == nil {
		return "", ErrInvalidConfig
	}
	if ctx == nil {
		return "", context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	client.mu.Lock()
	dcid := client.config.DCID
	apiID := client.config.APIID
	apiHash := client.config.APIHash
	phone := client.config.Phone
	testMode := client.config.TestMode
	authKey := client.exportAuthKeyLocked()
	store := client.config.Store
	client.mu.Unlock()
	if len(authKey) == 0 && store != nil {
		data, err := store.Load(ctx)
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
	if dcid <= 0 || dcid > 5 {
		return "", fmt.Errorf("%w: primary DC is not configured", ErrInvalidConfig)
	}
	if apiID <= 0 {
		return "", fmt.Errorf("%w: api id is not configured", ErrInvalidConfig)
	}
	if apiHash == "" {
		return "", fmt.Errorf("%w: api hash is not configured", ErrInvalidConfig)
	}
	users, err := Invoke(ctx, client, &tl.UsersGetUsersRequest{ID: []tl.InputUserClass{&tl.InputUserSelf{}}})
	if err != nil {
		return "", fmt.Errorf("export session: get self user: %w", err)
	}
	var self *tl.User
	for _, user := range users {
		if candidate, ok := user.(*tl.User); ok && candidate.Self {
			self = candidate
			break
		}
	}
	if self == nil {
		return "", errors.New("export session: self user missing from users.getUsers response")
	}
	return session.EncodeMTGOSessionString(session.SessionString{
		APIID:       apiID,
		Main:        session.SessionStringDC{ID: dcid, TestMode: testMode},
		User:        &session.SessionStringUser{ID: self.ID, Bot: self.Bot},
		AuthKey:     authKey,
		APIHash:     apiHash,
		PhoneNumber: phone,
	})
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
