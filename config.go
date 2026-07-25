package raw

import (
	"errors"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/mtgo-labs/raw/session"
	"github.com/mtgo-labs/raw/tl"
)

var (
	ErrInvalidConfig           = errors.New("raw: invalid configuration")
	ErrNotConnected            = errors.New("raw: client is not connected")
	ErrNoAuthKey               = errors.New("raw: no persisted authorization key")
	ErrUpdateOverflow          = errors.New("raw: update queue overflow")
	ErrAcknowledgementOverflow = errors.New("raw: acknowledgement queue overflow")
	ErrUnsupportedRoute        = errors.New("raw: unsupported connection route")
	ErrAuthKeyExpired          = errors.New("raw: authorization key expired")
	ErrAuthTransfer            = errors.New("raw: authorization transfer failed")
	ErrPFSBindRejected         = errors.New("raw: temporary authorization key binding rejected")
	ErrPFSKeysInvalid          = errors.New("raw: PFS keys must be recreated")
	ErrPFSRebindRequired       = errors.New("raw: PFS temporary key must be replaced and rebound")
	ErrConnectionFlood         = errors.New("raw: connection attempt rate limited")
	ErrDisconnected            = errors.New("raw: client is disconnected")
)

type ConnectionKind uint8

const (
	ConnectionMain ConnectionKind = iota
	ConnectionUpload
	ConnectionDownload
)

type InvokeOptions struct {
	DCID        int
	Kind        ConnectionKind
	Slot        int
	OrderingKey string
}

type AuthKeyConfig struct {
	Key        []byte
	ID         uint64
	Salt       int64
	SessionID  [8]byte
	TimeOffset int64
	CreatedAt  int64
	ExpiresAt  int64
}

// Expired reports whether this authorization key has passed its optional
// server-provided expiry time. A zero expiry means the key is permanent.
func (auth AuthKeyConfig) Expired(now time.Time) bool {
	return auth.ExpiresAt != 0 && auth.ExpiresAt <= now.Unix()
}

type RetryPolicy struct {
	MaxAttempts  int
	MaxFloodWait time.Duration
}

type ReconnectPolicy struct {
	Disabled     bool
	MaxAttempts  int
	InitialDelay time.Duration
	MaxDelay     time.Duration
}

// LivenessPolicy controls protocol-level ping scheduling for each connected
// route. Zero durations select the defaults.
type LivenessPolicy struct {
	Disabled     bool
	PingInterval time.Duration
	PongTimeout  time.Duration
}

type TransportKind uint8

const (
	TransportIntermediate TransportKind = iota
	TransportAbridged
	TransportPaddedIntermediate
)

type ProxyKind uint8

const (
	ProxyNone ProxyKind = iota
	ProxyHTTPConnect
	ProxySOCKS5
)

type ProxyConfig struct {
	Kind     ProxyKind
	Address  string
	Username string
	Password string
}

type InitConnectionConfig struct {
	DeviceModel        string
	SystemVersion      string
	AppVersion         string
	SystemLanguageCode string
	LanguagePack       string
	LanguageCode       string
	Proxy              tl.InputClientProxyClass
	Parameters         tl.JSONValueClass
}

type Config struct {
	APIID    int32
	APIHash  string
	BotToken string
	Phone    string
	// DCID defaults to production or test DC 2.
	DCID int
	// Address defaults to Telegram's DC 2 endpoint when DCID is omitted or 2.
	// For another DC, set Address or provide its entry in DCAddresses.
	Address     string
	DCAddresses map[int]string
	DCAuthKeys  map[int]AuthKeyConfig
	// SessionString is an mtcute, Pyrogram, Telethon, or encrypted mtgo-raw
	// authorization string. NewClient auto-detects the format.
	SessionString string
	// SessionStringKey decrypts mtgo-raw strings. It must be 32 bytes, is ignored
	// by no other format, and is not retained by Client.
	SessionStringKey []byte
	TestMode         bool
	// InMemory uses an in-memory session store when Store is not set.
	InMemory          bool
	Transport         TransportKind
	Obfuscate         bool
	Proxy             ProxyConfig
	Store             session.Store
	Logger            *slog.Logger
	PendingCapacity   int
	MaxPayload        int
	UpdateBuffer      int
	// NoUpdates disables update collection. When true, the Updates channel
	// is nil and inbound updates are silently discarded.
	NoUpdates bool
	PoolSize          int
	PoolIdleTimeout   time.Duration
	Retry             RetryPolicy
	Reconnect         ReconnectPolicy
	Liveness          LivenessPolicy
	InitConnection    InitConnectionConfig
	AuthKey           []byte
	AuthKeyID         uint64
	AuthKeyTimeOffset int64
	Salt              int64
	SessionID         [8]byte
}

func (config Config) validate() error {
	if config.APIID <= 0 || config.Address == "" {
		return ErrInvalidConfig
	}
	if config.DCID < 0 || config.DCID > int(^uint32(0)>>1) {
		return ErrInvalidConfig
	}
	if config.Transport > TransportPaddedIntermediate ||
		config.Proxy.Kind > ProxySOCKS5 ||
		(config.Proxy.Kind == ProxyHTTPConnect || config.Proxy.Kind == ProxySOCKS5) && !validAddress(config.Proxy.Address) ||
		config.PendingCapacity < 0 ||
		config.MaxPayload < 0 ||
		config.UpdateBuffer < 0 ||
		config.PoolSize < 0 ||
		config.PoolIdleTimeout < 0 ||
		config.Retry.MaxAttempts < 0 ||
		config.Retry.MaxFloodWait < 0 ||
		config.Reconnect.MaxAttempts < 0 ||
		config.Reconnect.InitialDelay < 0 ||
		config.Reconnect.MaxDelay < 0 ||
		config.Liveness.PingInterval < 0 ||
		config.Liveness.PongTimeout < 0 {
		return ErrInvalidConfig
	}
	if len(config.AuthKey) != 0 && len(config.AuthKey) != 256 {
		return ErrInvalidConfig
	}
	if len(config.AuthKey) != 0 && config.AuthKeyID == 0 {
		return ErrInvalidConfig
	}
	for id, auth := range config.DCAuthKeys {
		if id <= 0 || id > int(^uint32(0)>>1) || len(auth.Key) != 256 || auth.ID == 0 {
			return ErrInvalidConfig
		}
	}
	for id, address := range config.DCAddresses {
		if id <= 0 || id > int(^uint32(0)>>1) || !validAddress(address) {
			return ErrInvalidConfig
		}
	}
	return nil
}

func validAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return false
	}
	value, err := strconv.Atoi(port)
	return err == nil && value > 0 && value <= 65535
}
