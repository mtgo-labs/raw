package raw

import (
	"errors"
	"fmt"
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
	InMemory  bool
	Transport TransportKind
	Obfuscate bool
	NoDelay   bool
	// NetPoll selects the CloudWeGo/netpoll epoll-based transport instead of
	// the standard net package. It is Linux-only and ignored when a proxy is
	// configured. The zero value (false) keeps the default TCP transport.
	NetPoll         bool
	Proxy           ProxyConfig
	Store           session.Store
	Logger          *slog.Logger
	PendingCapacity int
	MaxPayload      int
	UpdateBuffer    int
	// NoUpdates disables update collection. When true, the Updates channel
	// is nil and inbound updates are silently discarded.
	NoUpdates         bool
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
	if config.APIID <= 0 {
		return fmt.Errorf("%w: api_id is %d (must be > 0)", ErrInvalidConfig, config.APIID)
	}
	if config.Address == "" {
		return fmt.Errorf("%w: address is empty (must be set)", ErrInvalidConfig)
	}
	if config.DCID < 0 || config.DCID > int(^uint32(0)>>1) {
		return fmt.Errorf("%w: dc_id %d is invalid", ErrInvalidConfig, config.DCID)
	}
	if config.Transport > TransportPaddedIntermediate {
		return fmt.Errorf("%w: transport %d is invalid", ErrInvalidConfig, config.Transport)
	}
	if config.Proxy.Kind > ProxySOCKS5 {
		return fmt.Errorf("%w: proxy kind %d is invalid", ErrInvalidConfig, config.Proxy.Kind)
	}
	if (config.Proxy.Kind == ProxyHTTPConnect || config.Proxy.Kind == ProxySOCKS5) && !validAddress(config.Proxy.Address) {
		return fmt.Errorf("%w: proxy address %q is invalid", ErrInvalidConfig, config.Proxy.Address)
	}
	if config.PendingCapacity < 0 {
		return fmt.Errorf("%w: pending capacity %d is negative", ErrInvalidConfig, config.PendingCapacity)
	}
	if config.MaxPayload < 0 {
		return fmt.Errorf("%w: max payload %d is negative", ErrInvalidConfig, config.MaxPayload)
	}
	if config.UpdateBuffer < 0 {
		return fmt.Errorf("%w: update buffer %d is negative", ErrInvalidConfig, config.UpdateBuffer)
	}
	if config.PoolSize < 0 {
		return fmt.Errorf("%w: pool size %d is negative", ErrInvalidConfig, config.PoolSize)
	}
	if config.PoolIdleTimeout < 0 {
		return fmt.Errorf("%w: pool idle timeout %s is negative", ErrInvalidConfig, config.PoolIdleTimeout)
	}
	if config.Retry.MaxAttempts < 0 {
		return fmt.Errorf("%w: retry max attempts %d is negative", ErrInvalidConfig, config.Retry.MaxAttempts)
	}
	if config.Retry.MaxFloodWait < 0 {
		return fmt.Errorf("%w: retry max flood wait %s is negative", ErrInvalidConfig, config.Retry.MaxFloodWait)
	}
	if config.Reconnect.MaxAttempts < 0 {
		return fmt.Errorf("%w: reconnect max attempts %d is negative", ErrInvalidConfig, config.Reconnect.MaxAttempts)
	}
	if config.Reconnect.InitialDelay < 0 {
		return fmt.Errorf("%w: reconnect initial delay %s is negative", ErrInvalidConfig, config.Reconnect.InitialDelay)
	}
	if config.Reconnect.MaxDelay < 0 {
		return fmt.Errorf("%w: reconnect max delay %s is negative", ErrInvalidConfig, config.Reconnect.MaxDelay)
	}
	if config.Liveness.PingInterval < 0 {
		return fmt.Errorf("%w: liveness ping interval %s is negative", ErrInvalidConfig, config.Liveness.PingInterval)
	}
	if config.Liveness.PongTimeout < 0 {
		return fmt.Errorf("%w: liveness pong timeout %s is negative", ErrInvalidConfig, config.Liveness.PongTimeout)
	}
	if len(config.AuthKey) != 0 && len(config.AuthKey) != 256 {
		return fmt.Errorf("%w: auth key length is %d (must be 256)", ErrInvalidConfig, len(config.AuthKey))
	}
	if len(config.AuthKey) != 0 && config.AuthKeyID == 0 {
		return fmt.Errorf("%w: auth key id is 0 when auth key is set", ErrInvalidConfig)
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
