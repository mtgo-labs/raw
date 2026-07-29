package raw

import (
	"context"
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
	// MaxAttempts limits the total number of send attempts per RPC,
	// including retries for transient and flood-wait errors. A value
	// <= 0 defaults to 1 (no retries).
	MaxAttempts int

	// MaxFloodWait is the longest FLOOD_WAIT duration the client will
	// honour. Waits exceeding this value are returned to the caller as
	// errors instead of being retried. A value <= 0 disables automatic
	// flood-wait retry; the error is returned immediately.
	//
	// When MaxFloodWait > 0, the client also enables proactive
	// per-method flood-wait tracking: after a method receives
	// FLOOD_WAIT_X, subsequent requests for the same method are
	// delayed or rejected before being sent.
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

// PFSPolicy controls Perfect Forward Secrecy via temporary auth keys.
// When Enabled is true, the client automatically negotiates a temporary key
// after connecting with its permanent key and binds it via
// auth.bindTempAuthKey. The temporary key encrypts all traffic and rotates
// before Lifetime expires. Telegram allows at most 24 hours (86400 s).
type PFSPolicy struct {
	Enabled bool
	// Lifetime is the temporary key TTL. Zero defaults to 24 hours.
	// Values above 24 hours are clamped to 24 hours.
	Lifetime time.Duration
}

type TransportKind uint8

const (
	TransportIntermediate TransportKind = iota
	TransportAbridged
	TransportPaddedIntermediate
	TransportHTTP
)

// PacketTransportConn is a packet-aware MTProto connection supplied by a
// DialFunc. Non-obfuscated TCP transports configure and use it directly.
// ConfigurePacketTransport is called once with the uint8 value of TransportKind
// before the transport marker is sent.
// Values 0, 1, and 2 select intermediate, abridged, and padded-intermediate
// framing respectively; other values are not passed to packet transports.
// ReadPacket and ReadPlainPacket return caller-owned buffers; ReadPlainPacket
// removes any transport padding. Write methods must not retain caller buffers
// after returning. Implementations may additionally provide ReadPacketView(int,
// func([]byte) error) error to expose a borrowed packet only for the callback's
// lifetime and must return the callback's error.
type PacketTransportConn interface {
	net.Conn
	ConfigurePacketTransport(uint8) error
	ReadPacket(int) ([]byte, error)
	WritePacket([]byte) error
	WritePacketReserved([]byte, int) error
	ReadPlainPacket(int) ([]byte, error)
	WritePlainPacket(uint64, []byte) error
}

// DialFunc establishes the underlying TCP connection to a Telegram DC.
// When Config.DialFunc is set, it replaces the default net.Dialer. A
// PacketTransportConn is used directly for non-obfuscated TCP; other
// connections retain the generic packet or obfuscation wrappers.
type DialFunc func(ctx context.Context, address string) (net.Conn, error)

// InvokeFunc is a raw RPC invocation function. It encodes the request,
// sends it over the client's primary route, and returns the raw response
// body. Middleware wraps InvokeFunc to add cross-cutting behavior
// (logging, metrics, retry, tracing) without modifying the core library.
type InvokeFunc func(ctx context.Context, request tl.Object) ([]byte, error)

// Middleware intercepts RPC invocations. Each middleware receives the
// next InvokeFunc in the chain and returns a new InvokeFunc that may
// modify the request, call next (possibly multiple times), and modify
// or observe the response. The chain is composed from outermost to
// innermost: the first middleware in the slice is called first, and the
// last middleware wraps the actual route invocation.
//
// When Config.Middlewares is nil or empty, the chain is a no-op with
// zero allocation overhead on the hot path.
type Middleware interface {
	Handle(next InvokeFunc) InvokeFunc
}

// MiddlewareFunc is a function adapter for Middleware.
type MiddlewareFunc func(next InvokeFunc) InvokeFunc

// Handle implements Middleware.
func (m MiddlewareFunc) Handle(next InvokeFunc) InvokeFunc { return m(next) }

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
	// DialFunc overrides the default TCP dialer. When set, it replaces
	// net.Dialer for establishing the underlying TCP connection. Ignored
	// when a proxy is configured. See github.com/mtgo-labs/contrib/netpoll
	// for a CloudWeGo/netpoll-based implementation.
	DialFunc DialFunc
	Proxy    ProxyConfig
	// Middlewares compose an RPC interceptor chain. Each middleware wraps the
	// next InvokeFunc in the chain. The chain is composed from outermost to
	// innermost: Config.Middlewares[0] is called first, then [1], …, and
	// the innermost call reaches the actual MTProto route invocation.
	// When nil or empty, the chain is a no-op with zero overhead.
	//
	// See github.com/mtgo-labs/contrib/middleware for implementations.
	Middlewares     []Middleware
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
	PFS               PFSPolicy
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
	if config.Transport > TransportHTTP {
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
