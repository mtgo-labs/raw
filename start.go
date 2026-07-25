package raw

import (
	"context"
	"errors"
	"fmt"

	"github.com/mtgo-labs/raw/tgerr"
	"github.com/mtgo-labs/raw/tl"
)

// StartOptions configures Client.Start.
type StartOptions struct {
	// SessionString imports an mtcute, Pyrogram, Telethon, or mtgo-raw
	// authorization string before connecting. Overrides Config.SessionString.
	SessionString string
	// BotToken authorizes a bot. If set, Start ignores Phone, Code, and
	// Password. Defaults to Config.BotToken.
	BotToken string
	// Phone authorizes a user account. Defaults to Config.Phone.
	Phone string
	// Code returns the confirmation code for the phone-number login flow.
	Code func(ctx context.Context) (string, error)
	// Password is the 2FA password.
	Password string
}

// ErrTwoFactorRequired indicates that the account has 2FA enabled and no
// password was supplied to Start. Continue with the generated
// account.getPassword and auth.checkPassword requests.
var ErrTwoFactorRequired = errors.New("raw: two-factor authentication required")

// ErrMissingCredentials indicates that Start was called without a bot token,
// phone number, or existing authorization.
var ErrMissingCredentials = errors.New("raw: no bot token, phone number, or stored authorization")

// Start connects to the primary DC and completes Telegram authorization.
// If the session is already authorized it returns the current user without
// performing a new login.
//
// BotToken and Phone default to Config.BotToken and Config.Phone. Pass
// StartOptions to override per-call:
//
//	client.Start(ctx)                              // uses Config credentials
//	client.Start(ctx, raw.StartOptions{Phone: p})  // overrides phone
//
// Start mirrors mtcute's TelegramClient.start: it probes users.getUsers first,
// falls back to auth.importBotAuthorization for bots or auth.sendCode +
// auth.signIn for users, and returns the authorized *tl.User.
func (client *Client) Start(ctx context.Context, opts ...StartOptions) (*tl.User, error) {
	if client == nil {
		return nil, ErrNotConnected
	}
	if ctx == nil {
		return nil, context.Canceled
	}
	apiHash := client.config.APIHash
	if apiHash == "" {
		return nil, fmt.Errorf("%w: Config.APIHash is required for Start", ErrInvalidConfig)
	}

	var opt StartOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	if opt.SessionString != "" {
		client.mu.Lock()
		client.config.SessionString = opt.SessionString
		applyErr := applySessionString(&client.config)
		client.mu.Unlock()
		if applyErr != nil {
			return nil, applyErr
		}
	}

	if err := client.Connect(ctx); err != nil {
		return nil, err
	}

	user, err := client.GetMe(ctx)
	if err == nil {
		return user, nil
	}
	if !tgerr.Is(err, tgerr.ErrAuthKeyUnregistered, tgerr.ErrSessionRevoked) {
		return nil, err
	}

	botToken := opt.BotToken
	if botToken == "" {
		botToken = client.config.BotToken
	}
	phone := opt.Phone
	if phone == "" {
		phone = client.config.Phone
	}
	if botToken != "" {
		return client.startBot(ctx, apiHash, botToken)
	}
	if phone != "" {
		phoneOpts := opt
		phoneOpts.Phone = phone
		return client.startUser(ctx, apiHash, phoneOpts)
	}
	return nil, ErrMissingCredentials
}

// GetMe returns the currently authorized user via users.getUsers([inputUserSelf]).
func (client *Client) GetMe(ctx context.Context) (*tl.User, error) {
	if client == nil {
		return nil, ErrNotConnected
	}
	users, err := Invoke(ctx, client, &tl.UsersGetUsersRequest{
		ID: []tl.InputUserClass{&tl.InputUserSelf{}},
	})
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("raw: users.getUsers returned no users")
	}
	user, ok := users[0].(*tl.User)
	if !ok {
		return nil, fmt.Errorf("raw: users.getUsers returned %T, want *tl.User", users[0])
	}
	return user, nil
}

func (client *Client) startBot(ctx context.Context, apiHash, botToken string) (*tl.User, error) {
	authorization, err := Invoke(ctx, client, &tl.AuthImportBotAuthorizationRequest{
		APIID:        client.config.APIID,
		APIHash:      apiHash,
		BotAuthToken: botToken,
	})
	if err != nil {
		return nil, err
	}
	auth, ok := authorization.(*tl.AuthAuthorization)
	if !ok {
		return nil, fmt.Errorf("raw: auth.importBotAuthorization returned %T", authorization)
	}
	user, ok := auth.User.(*tl.User)
	if !ok {
		return nil, fmt.Errorf("raw: authorization user is %T, want *tl.User", auth.User)
	}
	return user, nil
}

func (client *Client) startUser(ctx context.Context, apiHash string, opts StartOptions) (*tl.User, error) {
	if opts.Code == nil {
		return nil, fmt.Errorf("%w: StartOptions.Code is required for phone login", ErrInvalidConfig)
	}
	sentCode, err := Invoke(ctx, client, &tl.AuthSendCodeRequest{
		PhoneNumber: opts.Phone,
		APIID:       client.config.APIID,
		APIHash:     apiHash,
		Settings:    &tl.CodeSettings{},
	})
	if err != nil {
		return nil, err
	}
	if success, ok := sentCode.(*tl.AuthSentCodeSuccess); ok {
		auth, ok := success.Authorization.(*tl.AuthAuthorization)
		if !ok {
			return nil, fmt.Errorf("raw: sentCode authorization is %T", success.Authorization)
		}
		return userFromAuthorization(auth)
	}
	sent, ok := sentCode.(*tl.AuthSentCode)
	if !ok {
		return nil, fmt.Errorf("raw: auth.sendCode returned %T", sentCode)
	}

	code, err := opts.Code(ctx)
	if err != nil {
		return nil, fmt.Errorf("raw: code callback: %w", err)
	}
	authorization, err := Invoke(ctx, client, &tl.AuthSignInRequest{
		PhoneNumber:   opts.Phone,
		PhoneCodeHash: sent.PhoneCodeHash,
		PhoneCode:     &code,
	})
	if err != nil {
		if tgerr.Is(err, tgerr.ErrSessionPasswordNeeded) {
			if opts.Password == "" {
				return nil, ErrTwoFactorRequired
			}
			return nil, fmt.Errorf("%w: 2FA password flow is not implemented; use account.getPassword and auth.checkPassword", ErrTwoFactorRequired)
		}
		return nil, err
	}
	auth, ok := authorization.(*tl.AuthAuthorization)
	if !ok {
		return nil, fmt.Errorf("raw: auth.signIn returned %T", authorization)
	}
	return userFromAuthorization(auth)
}

func userFromAuthorization(auth *tl.AuthAuthorization) (*tl.User, error) {
	user, ok := auth.User.(*tl.User)
	if !ok {
		return nil, fmt.Errorf("raw: authorization user is %T, want *tl.User", auth.User)
	}
	return user, nil
}
