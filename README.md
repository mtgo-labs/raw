# raw

High-performance, low-level Go MTProto 2.0 client library for Telegram.

```go
client, _ := raw.NewClient(raw.Config{
    SessionString: "...",
    InMemory:      true,
})
client.Connect(ctx)
user, _ := raw.Invoke(ctx, client, &tl.UsersGetUsersRequest{
    ID: []tl.InputUserClass{&tl.InputUserSelf{}},
})
```

## Features

- Full MTProto 2.0 protocol: encrypted transport, auth key negotiation, session management
- Zero-allocation AES-256-IGE encryption
- Compile-time typed TL schema with generated encode/decode (layer 228)
- Intermediate, abridged, padded, and obfuscated transports
- TCP_NODELAY enabled by default
- Connection pooling, reconnect, DC migration, PFS temporary keys
- Import session strings from Pyrogram, Telethon, and other formats

## Install

```
go get github.com/mtgo-labs/raw
```

## Quick start

```go
package main

import (
    "context"
    "fmt"

    raw "github.com/mtgo-labs/raw"
    "github.com/mtgo-labs/raw/tl"
)

func main() {
    ctx := context.Background()

    client, err := raw.NewClient(raw.Config{
        SessionString: "your-session-string",
        InMemory:      true,
    })
    if err != nil {
        panic(err)
    }
    defer client.Close()

    if err := client.Connect(ctx); err != nil {
        panic(err)
    }

    users, err := raw.Invoke(ctx, client, &tl.UsersGetUsersRequest{
        ID: []tl.InputUserClass{&tl.InputUserSelf{}},
    })
    if err != nil {
        panic(err)
    }

    for _, user := range users {
        if u, ok := user.(*tl.User); ok {
            fmt.Println(u.FirstName)
        }
    }
}
```

## License

Apache-2.0
