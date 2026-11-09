# passport-magiclink

Passwordless login by email link for [`passport`](https://github.com/shibisty/passport.go).
Go package: `magiclink`.

## Installation

```bash
gtr add github:shibisty/passport.go github:shibisty/passport.go-magiclink-strategy
```

## Usage

```go
ml := magiclink.New(magiclink.NewMemoryStore(), "https://app.example.com/auth/magic",
    func(ctx context.Context, email, link string) error { return mailer.Send(ctx, email, link) })
a.Use(ml)

// POST /auth/magic/send (put httpauth.LimitLogin in front)
err := ml.Send(ctx, r.PostFormValue("email"))

// GET /auth/magic?token=…
id, err := a.Credential(ctx, "magiclink", map[string]string{"token": r.URL.Query().Get("token")})
```

- A link carries 32 random bytes; the store keeps their SHA-256, the email and the
  expiry (15 minutes, `WithTTL`). `Take` removes the record atomically: a link works once,
  even with concurrent clicks.
- The Identity has the normalized email as `ProviderUserID` and `EmailVerified: true`.
- `Store` is two methods; `MemoryStore` is for one instance (implement it on a table or
  Redis for several).
- Always answer the "send" request the same way, whether the email is known or not.

## License

MIT
