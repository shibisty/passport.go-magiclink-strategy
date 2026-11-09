// Package magiclink logs users in with a one-time link sent by email.
// gtr package: passport-magiclink.
//
//	ml := magiclink.New(magiclink.NewMemoryStore(), "https://app.example.com/auth/magic",
//	    func(ctx context.Context, email, link string) error { return mailer.Send(ctx, email, link) })
//	a.Use(ml)
//
//	// POST /auth/magic/send       (behind httpauth.LimitLogin)
//	err := ml.Send(ctx, r.PostFormValue("email"))
//	// GET /auth/magic?token=...
//	identity, err := a.Credential(ctx, "magiclink", map[string]string{"token": r.URL.Query().Get("token")})
//
// A link holds 32 random bytes; the store keeps only their SHA-256, with the
// email and the expiry (15 minutes by default). It works once: Take removes
// it atomically. The Identity has the email as ProviderUserID and
// EmailVerified = true (the user proved access to the mailbox): map it to
// your user, or create one.
package magiclink

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	"passport"
)

// DefaultTTL is how long a link works.
const DefaultTTL = 15 * time.Minute

// ErrNotFound is returned by a Store for a missing record.
var ErrNotFound = errors.New("magiclink: not found")

// Store keeps pending links by the hash of their token.
type Store interface {
	Save(ctx context.Context, hash, email string, expires time.Time) error
	// Take returns and deletes a record in one step (ErrNotFound if none),
	// so a link cannot be used twice even by concurrent requests.
	Take(ctx context.Context, hash string) (email string, expires time.Time, err error)
}

// SendFunc delivers the link (an email, usually).
type SendFunc func(ctx context.Context, email, link string) error

// Strategy is the "magiclink" passport.CredentialStrategy.
type Strategy struct {
	store   Store
	baseURL string
	send    SendFunc
	ttl     time.Duration
	now     func() time.Time
}

// Option changes strategy settings.
type Option func(*Strategy)

// WithTTL sets how long a link works (DefaultTTL).
func WithTTL(d time.Duration) Option { return func(s *Strategy) { s.ttl = d } }

// WithClock replaces the clock (tests).
func WithClock(now func() time.Time) Option { return func(s *Strategy) { s.now = now } }

// New makes the strategy; links are baseURL?token=<token>.
func New(store Store, baseURL string, send SendFunc, opts ...Option) *Strategy {
	s := &Strategy{store: store, baseURL: baseURL, send: send, ttl: DefaultTTL, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Name is "magiclink".
func (s *Strategy) Name() string { return "magiclink" }

// Send makes a link for email and delivers it. The email is normalized
// (trimmed, lower-cased) and must parse as an address.
func (s *Strategy) Send(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if a, err := mail.ParseAddress(email); err != nil || a.Address != email {
		return fmt.Errorf("magiclink: invalid email %q", email)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	if err := s.store.Save(ctx, hash(token), email, s.now().Add(s.ttl)); err != nil {
		return err
	}
	sep := "?"
	if strings.Contains(s.baseURL, "?") {
		sep = "&"
	}
	return s.send(ctx, email, s.baseURL+sep+"token="+url.QueryEscape(token))
}

// Authenticate expects credentials{"token": token from the link}.
func (s *Strategy) Authenticate(ctx context.Context, credentials map[string]string) (*passport.Identity, error) {
	token := credentials["token"]
	if len(token) != 43 {
		return nil, passport.ErrInvalidCredentials
	}
	email, expires, err := s.store.Take(ctx, hash(token))
	if errors.Is(err, ErrNotFound) {
		return nil, passport.ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if !s.now().Before(expires) {
		return nil, passport.ErrInvalidCredentials
	}
	return &passport.Identity{Provider: "magiclink", ProviderUserID: email, Email: email, EmailVerified: true}, nil
}

func hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// MemoryStore is an in-process Store (one instance; links are lost on restart).
type MemoryStore struct {
	mu    sync.Mutex
	items map[string]memItem
}

type memItem struct {
	email   string
	expires time.Time
}

// NewMemoryStore makes an empty MemoryStore.
func NewMemoryStore() *MemoryStore { return &MemoryStore{items: map[string]memItem{}} }

func (m *MemoryStore) Save(_ context.Context, h, email string, expires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, it := range m.items { // drop expired links as new ones come
		if !now.Before(it.expires) {
			delete(m.items, k)
		}
	}
	m.items[h] = memItem{email, expires}
	return nil
}

func (m *MemoryStore) Take(_ context.Context, h string) (string, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.items[h]
	if !ok {
		return "", time.Time{}, ErrNotFound
	}
	delete(m.items, h)
	return it.email, it.expires, nil
}

var (
	_ passport.CredentialStrategy = (*Strategy)(nil)
	_ Store                       = (*MemoryStore)(nil)
)
