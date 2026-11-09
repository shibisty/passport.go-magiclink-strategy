package magiclink_test

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"passport"
	magiclink "passport-magiclink"
)

var ctx = context.Background()

func TestLink(t *testing.T) {
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	var sent string
	ml := magiclink.New(magiclink.NewMemoryStore(), "https://app/magic?src=mail", func(_ context.Context, email, link string) error {
		sent = link
		return nil
	}, magiclink.WithClock(func() time.Time { return now }), magiclink.WithTTL(10*time.Minute))
	if ml.Name() != "magiclink" {
		t.Fatal("Name")
	}
	if err := ml.Send(ctx, "  Ann@Example.com "); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(sent)
	tok := u.Query().Get("token")
	if u.Query().Get("src") != "mail" || len(tok) != 43 {
		t.Fatalf("link %s", sent)
	}
	id, err := ml.Authenticate(ctx, map[string]string{"token": tok})
	if err != nil || id.Email != "ann@example.com" || !id.EmailVerified || id.Provider != "magiclink" {
		t.Fatalf("%+v %v", id, err)
	}
	if _, err := ml.Authenticate(ctx, map[string]string{"token": tok}); !errors.Is(err, passport.ErrInvalidCredentials) {
		t.Fatalf("second use: %v", err)
	}
	ml.Send(ctx, "bob@x.io")
	u, _ = url.Parse(sent)
	now = now.Add(11 * time.Minute)
	if _, err := ml.Authenticate(ctx, map[string]string{"token": u.Query().Get("token")}); !errors.Is(err, passport.ErrInvalidCredentials) {
		t.Fatalf("expired: %v", err)
	}
	for _, bad := range []string{"", "not an email", "a@b@c", "Ann <ann@x.io>"} {
		if err := ml.Send(ctx, bad); err == nil {
			t.Errorf("Send(%q) accepted", bad)
		}
	}
	if _, err := ml.Authenticate(ctx, map[string]string{"token": "short"}); !errors.Is(err, passport.ErrInvalidCredentials) {
		t.Fatal("short token")
	}
}

type failStore struct{ save, take error }

func (f failStore) Save(context.Context, string, string, time.Time) error { return f.save }
func (f failStore) Take(context.Context, string) (string, time.Time, error) {
	return "", time.Time{}, f.take
}

func TestErrors(t *testing.T) {
	boom := errors.New("boom")
	noSend := func(context.Context, string, string) error { return nil }
	if err := magiclink.New(failStore{save: boom}, "https://a/m", noSend).Send(ctx, "a@b.io"); !errors.Is(err, boom) {
		t.Fatalf("save: %v", err)
	}
	if _, err := magiclink.New(failStore{take: boom}, "https://a/m", noSend).Authenticate(ctx, map[string]string{"token": "0123456789012345678901234567890123456789012"}); !errors.Is(err, boom) {
		t.Fatalf("take: %v", err)
	}
	mailErr := errors.New("smtp")
	if err := magiclink.New(magiclink.NewMemoryStore(), "https://a/m", func(context.Context, string, string) error { return mailErr }).Send(ctx, "a@b.io"); !errors.Is(err, mailErr) {
		t.Fatalf("send: %v", err)
	}
}

// One link, many concurrent clicks: one login.
func TestConcurrentUse(t *testing.T) {
	var link string
	ml := magiclink.New(magiclink.NewMemoryStore(), "https://a/m", func(_ context.Context, _, l string) error { link = l; return nil })
	ml.Send(ctx, "a@b.io")
	u, _ := url.Parse(link)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ml.Authenticate(ctx, map[string]string{"token": u.Query().Get("token")}); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d logins", ok)
	}
	// Expired links are swept on Save.
	s := magiclink.NewMemoryStore()
	s.Save(ctx, "old", "a@b", time.Now().Add(-time.Second))
	s.Save(ctx, "new", "a@b", time.Now().Add(time.Hour))
	if _, _, err := s.Take(ctx, "old"); !errors.Is(err, magiclink.ErrNotFound) {
		t.Fatal("expired link kept")
	}
}
