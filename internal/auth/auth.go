package auth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	hashScheme = "pbkdf2-sha256"
	iterations = 210_000
	keyLength  = 32
)

type Session struct {
	ID        string
	ActorID   string
	CSRFToken string
	CreatedAt time.Time
	ExpiresAt time.Time
	Revoked   bool
}

func NewRandomToken(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func HashSecret(secret string) (string, error) {
	if len(secret) < 12 {
		return "", errors.New("secret must be at least 12 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, secret, salt, iterations, keyLength)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s$%d$%s$%s",
		hashScheme,
		iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func VerifySecret(encoded, secret string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return false
	}
	var iter int
	if _, err := fmt.Sscanf(parts[1], "%d", &iter); err != nil || iter <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	actual, err := pbkdf2.Key(sha256.New, secret, salt, iter, len(expected))
	if err != nil {
		return false
	}
	return hmac.Equal(actual, expected)
}

func NewSession(actorID string, ttl time.Duration) (Session, error) {
	id, err := NewRandomToken(32)
	if err != nil {
		return Session{}, err
	}
	csrf, err := NewRandomToken(32)
	if err != nil {
		return Session{}, err
	}
	now := time.Now().UTC()
	return Session{
		ID:        id,
		ActorID:   actorID,
		CSRFToken: csrf,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}, nil
}

func (s Session) Active(now time.Time) bool {
	return !s.Revoked && !s.ExpiresAt.Before(now)
}
