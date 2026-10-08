package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/LatticeNet/lattice-sdk/model"
)

// Per-share age encryption (design 28, "Share serving and tokens"). A share
// that names an age recipient is served as an armored age file for that
// recipient instead of the plain document. The core encrypts, because the
// core is where the final body is, and for a fleet-bound record it is the
// only place the bound document ever exists: the plugin cannot encrypt what
// it never holds. The share stores the recipient's public key only; the key
// pair is generated client-side or revealed once and never stored.
//
// The rendered plaintext is encrypted before it enters the body cache, so a
// cached body is ciphertext, and the plaintext is never logged: every error
// below is a fixed message that carries neither the body nor the key.

const (
	// subStoreSvcShareExtraAgeRecipient stores a share's age recipient.
	//
	// yagni: the pinned SDK's SubscriptionShare has no field for it, so the
	// value rides in the share's Extra map, as update_interval_hours does.
	// Upgrade path: add AgeRecipient `json:"age_recipient,omitempty"` to the
	// SDK model and read the field; stored values decode into it unchanged.
	subStoreSvcShareExtraAgeRecipient = "age_recipient"

	// subStoreSvcMaxAgeRecipientBytes bounds a recipient before it is
	// parsed. An X25519 recipient is 62 bytes.
	subStoreSvcMaxAgeRecipientBytes = 128

	// subStoreSvcAgeWireType is the content type of an encrypted body: an
	// armored age file is ASCII text whatever the document inside it is.
	subStoreSvcAgeWireType = "text/plain; charset=utf-8"
)

// errSubStoreSvcAgeSecretKey refuses a value that is an age identity. Its
// message never quotes the value: an operator who pasted the secret half of
// the pair must not find it in an error, a log or the audit trail.
var errSubStoreSvcAgeSecretKey = errors.New("age_recipient is an age secret key; give the recipient (the public key starting age1), and keep the secret key off the server")

// subStoreSvcParseAgeRecipient validates an age recipient and returns its
// canonical form. Only X25519 recipients (age1...) are accepted. The parser's
// own error quotes its input, so it is replaced by a fixed message.
//
// yagni: filippo.io/age v1.2.1 has no post-quantum hybrid recipients
// (age1pq1...), which v1.3 adds; those are refused here until the module
// moves, which keeps this change from bumping golang.org/x/crypto.
func subStoreSvcParseAgeRecipient(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToUpper(value), "AGE-SECRET-KEY-") {
		return "", errSubStoreSvcAgeSecretKey
	}
	if value == "" || len(value) > subStoreSvcMaxAgeRecipientBytes {
		return "", errors.New("age_recipient must be an X25519 age recipient (age1...)")
	}
	recipient, err := age.ParseX25519Recipient(value)
	if err != nil {
		return "", errors.New("age_recipient must be an X25519 age recipient (age1...)")
	}
	return recipient.String(), nil
}

// subStoreSvcShareAgeRecipient is the recipient a share is encrypted for, or
// "" when it is served in the clear. A stored value that no longer parses is
// returned as is, so encryption fails closed rather than serving plaintext.
func subStoreSvcShareAgeRecipient(share model.SubscriptionShare) string {
	raw, ok := share.Extra[subStoreSvcShareExtraAgeRecipient]
	if !ok {
		return ""
	}
	var recipient string
	if err := json.Unmarshal(raw, &recipient); err != nil {
		// Present but unreadable is not "no recipient": serving the
		// plaintext would be the wrong way to fail.
		return string(raw)
	}
	return recipient
}

// subStoreSvcWithAgeRecipient returns the share with its recipient set, or
// cleared for "". The Extra map is copied, never edited in place: it is
// shared with the store's copy of the record.
func subStoreSvcWithAgeRecipient(share model.SubscriptionShare, recipient string) model.SubscriptionShare {
	extra := make(map[string]json.RawMessage, len(share.Extra)+1)
	for k, v := range share.Extra {
		extra[k] = v
	}
	if recipient == "" {
		delete(extra, subStoreSvcShareExtraAgeRecipient)
	} else {
		encoded, _ := json.Marshal(recipient)
		extra[subStoreSvcShareExtraAgeRecipient] = encoded
	}
	if len(extra) == 0 {
		extra = nil
	}
	share.Extra = extra
	return share
}

// subStoreSvcAgeCacheToken extends a cache key's variant token with the
// recipient's fingerprint. An encrypted body is cached under a key that names
// its recipient, so a body encrypted for one recipient (or rendered in the
// clear) is never served after the recipient changes, even when a render that
// started before the change publishes after it. A share with no recipient
// keeps its key byte for byte.
func subStoreSvcAgeCacheToken(share model.SubscriptionShare, token string) string {
	recipient := subStoreSvcShareAgeRecipient(share)
	if recipient == "" {
		return token
	}
	sum := sha256.Sum256([]byte(recipient))
	mark := "age=" + hex.EncodeToString(sum[:8])
	if token == "" {
		return mark
	}
	return token + ";" + mark
}

// subStoreAgeEncrypt encrypts plaintext for one X25519 recipient as an
// armored age file. It is the one encryption step for every core-rendered
// Sub-Store body: the share serve path calls it today, and the artifact
// render path of the operator-surface slice calls it before handing the
// ciphertext to the plugin's publish. Its errors are fixed messages and never
// carry the plaintext or the recipient.
func subStoreAgeEncrypt(recipient string, plaintext []byte) ([]byte, error) {
	parsed, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return nil, errors.New("age encryption: the share's recipient does not parse")
	}
	var out bytes.Buffer
	// Armor adds about a third for base64 plus a header and footer; age
	// adds a header and 16 bytes per 64 KiB chunk.
	out.Grow(len(plaintext)*4/3 + 512)
	armored := armor.NewWriter(&out)
	w, err := age.Encrypt(armored, parsed)
	if err != nil {
		return nil, errors.New("age encryption: could not start")
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, errors.New("age encryption: could not write")
	}
	if err := w.Close(); err != nil {
		return nil, errors.New("age encryption: could not finish")
	}
	if err := armored.Close(); err != nil {
		return nil, errors.New("age encryption: could not finish the armor")
	}
	return out.Bytes(), nil
}

// subStoreSvcSealShareBody encrypts a rendered body when the share names a
// recipient. It returns the body to cache and serve, and whether it was
// encrypted. A share with no recipient gets its body back unchanged.
func subStoreSvcSealShareBody(share model.SubscriptionShare, body []byte) ([]byte, bool, error) {
	recipient := subStoreSvcShareAgeRecipient(share)
	if recipient == "" {
		return body, false, nil
	}
	sealed, err := subStoreAgeEncrypt(recipient, body)
	if err != nil {
		return nil, false, err
	}
	return sealed, true, nil
}
