package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/LatticeNet/lattice-sdk/model"
)

func subStoreSvcDecrypt(t *testing.T, body []byte, identity age.Identity) string {
	t.Helper()
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(body)), identity)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(plain)
}

// A share with a recipient is served as an armored age file that the
// recipient's identity decrypts to the rendered document. The plaintext
// reaches neither the cache, the log nor the audit trail.
func TestSubStoreAgeShareDecryptsWithRecipientIdentity(t *testing.T) {
	h := newSubStoreSvcHarness(t)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	row := h.createShare(t, `{"subscription_id":"rec","slug":"sealed","age_recipient":"`+identity.Recipient().String()+`"}`)
	if row.AgeRecipient != identity.Recipient().String() {
		t.Fatalf("row age_recipient = %q", row.AgeRecipient)
	}
	share, _ := h.st.SubscriptionShare(row.ShareID)
	path := "/sub/sealed/" + share.Token

	res := h.fetch(path)
	if res.Code != http.StatusOK {
		t.Fatalf("status %d", res.Code)
	}
	body := res.Body.Bytes()
	if !bytes.HasPrefix(body, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) || bytes.Contains(body, []byte("PLAINTEXT-MARKER")) {
		t.Fatalf("the body is not an armored age file: %q", body)
	}
	if got := res.Header().Get("Content-Type"); got != subStoreSvcAgeWireType {
		t.Fatalf("content type %q", got)
	}
	if plain := subStoreSvcDecrypt(t, body, identity); plain != h.body {
		t.Fatalf("decrypted %q, want %q", plain, h.body)
	}
	// Another identity cannot read it.
	other, _ := age.GenerateX25519Identity()
	if _, err := age.Decrypt(armor.NewReader(bytes.NewReader(body)), other); err == nil {
		t.Fatal("a different identity decrypted the share")
	}

	// The cached body is the ciphertext. Every encryption draws a fresh file
	// key, so the second fetch returning the same bytes under the same
	// validator means it came from the cache, which therefore holds the
	// ciphertext and not the document.
	again := h.fetch(path)
	if !bytes.Equal(again.Body.Bytes(), body) || again.Header().Get("ETag") == "" || again.Header().Get("ETag") != res.Header().Get("ETag") {
		t.Fatal("the cached body is not the ciphertext served first")
	}
	if strings.Contains(h.log.String(), "PLAINTEXT-MARKER") {
		t.Fatalf("the plaintext reached the log: %s", h.log.String())
	}
	for _, ev := range h.st.AuditEvents() {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), "PLAINTEXT-MARKER") {
			t.Fatalf("the plaintext reached the audit trail: %s", raw)
		}
	}
}

// Changing the recipient re-encrypts for the new one at once, and clearing
// it serves the document in the clear again.
func TestSubStoreAgeRecipientChangeReencrypts(t *testing.T) {
	h := newSubStoreSvcHarness(t)
	first, _ := age.GenerateX25519Identity()
	second, _ := age.GenerateX25519Identity()
	row := h.createShare(t, `{"subscription_id":"rec","slug":"sealed","age_recipient":"`+first.Recipient().String()+`"}`)
	share, _ := h.st.SubscriptionShare(row.ShareID)
	path := "/sub/sealed/" + share.Token
	if plain := subStoreSvcDecrypt(t, h.fetch(path).Body.Bytes(), first); plain != h.body {
		t.Fatalf("first recipient read %q", plain)
	}

	h.mustCall(t, subStoreSharesService, "update", `{"share_id":"`+row.ShareID+`","age_recipient":"`+second.Recipient().String()+`"}`)
	body := h.fetch(path).Body.Bytes()
	if _, err := age.Decrypt(armor.NewReader(bytes.NewReader(body)), first); err == nil {
		t.Fatal("the old recipient still reads the share after the change")
	}
	if plain := subStoreSvcDecrypt(t, body, second); plain != h.body {
		t.Fatalf("second recipient read %q", plain)
	}
	if evs := h.auditFor(auditActionShareUpdate, row.ShareID); len(evs) != 1 || evs[0].Metadata["age"] != "set" {
		t.Fatalf("recipient change audit = %+v", evs)
	}

	h.mustCall(t, subStoreSharesService, "update", `{"share_id":"`+row.ShareID+`","age_recipient":""}`)
	if res := h.fetch(path); res.Body.String() != h.body {
		t.Fatalf("a cleared recipient still serves ciphertext: %q", res.Body.String())
	}
}

// A stored recipient that no longer parses fails closed: the decoy, never
// the plaintext.
func TestSubStoreAgeEncryptionFailsClosed(t *testing.T) {
	h := newSubStoreSvcHarness(t)
	row := h.createShare(t, `{"subscription_id":"rec","slug":"broken"}`)
	share, _ := h.st.SubscriptionShare(row.ShareID)
	share.Extra = map[string]json.RawMessage{subStoreSvcShareExtraAgeRecipient: json.RawMessage(`"age1notarecipient"`)}
	mustUpsertShare(t, h.st, share)

	res := h.fetch("/sub/broken/" + share.Token)
	unknown := h.fetch("/sub/broken/" + strings.Repeat("z", len(share.Token)))
	if res.Code != unknown.Code || res.Body.String() != unknown.Body.String() || strings.Contains(res.Body.String(), "PLAINTEXT-MARKER") {
		t.Fatalf("a share whose recipient does not parse answered %d %q", res.Code, res.Body.String())
	}
	if strings.Contains(h.log.String(), "PLAINTEXT-MARKER") {
		t.Fatal("the plaintext reached the log")
	}
}

// Only an X25519 recipient is stored, in canonical form. A pasted secret key
// is refused, and the refusal never repeats it.
func TestSubStoreAgeRecipientValidation(t *testing.T) {
	h := newSubStoreSvcHarness(t)
	identity, _ := age.GenerateX25519Identity()
	secretKey := identity.String()
	_, err := h.call(subStoreSvcAdmin, subStoreSharesService, "create", `{"subscription_id":"rec","slug":"oops","age_recipient":"`+secretKey+`"}`)
	if subStoreSvcErrStatus(err) != http.StatusBadRequest || !strings.Contains(subStoreSvcErrBody(err), "secret key") {
		t.Fatalf("a secret key as recipient: %v %s", err, subStoreSvcErrBody(err))
	}
	if strings.Contains(subStoreSvcErrBody(err), secretKey) || strings.Contains(subStoreSvcErrBody(err), secretKey[15:]) {
		t.Fatal("the refusal repeats the secret key")
	}
	for _, bad := range []string{"age1", "ssh-ed25519 AAAA", strings.Repeat("a", 200), "age1pq1" + strings.Repeat("q", 60)} {
		if _, err := subStoreSvcParseAgeRecipient(bad); err == nil {
			t.Fatalf("recipient %q was accepted", bad)
		}
	}
	canonical, err := subStoreSvcParseAgeRecipient("  " + identity.Recipient().String() + "\n")
	if err != nil || canonical != identity.Recipient().String() {
		t.Fatalf("canonical = %q, %v", canonical, err)
	}
	for _, ev := range h.st.AuditEvents() {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), secretKey[15:]) {
			t.Fatal("the audit trail holds the secret key")
		}
	}
}

// subStoreAgeEncrypt is the step the artifact path calls: a round trip for
// the recipient, a fixed error otherwise.
func TestSubStoreAgeEncryptRoundTrip(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	plaintext := bytes.Repeat([]byte("vless://PLAINTEXT-MARKER@node.example:443\n"), 4000)
	sealed, err := subStoreAgeEncrypt(identity.Recipient().String(), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if got := subStoreSvcDecrypt(t, sealed, identity); got != string(plaintext) {
		t.Fatal("round trip changed the document")
	}
	if _, err := subStoreAgeEncrypt("not-a-recipient", plaintext); err == nil || strings.Contains(err.Error(), "PLAINTEXT") {
		t.Fatalf("a bad recipient: %v", err)
	}
	// A share with no recipient keeps its cache key and its body.
	share := model.SubscriptionShare{ID: "s"}
	if token := subStoreSvcAgeCacheToken(share, "t=URI"); token != "t=URI" {
		t.Fatalf("cache token changed for a share with no recipient: %q", token)
	}
	if body, sealed, err := subStoreSvcSealShareBody(share, plaintext); err != nil || sealed || !bytes.Equal(body, plaintext) {
		t.Fatal("a share with no recipient was encrypted")
	}
}

// A render that started before the recipient changed publishes under the
// old recipient's cache key, so the next fetch never serves the body it
// encrypted for the old recipient.
func TestSubStoreAgeInFlightRenderDoesNotOutliveRecipientChange(t *testing.T) {
	h := newSubStoreSvcHarness(t)
	first, _ := age.GenerateX25519Identity()
	second, _ := age.GenerateX25519Identity()
	row := h.createShare(t, `{"subscription_id":"rec","slug":"sealed","age_recipient":"`+first.Recipient().String()+`"}`)
	share, _ := h.st.SubscriptionShare(row.ShareID)
	path := "/sub/sealed/" + share.Token

	started, release := make(chan struct{}), make(chan struct{})
	render := h.srv.subscriptionRender
	var once sync.Once
	h.srv.subscriptionRender = func(ctx context.Context, s model.SubscriptionShare, format, ua string, v shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		blocked := false
		once.Do(func() { blocked = true })
		if blocked {
			close(started)
			<-release
		}
		return render(ctx, s, format, ua, v, snap)
	}
	done := make(chan []byte)
	go func() { done <- h.fetch(path).Body.Bytes() }()
	<-started
	h.mustCall(t, subStoreSharesService, "update", `{"share_id":"`+row.ShareID+`","age_recipient":"`+second.Recipient().String()+`"}`)
	close(release)
	if plain := subStoreSvcDecrypt(t, <-done, first); plain != h.body {
		t.Fatalf("the request that started first read %q", plain)
	}

	body := h.fetch(path).Body.Bytes()
	if _, err := age.Decrypt(armor.NewReader(bytes.NewReader(body)), first); err == nil {
		t.Fatal("a body encrypted for the old recipient was served after the change")
	}
	if plain := subStoreSvcDecrypt(t, body, second); plain != h.body {
		t.Fatalf("the new recipient read %q", plain)
	}
}
