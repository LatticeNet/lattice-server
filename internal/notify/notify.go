// Package notify delivers short operational messages (SSH login alerts, audit
// denials, task failures) to one or more user-configured channels. It is
// deliberately dependency-free: every channel is a plain HTTPS POST built on
// the standard library, so the server keeps its zero-dependency footprint.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-server/internal/outbound"
)

// Message is a channel-agnostic notification.
type Message struct {
	Title string
	Body  string
}

// Channel delivers a Message to a single destination.
type Channel interface {
	Kind() string
	Send(ctx context.Context, m Message) error
}

// Result records the outcome of sending to one channel.
type Result struct {
	Kind string
	Err  error
}

// Dispatcher fans a message out to every configured channel, isolating failures
// so one broken channel does not suppress the others.
type Dispatcher struct {
	channels []Channel
}

func NewDispatcher(channels ...Channel) *Dispatcher {
	return &Dispatcher{channels: channels}
}

// Send delivers m to all channels and returns a per-channel result slice. The
// call itself never errors; inspect the results for per-channel failures.
func (d *Dispatcher) Send(ctx context.Context, m Message) []Result {
	results := make([]Result, 0, len(d.channels))
	for _, ch := range d.channels {
		results = append(results, Result{Kind: ch.Kind(), Err: ch.Send(ctx, m)})
	}
	return results
}

func defaultClient() *http.Client { return outbound.NewClient(10 * time.Second) }

// postForm/postJSON helpers share consistent timeout and status handling.
func doRequest(ctx context.Context, client *http.Client, req *http.Request) error {
	if client == nil {
		client = defaultClient()
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("notify: upstream status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// Telegram posts via the Bot API sendMessage method.
type Telegram struct {
	Token   string
	ChatID  string
	BaseURL string // defaults to https://api.telegram.org
	Client  *http.Client
}

func (t Telegram) Kind() string { return "telegram" }

func (t Telegram) Send(ctx context.Context, m Message) error {
	if t.Token == "" || t.ChatID == "" {
		return fmt.Errorf("telegram: token and chat_id are required")
	}
	base := t.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	form := url.Values{}
	form.Set("chat_id", t.ChatID)
	form.Set("text", joinTitleBody(m))
	endpoint := fmt.Sprintf("%s/bot%s/sendMessage", strings.TrimRight(base, "/"), t.Token)
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return doRequest(ctx, t.Client, req)
}

// Bark posts to a Bark server (iOS push). URL form: <base>/<key>/<title>/<body>.
type Bark struct {
	BaseURL string // e.g. https://api.day.app
	Key     string
	Client  *http.Client
}

func (b Bark) Kind() string { return "bark" }

func (b Bark) Send(ctx context.Context, m Message) error {
	if b.BaseURL == "" || b.Key == "" {
		return fmt.Errorf("bark: base_url and key are required")
	}
	endpoint := fmt.Sprintf("%s/%s/%s/%s",
		strings.TrimRight(b.BaseURL, "/"), b.Key,
		url.PathEscape(orDefault(m.Title, "Lattice")), url.PathEscape(m.Body))
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	return doRequest(ctx, b.Client, req)
}

// Discord posts to an incoming webhook URL.
type Discord struct {
	WebhookURL string
	Client     *http.Client
}

func (d Discord) Kind() string { return "discord" }

func (d Discord) Send(ctx context.Context, m Message) error {
	if d.WebhookURL == "" {
		return fmt.Errorf("discord: webhook_url is required")
	}
	payload, _ := json.Marshal(map[string]string{"content": joinTitleBody(m)})
	req, err := http.NewRequest(http.MethodPost, d.WebhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return doRequest(ctx, d.Client, req)
}

// Webhook posts a generic JSON document {title, body} to an arbitrary URL.
type Webhook struct {
	URL    string
	Client *http.Client
}

func (h Webhook) Kind() string { return "webhook" }

func (h Webhook) Send(ctx context.Context, m Message) error {
	if h.URL == "" {
		return fmt.Errorf("webhook: url is required")
	}
	payload, _ := json.Marshal(map[string]string{"title": m.Title, "body": m.Body})
	req, err := http.NewRequest(http.MethodPost, h.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return doRequest(ctx, h.Client, req)
}

func joinTitleBody(m Message) string {
	if m.Title == "" {
		return m.Body
	}
	if m.Body == "" {
		return m.Title
	}
	return m.Title + "\n" + m.Body
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
