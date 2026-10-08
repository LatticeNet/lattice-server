package ddns

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
)

// DefaultCommentTemplate is written on a record when the profile has not
// chosen its own, so an operator browsing Cloudflare can tell which records
// Lattice maintains and for which node.
const DefaultCommentTemplate = "Lattice DDNS for #node#, #time#"

const (
	// MaxCommentTemplateBytes bounds what an operator may store as a template.
	MaxCommentTemplateBytes = 200
	// MaxCommentRunes is the Cloudflare Free plan's comment limit. Paid plans
	// allow 500, but a comment that fits Free fits everywhere.
	MaxCommentRunes = 100
)

// CommentPlaceholders are the names a comment template may use, in the #name#
// syntax the webhook provider's templates already take.
var CommentPlaceholders = []string{
	"#node#", "#node_id#", "#profile#", "#domain#", "#type#",
	"#ip#", "#old_ip#", "#time#", "#date#", "#lattice#",
}

var placeholderPattern = regexp.MustCompile(`#[A-Za-z0-9_]+#`)

// CommentVars are the values a template is rendered with. Domain, Type, IP and
// OldIP belong to one record, so the provider fills them in per write.
type CommentVars struct {
	Node    string
	NodeID  string
	Profile string
	Lattice string
	Time    time.Time
	Domain  string
	Type    string
	IP      string
	OldIP   string // the record's content before this write; empty on create
}

// Comment says what a record's comment should become. A Record without one
// leaves the record's comment exactly as it is.
type Comment struct {
	Template string
	Vars     CommentVars
	// Refresh rewrites the comment even when the record already holds the
	// address, so a template the operator just changed applies on "Run now".
	Refresh bool
}

func (c *Comment) render(r Record, oldIP string) string {
	v := c.Vars
	v.Domain, v.Type, v.IP, v.OldIP = r.Name, r.Type, r.IP, oldIP
	return RenderComment(c.Template, v)
}

// CommentTemplateFor returns the template a profile's records carry, and false
// when the profile asked Lattice never to set or change the comment. An empty
// or unknown mode is the default mode, which is what a profile saved before
// comments existed gets.
func CommentTemplateFor(p model.DDNSProfile) (string, bool) {
	switch strings.TrimSpace(p.CommentMode) {
	case model.DDNSCommentNone:
		return "", false
	case model.DDNSCommentCustom:
		if strings.TrimSpace(p.RecordComment) != "" {
			return p.RecordComment, true
		}
	}
	return DefaultCommentTemplate, true
}

// ValidateCommentSettings checks a profile's comment fields before they are
// stored. Only a custom template is checked, because only a custom template is
// ever rendered; text left in the field while another mode is selected is kept
// so switching back restores it.
func ValidateCommentSettings(p model.DDNSProfile) error {
	switch strings.TrimSpace(p.CommentMode) {
	case "", model.DDNSCommentDefault, model.DDNSCommentNone:
		return nil
	case model.DDNSCommentCustom:
		if strings.TrimSpace(p.RecordComment) == "" {
			return errors.New("record_comment is required when comment_mode is custom")
		}
		return ValidateCommentTemplate(p.RecordComment)
	default:
		return fmt.Errorf("comment_mode must be default, custom or none, not %q", p.CommentMode)
	}
}

// ValidateCommentTemplate rejects a template Cloudflare could not store or
// Lattice could not render: one with a line break, one longer than
// MaxCommentTemplateBytes, or one naming a placeholder that does not exist.
func ValidateCommentTemplate(tmpl string) error {
	if strings.ContainsAny(tmpl, "\r\n") {
		return errors.New("record_comment must be a single line")
	}
	if len(tmpl) > MaxCommentTemplateBytes {
		return fmt.Errorf("record_comment is %d bytes; the limit is %d", len(tmpl), MaxCommentTemplateBytes)
	}
	allowed := make(map[string]bool, len(CommentPlaceholders))
	for _, name := range CommentPlaceholders {
		allowed[name] = true
	}
	for _, found := range placeholderPattern.FindAllString(tmpl, -1) {
		if !allowed[found] {
			return fmt.Errorf("record_comment uses unknown placeholder %s; allowed: %s", found, strings.Join(CommentPlaceholders, ", "))
		}
	}
	return nil
}

// RenderComment fills a template and returns a single line of at most
// MaxCommentRunes characters, cut on a character boundary.
func RenderComment(tmpl string, v CommentVars) string {
	when := v.Time.UTC()
	rep := strings.NewReplacer(
		"#node#", v.Node,
		"#node_id#", v.NodeID,
		"#profile#", v.Profile,
		"#domain#", v.Domain,
		"#type#", v.Type,
		"#ip#", v.IP,
		"#old_ip#", v.OldIP,
		"#time#", when.Format("2006-01-02 15:04")+"Z",
		"#date#", when.Format("2006-01-02"),
		"#lattice#", v.Lattice,
	)
	out := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, rep.Replace(tmpl))
	out = strings.TrimSpace(out)
	if utf8.RuneCountInString(out) > MaxCommentRunes {
		out = strings.TrimSpace(string([]rune(out)[:MaxCommentRunes]))
	}
	return out
}
