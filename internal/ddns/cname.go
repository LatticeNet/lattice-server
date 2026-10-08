package ddns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// MaxHostnameBytes is the longest name DNS can carry, written without the
// trailing dot.
const MaxHostnameBytes = 253

// IsCNAME reports whether a profile publishes a CNAME rather than its node's
// addresses. An empty or unknown type is the address type, which is what a
// profile saved before record types existed gets.
func IsCNAME(p model.DDNSProfile) bool {
	return strings.TrimSpace(p.RecordType) == model.DDNSRecordCNAME
}

// NormalizeHost is the form a hostname is compared and stored in: trimmed,
// lower case, without the trailing dot of a fully qualified name.
func NormalizeHost(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// ValidateRecordSettings checks a profile's record type and CNAME target
// before they are stored. The target is checked only for a CNAME profile; a
// target left in the field while the address type is selected is kept, so
// switching back restores it. The target is expected in NormalizeHost form.
func ValidateRecordSettings(p model.DDNSProfile) error {
	switch strings.TrimSpace(p.RecordType) {
	case "", model.DDNSRecordAddress:
		return nil
	case model.DDNSRecordCNAME:
	default:
		return fmt.Errorf("record_type must be address or cname, not %q", p.RecordType)
	}
	if p.Provider != model.DDNSProviderCloudflare {
		return errors.New("record_type cname needs the cloudflare provider; a webhook only receives the node's addresses")
	}
	target := NormalizeHost(p.CNAMETarget)
	if target == "" {
		return errors.New("cname_target is required when record_type is cname")
	}
	if err := ValidateHostname(target); err != nil {
		return fmt.Errorf("cname_target %w", err)
	}
	for _, domain := range p.Domains {
		domain = NormalizeHost(domain)
		if domain == "" {
			continue
		}
		if target == domain || strings.HasSuffix(target, "."+domain) {
			return fmt.Errorf("cname_target %s is %s or a name under it; a record cannot point into the names it publishes", target, domain)
		}
	}
	return nil
}

// ValidateHostname rejects a name a CNAME cannot point to: an IP literal, a
// name longer than MaxHostnameBytes, a single label, or a label that is
// empty, longer than 63 bytes, holds anything but letters, digits, hyphens
// and underscores, or starts or ends with a hyphen. The error reads as the
// end of a sentence that names the field.
func ValidateHostname(name string) error {
	if net.ParseIP(name) != nil {
		return fmt.Errorf("must be a hostname, not an IP address (%s); an address profile publishes IPs", name)
	}
	if len(name) > MaxHostnameBytes {
		return fmt.Errorf("is %d bytes; a hostname is at most %d", len(name), MaxHostnameBytes)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("must be a fully qualified hostname such as nat-us-28tz.aproxy.top, not %q", name)
	}
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("%q has an empty label", name)
		}
		if len(label) > 63 {
			return fmt.Errorf("%q has a label longer than 63 bytes", name)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%q has a label that starts or ends with a hyphen", name)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return fmt.Errorf("%q may hold only letters, digits, hyphens and underscores", name)
			}
		}
	}
	return nil
}

// CNAMEBlockers returns the records at a name that keep a CNAME from being
// written there: every record that is not itself a CNAME.
func CNAMEBlockers(existing []ExistingRecord) []ExistingRecord {
	var out []ExistingRecord
	for _, rec := range existing {
		if !strings.EqualFold(rec.Type, "CNAME") {
			out = append(out, rec)
		}
	}
	return out
}

// CNAMEConflictSentence explains, for the operator, the records that keep a
// CNAME off name. The run error and the save-time warning both use it, so
// they say the same thing.
func CNAMEConflictSentence(name string, blockers []ExistingRecord) string {
	parts := make([]string, 0, len(blockers))
	for _, rec := range blockers {
		typ := strings.ToUpper(rec.Type)
		parts = append(parts, fmt.Sprintf("%s %s record (%s)", article(typ), typ, strings.TrimSuffix(rec.Content, ".")))
	}
	pronoun := "it"
	if len(blockers) > 1 {
		pronoun = "them"
	}
	return fmt.Sprintf("%s already has %s; a name cannot hold a CNAME and other records. Remove %s in Cloudflare, then run again.",
		name, joinAnd(parts), pronoun)
}

func joinAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return "another record"
	case 1:
		return parts[0]
	default:
		return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
	}
}

// CNAMEInSync reports whether every domain of a CNAME profile already holds
// exactly its CNAME, read through the provider. The scheduled check uses it to
// leave a profile that is in sync untouched, without a write or an audit
// record each interval.
func CNAMEInSync(ctx context.Context, inspector Inspector, p model.DDNSProfile) (bool, error) {
	target := NormalizeHost(p.CNAMETarget)
	for _, domain := range p.Domains {
		existing, err := inspector.RecordsAt(ctx, domain)
		if err != nil {
			return false, err
		}
		if len(existing) != 1 || !strings.EqualFold(existing[0].Type, "CNAME") || NormalizeHost(existing[0].Content) != target {
			return false, nil
		}
	}
	return true, nil
}
