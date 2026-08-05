package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/LatticeNet/lattice-sdk/model"
)

// subscriptionShareExportFormat names the envelope. Import refuses anything else
// rather than guessing, so a file from a different tool cannot be half-read into
// a state nobody intended.
const subscriptionShareExportFormat = "lattice.subscription-shares.v1"

type subscriptionShareExport struct {
	Format string                    `json:"format"`
	Shares []model.SubscriptionShare `json:"shares"`
}

// exportSubscriptionShares writes the portable form. Records are sorted by id so
// two exports of the same data are byte-identical: an export that depended on map
// iteration order would diff against itself and be useless for review or backup
// comparison.
func exportSubscriptionShares(shares []model.SubscriptionShare) ([]byte, error) {
	sorted := append([]model.SubscriptionShare(nil), shares...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	if sorted == nil {
		sorted = []model.SubscriptionShare{}
	}
	return json.MarshalIndent(subscriptionShareExport{
		Format: subscriptionShareExportFormat,
		Shares: sorted,
	}, "", "  ")
}

// importSubscriptionShares parses the portable form. Unknown per-record fields
// survive because SubscriptionShare keeps them; this only guards the envelope.
func importSubscriptionShares(data []byte) ([]model.SubscriptionShare, error) {
	var doc subscriptionShareExport
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode subscription share export: %w", err)
	}
	if doc.Format != subscriptionShareExportFormat {
		if doc.Format == "" {
			return nil, errors.New("subscription share export has no format")
		}
		return nil, fmt.Errorf("unsupported subscription share export format %q", doc.Format)
	}
	if doc.Shares == nil {
		doc.Shares = []model.SubscriptionShare{}
	}
	return doc.Shares, nil
}
