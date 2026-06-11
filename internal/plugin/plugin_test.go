package plugin

import "testing"

func TestValidateManifestRejectsUnknownCapability(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "bad",
		Name:         "Bad",
		Type:         "wasm",
		Capabilities: []string{"exec:anything"},
	})
	if err == nil {
		t.Fatal("expected unknown capability rejection")
	}
}

func TestValidateManifestAcceptsSystemNetworkPlan(t *testing.T) {
	err := ValidateManifest(Manifest{
		ID:           "nft",
		Name:         "nft guard",
		Type:         "system",
		Capabilities: []string{"network:plan", "network:apply"},
	})
	if err != nil {
		t.Fatal(err)
	}
}
