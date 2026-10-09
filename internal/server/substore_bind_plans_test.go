package server

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A revision that only swaps provider content must still show in a plan:
// provider nodes fold under one key whose digest covers their content.
func TestPlanPreviewFoldsProviderContent(t *testing.T) {
	reply := func(providerDigest string) substoreBindPreviewReply {
		return substoreBindPreviewReply{Entries: []substoreBindEntry{
			{Index: 0, LineUUID: "11111111-1111-4111-8111-111111111111", Label: "hk-1 vless", Digest: "d-line"},
			{Index: 1, Provider: true, Name: "provider node", Digest: providerDigest},
		}}
	}
	before := subStorePlanFold(substoreBindResultFromPreview(reply("d-provider-a")).Included)
	after := subStorePlanFold(substoreBindResultFromPreview(reply("d-provider-b")).Included)
	p1, ok1 := before[subStorePlanProviderKey]
	p2, ok2 := after[subStorePlanProviderKey]
	if !ok1 || !ok2 {
		t.Fatalf("provider content is missing from the plan state: %v %v", before, after)
	}
	if p1.Digest == p2.Digest {
		t.Fatal("swapped provider content folds to the same digest, so the plan would show no change")
	}
	if len(p1.Names) != 1 || p1.Names[0] != "provider node" {
		t.Fatalf("provider names: %v", p1.Names)
	}
	if before["11111111-1111-4111-8111-111111111111"].Digest != after["11111111-1111-4111-8111-111111111111"].Digest {
		t.Fatal("an unchanged fleet line changed digest")
	}
	refused := reply("d-provider-a")
	refused.Refused = "placeholder_count"
	if got := substoreBindResultFromPreview(refused); len(got.Included) != 0 || len(got.Excluded) != 2 {
		t.Fatalf("a refused plan still includes entries: %+v", got)
	}
}

// apply_revision runs only inside an approved plan's apply. The gateway
// refuses it for operators; every other core path refuses it too.
func TestApplyRevisionRefusedOutsideAnApprovedApply(t *testing.T) {
	env := newE2EEnv(t, true)
	_, err := env.srv.callRuntimePluginService(context.Background(), subStorePluginID, subStorePluginID+"/subscription", subStoreApplyRevisionMethod, []byte(`{}`), nil, nil)
	if !errors.Is(err, errSubStoreCoreOnlyMethod) {
		t.Fatalf("apply_revision outside an apply: err %v", err)
	}
	if n := env.fake.count(subStoreApplyRevisionMethod); n != 0 {
		t.Fatalf("the plugin's apply_revision ran %d times", n)
	}
	err = env.srv.pluginTaskScheduleMethodAllowed(subStorePluginID, subStorePluginID+"/subscription", subStoreApplyRevisionMethod)
	if err == nil || !strings.Contains(err.Error(), "approved plan apply") {
		t.Fatalf("a schedule naming apply_revision was admitted: %v", err)
	}
}
