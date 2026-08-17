package server

import (
	"context"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestLineChainPlanPublicationWaitsForGraphReaders(t *testing.T) {
	srv, sourceUUID, targetUUID, _, _ := seedLineChainFixture(t)
	compiled, err := srv.compileLineChain(lineChainCompileRequest{SourceLineUUID: sourceUUID, TargetLineUUID: targetUUID})
	if err != nil {
		t.Fatal(err)
	}
	waiter := make(chan struct{}, 1)
	srv.subscriptionGraphWriteWaiter = waiter
	_, release := srv.acquireSubscriptionGraphRead(context.Background(), vpnCorePluginID)
	done := make(chan error, 1)
	go func() {
		_, err := srv.persistLineChainPlan(lineUserTestPrincipal(), compiled)
		done <- err
	}()
	<-waiter
	if attempts := srv.store.LineChainSnapshot().Attempts; len(attempts) != 0 {
		t.Fatalf("plan published while graph reader was active: %+v", attempts)
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if attempts := srv.store.LineChainSnapshot().Attempts; len(attempts) != 1 {
		t.Fatalf("plan publication missing after reader release: %+v", attempts)
	}
}

func TestSubscriptionGraphAuthorityNestedReadDoesNotReacquire(t *testing.T) {
	srv := &Server{}
	ctx, release := srv.acquireSubscriptionGraphRead(context.Background(), vpnCorePluginID)
	defer release()
	state := srv.subscriptionGraphAuthorityFor(vpnCorePluginID)
	if state.mu.TryLock() {
		state.mu.Unlock()
		t.Fatal("outer read did not hold graph authority")
	}
	nested, nestedRelease := srv.acquireSubscriptionGraphRead(ctx, vpnCorePluginID)
	defer nestedRelease()
	if !subscriptionGraphAuthorityHeld(nested, vpnCorePluginID) {
		t.Fatal("nested graph authority marker was lost")
	}
}

func TestSubscriptionGraphAuthorityBlocksLiveInventoryPublication(t *testing.T) {
	srv := &Server{singboxInv: map[string]model.SingBoxInventory{}}
	waiter := make(chan struct{}, 1)
	srv.subscriptionGraphWriteWaiter = waiter
	_, releaseRead := srv.acquireSubscriptionGraphRead(context.Background(), vpnCorePluginID)
	done := make(chan struct{})
	go func() {
		srv.publishSingBoxInventory("node-a", model.SingBoxInventory{NodeID: "node-a", Status: "ok"})
		close(done)
	}()
	<-waiter
	if _, ok := srv.singBoxInventory("node-a"); ok {
		t.Fatal("inventory published while save authority was held")
	}
	releaseRead()
	<-done
	if _, ok := srv.singBoxInventory("node-a"); !ok {
		t.Fatal("inventory publication was lost")
	}
}

func TestSubscriptionGraphAuthoritySerializesSaveAndMutation(t *testing.T) {
	srv := &Server{}
	_, releaseRead := srv.acquireSubscriptionGraphRead(context.Background(), vpnCorePluginID)
	state := srv.subscriptionGraphAuthorityFor(vpnCorePluginID)
	if state.mu.TryLock() {
		state.mu.Unlock()
		t.Fatal("mutation acquired while save authority was held")
	}
	releaseRead()
	if !state.mu.TryLock() {
		t.Fatal("mutation could not acquire after save authority released")
	}
	if state.mu.TryRLock() {
		state.mu.RUnlock()
		state.mu.Unlock()
		t.Fatal("save acquired while mutation authority was held")
	}
	state.mu.Unlock()
}
