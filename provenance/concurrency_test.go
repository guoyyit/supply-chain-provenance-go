package provenance

import (
	"fmt"
	"sync"
	"testing"
)

// TestConcurrentRegisterAndEvaluate hammers one artifact with concurrent
// registrations while readers evaluate policy and snapshot the chain. Every
// observed snapshot must be internally consistent: no half-written statement,
// no mixture of two registrations.
func TestConcurrentRegisterAndEvaluate(t *testing.T) {
	dir := t.TempDir()
	svc, err := OpenService(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	if err := svc.SetPolicy(Policy{Name: "p", Rules: []Rule{
		{Name: "has-build", StatementType: StatementTypeBuild},
	}}); err != nil {
		t.Fatal(err)
	}

	const writers = 8
	const perWriter = 50

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Readers: every snapshot must be a consistent prefix-linked chain.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				snap := svc.Statements("app")
				for i, st := range snap {
					if st.Sequence != uint64(i+1) {
						t.Errorf("snapshot sequence gap at %d: seq=%d", i, st.Sequence)
						return
					}
					if i > 0 && st.PrevDigest != snap[i-1].Digest {
						t.Errorf("snapshot link broken at %d", i)
						return
					}
				}
				if _, err := svc.Evaluate("app"); err != nil {
					t.Errorf("evaluate: %v", err)
					return
				}
			}
		}()
	}

	// Writers.
	var writersWG sync.WaitGroup
	for w := 0; w < writers; w++ {
		writersWG.Add(1)
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer writersWG.Done()
			for i := 0; i < perWriter; i++ {
				if _, err := svc.RegisterStatement("app", StatementTypeBuild,
					fmt.Sprintf("builder-%d", id), map[string]string{"i": fmt.Sprint(i)}); err != nil {
					t.Errorf("register: %v", err)
					return
				}
			}
		}(w)
	}

	// Stop readers once all writers finished, then join everyone.
	writersWG.Wait()
	close(stop)
	wg.Wait()

	if got := len(svc.Statements("app")); got != writers*perWriter {
		t.Fatalf("want %d statements, got %d", writers*perWriter, got)
	}
	if verr := svc.VerifyArtifact("app"); verr != nil {
		t.Fatalf("final verify: %v", verr)
	}
	res, err := svc.Evaluate("app")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed || res.ChainLength != writers*perWriter {
		t.Fatalf("final evaluate: passed=%v len=%d", res.Passed, res.ChainLength)
	}
}

// TestLongChainIncrementalVerification proves verification cost does not grow
// with chain length: a re-verify scans zero statements, and after one append
// only the new statement is inspected.
func TestLongChainIncrementalVerification(t *testing.T) {
	dir := t.TempDir()
	svc, err := OpenService(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	const n = 2000
	registerN(t, svc, "big", n)

	if verr := svc.VerifyArtifact("big"); verr != nil {
		t.Fatalf("first verify: %v", verr)
	}
	if got := svc.LastVerifiedCount("big"); got != n {
		t.Fatalf("first verify should scan %d statements, scanned %d", n, got)
	}

	// Cached: nothing to re-scan.
	if verr := svc.VerifyArtifact("big"); verr != nil {
		t.Fatalf("cached verify: %v", verr)
	}
	if got := svc.LastVerifiedCount("big"); got != 0 {
		t.Fatalf("cached verify should scan 0 statements, scanned %d", got)
	}

	// Incremental: appending one statement must not re-scan history.
	if _, err := svc.RegisterStatement("big", StatementTypeTest, "ci",
		map[string]string{"status": "ok"}); err != nil {
		t.Fatal(err)
	}
	if verr := svc.VerifyArtifact("big"); verr != nil {
		t.Fatalf("incremental verify: %v", verr)
	}
	if got := svc.LastVerifiedCount("big"); got != 1 {
		t.Fatalf("incremental verify should scan 1 statement, scanned %d", got)
	}
}
