//go:build linux

package ebpf

import "testing"

func TestPublicationBufferKeepsKeysAndEntriesIndependent(t *testing.T) {
	b := loadDatapath(t)
	controller, err := b.BeginRuleTransaction(42)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := controller.Rollback(); err != nil {
			t.Error(err)
		}
	}()
	// Cross the small-draft index boundary, then revisit an earlier key.
	for key := uint32(100); key < 112; key++ {
		for id := uint32(1); id <= key%3+1; id++ {
			if err := controller.PutPdrUplink(key, PdrInfo{SessionID: 42, PdrID: id, FarId: key, Precedence: id}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := controller.PutPdrUplink(100, PdrInfo{SessionID: 42, PdrID: 1, FarId: 999, Precedence: 1}); err != nil {
		t.Fatal(err)
	}
	if err := controller.Commit(); err != nil {
		t.Fatal(err)
	}
	for key := uint32(100); key < 112; key++ {
		var info IpEntrypointPdrInfo
		if err := b.LookupUplinkPDR(key, &info); err != nil {
			t.Fatal(err)
		}
		if info.SessionId != 42 || info.Count != key%3+1 {
			t.Fatalf("publication mixed key %d: owner=%d count=%d", key, info.SessionId, info.Count)
		}
		for i, entry := range info.Entries {
			if i >= int(info.Count) {
				if entry != (IpEntrypointPdrEntry{}) {
					t.Fatalf("key %d retained entries beyond its count", key)
				}
				continue
			}
			want := key
			if key == 100 && entry.PdrId == 1 {
				want = 999
			}
			if entry.Pdr.FarId != want {
				t.Fatalf("key %d borrowed another publication's FAR: %d", key, entry.Pdr.FarId)
			}
		}
	}
}
