//go:build linux

package ebpf

import "testing"

func TestPDRImageReuseKeepsCommittedAndRollbackImages(t *testing.T) {
	b := loadDatapath(t)
	key := pdrMutationKey{b.PdrMapTeidIp4, uint32(10)}
	for i := uint32(1); i <= 32; i++ {
		info := PdrInfo{PdrID: 1, FarId: 2, Precedence: i}
		if err := b.PutPdrUplink(10, info); err != nil {
			t.Fatal(err)
		}
		expected, err := encodePDR(info)
		if err != nil {
			t.Fatal(err)
		}
		image := b.ruleImages[key]
		if len(image.entries) != 1 || image.entries[0] != expected {
			t.Fatalf("committed image overwritten: iteration=%d", i)
		}
		controller, err := b.BeginRuleTransaction(0)
		if err != nil {
			t.Fatal(err)
		}
		tx := controller.(*ruleTransaction)
		changed := info
		changed.Precedence += 1000
		if err := tx.PutPdrUplink(10, changed); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.publishPDRs(); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		image = b.ruleImages[key]
		if len(image.entries) != 1 || image.entries[0] != expected {
			t.Fatalf("rollback image overwritten: iteration=%d", i)
		}
		var kernel IpEntrypointPdrInfo
		if err := b.LookupUplinkPDR(10, &kernel); err != nil {
			t.Fatal(err)
		}
		if kernel.Count != 1 || kernel.Entries[0] != expected {
			t.Fatal("kernel rollback diverged from committed image")
		}
	}
}
