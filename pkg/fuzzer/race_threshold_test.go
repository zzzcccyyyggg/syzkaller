package fuzzer

import "testing"

func TestSerializedSeedEntryPreservesAdmissionThreshold(t *testing.T) {
	entry := &UAFCorpusEntry{AdmissionThresholdUs: 2500}
	blob := newSerializedSeedEntry(entry, false)
	got, err := blob.materialize(nil)
	if err != nil {
		t.Fatalf("materialize failed: %v", err)
	}
	if got.AdmissionThresholdUs != entry.AdmissionThresholdUs {
		t.Fatalf("admission threshold = %d, want %d", got.AdmissionThresholdUs, entry.AdmissionThresholdUs)
	}
}
