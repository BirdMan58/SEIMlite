package discovery

import "testing"

func TestAssessBulkUploadDetectsStorageDoS(t *testing.T) {
	result := AssessBulkUpload(35, 120*1024*1024)
	if !result.Blocked {
		t.Fatal("expected bulk upload burst to be blocked")
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected a security finding for the bulk upload burst")
	}
}

func TestAssessBulkUploadAllowsNormalUpload(t *testing.T) {
	result := AssessBulkUpload(4, 3*1024*1024)
	if result.Blocked {
		t.Fatal("expected normal upload volume to be allowed")
	}
	if len(result.Findings) != 0 {
		t.Fatal("expected no findings for a normal upload volume")
	}
}
