package circlcve

import (
	"context"
	"strings"
	"testing"
)

func TestGetCWEs(t *testing.T) {
	results, err := GetCWEs(context.Background())
	if err != nil {
		t.Error(err)
		return
	}

	if results[4].Name != "J2EE Misconfiguration: Data Transmission Without Encryption" {
		t.Error("Different expected result than published API!")
		return
	}
}

func TestGetCWE(t *testing.T) {
	cweid := "CWE-200"
	result, err := GetCWE(context.Background(), cweid)
	if err != nil {
		t.Error(err)
		return
	}

	if result.Id != strings.ReplaceAll(cweid, "CWE-", "") {
		t.Error("Retrieved invalid CWE")
		return
	}

	// Check for a failure for an invalid/missing CWE
	_, err = GetCWE(context.Background(), "")
	if err == nil {
		t.Errorf("no error received")
		return
	}
}