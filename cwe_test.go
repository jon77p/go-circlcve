package circlcve

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestGetAllCWEs(t *testing.T) {
	results, err := GetAllCWEs(context.Background())
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

	// Check for a failure for an empty CWE
	_, err = GetCWE(context.Background(), "")
	if err == nil {
		t.Errorf("no error received")
		return
	}

	// Check for a failure for a missing CWE
	r, err := GetCWE(context.Background(), "CWE-0000")
	if err == nil {
		t.Errorf("no error received")
		return
	}
	// Check for a null result
	if r != nil {
		t.Errorf("non-nil result received")
		return
	}
}

func TestGetCWEs(t *testing.T) {
	cweids := []string{"CWE-15", "CWE-20", "CWE-200", "CWE-285", "CWE-302", "CWE-353", "CWE-73", "CWE-74", "CWE-9999"}
	result, err := GetCWEs(context.Background(), cweids)
	if err != nil {
		t.Error(err)
		return
	}

	if len(result) != len(cweids) {
		t.Error("Failed to retrieve all CWEs")
		return
	}

	if result["CWE-15"].error != nil {
		t.Error("Received error for valid CWE (CWE-15)", result["CWE-15"].error)
		return
	}

	if result["CWE-9999"].error == nil {
		t.Error("No error received for invalid CWE (CWE-9999)")
		return
	}
}

func ExampleGetCWE() {
	result, err := GetCWE(context.Background(), "CWE-200")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(result.Id)
	// Output: 200
}
