package circlcve

import (
	"context"
	"fmt"
	"testing"
)

func TestGetCAPEC(t *testing.T) {
	result, err := GetCAPEC(context.Background(), "13")
	if err != nil {
		t.Error(err)
		return
	}

	if result.Name != "Subverting Environment Variable Values" {
		t.Error("Failed to retrieve CAPEC for CAPEC-13")
		return
	}

	// Test for CAPEC retrieval in CAPEC-x format
	result, err = GetCAPEC(context.Background(), "CAPEC-13")
	if err != nil {
		t.Error(err)
		return
	}

	if result.Name != "Subverting Environment Variable Values" {
		t.Error("Failed to retrieve CAPEC for CAPEC-13")
		return
	}

	// Check for a failure for an invalid/missing CWE
	_, err = GetCAPEC(context.Background(), "")
	if err == nil {
		t.Errorf("no error received")
		return
	}
}

func ExampleGetCAPEC() {
	result, err := GetCAPEC(context.Background(), "CAPEC-13")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(result.Name)
	// Output: Subverting Environment Variable Values
}
