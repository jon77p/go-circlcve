package circlcve

import (
	"context"
	"fmt"
	"testing"
)

func TestGetCVE(t *testing.T) {
	result, err := GetCVE(context.Background(), "CVE-2018-15919")
	if err != nil {
		t.Error(err)
		return
	}

	if result.Id != "CVE-2018-15919" {
		t.Error("Failed to retrieve CVE-2018-15919")
		return
	}

	// Check for a failure for an empty CVE
	_, err = GetCVE(context.Background(), "")
	if err == nil {
		t.Errorf("no error received")
		return
	}

	// Check for a failure for a missing CVE
	r, err := GetCVE(context.Background(), "CVE-2999-0000")
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

func ExampleGetCVE() {
	result, err := GetCVE(context.Background(), "CVE-2018-15919")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(result.Id)
	// Output: CVE-2018-15919
}
