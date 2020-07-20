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

	// Check for a failure for an invalid/missing CVE
	_, err = GetCVE(context.Background(), "")
	if err == nil {
		t.Errorf("no error received")
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
