package circlcve

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestGetCPE(t *testing.T) {
	cpe := "cpe:/a:openbsd:openssh:7.5:-"

	result, err := GetCPE(context.Background(), cpe)
	if err != nil {
		t.Error(err)
		return
	}

	substr := strings.Split(cpe, "/a:")[1]
	test := strings.Contains(result.CPE23URI, substr)

	if !test {
		t.Errorf("Failed to retrieve CPE results for %s", cpe)
		return
	}

	// Check for a failure for an empty CPE
	_, err = GetCPE(context.Background(), "")
	if err == nil {
		t.Errorf("no error received")
		return
	}

	// Check for a failure for a missing CPE
	r, err := GetCPE(context.Background(), "cpe:2.3:a:netapp:cloud_backup:-:*:*:*:*:*:*:*")
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

func ExampleGetCPE() {
	cpe := "cpe:/a:openbsd:openssh:7.5:-"

	result, err := GetCPE(context.Background(), cpe)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(result.CPE23URI)
	// Output: cpe:2.3:a:openbsd:openssh:7.5:-:*:*:*:*:*:*
}

func TestExtractCPE(t *testing.T) {
	cpe := "cpe:2.3:a:python:python:2.7.0"

	result, err := ExtractCPE(context.Background(), cpe)
	if err != nil {
		t.Error(err)
		return
	}

	if vendor := result["vendor"]; vendor != "python" {
		t.Error("Failed to extract correct vendor")
		return
	} else if product := result["product"]; product != "python" {
		t.Error("Failed to extract correct product")
		return
	} else if ver := result["version"]; ver != "2.7.0" {
		t.Error("Failed to extract correct version")
		return
	}
}
