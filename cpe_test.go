package circlcve

import (
	"context"
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

	// Check for a failure for an invalid/missing CPE
	_, err = GetCPE(context.Background(), "")
	if err == nil {
		t.Errorf("no error received")
		return
	}
}