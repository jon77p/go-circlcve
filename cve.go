package circlcve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const cvePath = "/cve/"

// GetCVE retrieves the CVE entry for the specified cveid
// The input cveid must either be just the numerical id or in the CVE-x format
func GetCVE(ctx context.Context, cveid string) (*CVE, error) {
	if cveid == "" {
		return nil, errors.New("missing CVE")
	}

	// normalize the input cveid to the CVE-x format
	var normalizedCVE string
	if !strings.HasPrefix(cveid, "CVE-") {
		normalizedCVE = "CVE-" + cveid
	} else {
		normalizedCVE = cveid
	}

	path := baseURL + cvePath + normalizedCVE
	response := CVE{}

	err := SafeJSONRequest(ctx, path, http.StatusOK, nil, &response)
	if err != nil {
		return nil, err
	}

	if response.Id != normalizedCVE {
		return nil, fmt.Errorf("missing CVE %s", normalizedCVE)
	} else {
		return &response, err
	}
}
