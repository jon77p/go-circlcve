package circlcve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const cwePath = "/cwe"

// fixDescription removes the duplicate description text found in circl.lu's CWE endpoint results
func fixDescription(cwe *CWE) {
	split := strings.Split(cwe.Description, ".")
	firstSent := split[0]
	repeatIdx := strings.LastIndex(cwe.Description, firstSent)
	fixed := cwe.Description[:repeatIdx]
	cwe.Description = fixed
}

// GetCWEs retrieves a list of all CWEs (Common Weakness Enumerations)
func GetCWEs(ctx context.Context) ([]CWE, error) {
	response := []CWE{}

	err := safeJSONRequest(ctx, baseURL + cwePath, http.StatusOK, nil, &response)
	if err != nil {
		return nil, err
	}

	for i := range response {
		fixDescription(&response[i])
	}

	return response, err
}

// GetCWE retrieves the CWE entry for the specified cweid, or errors if nonexistent
// The input cweid must either be just the numerical id or in the CWE-x format
func GetCWE(ctx context.Context, cweid string) (*CWE, error) {
	normalizedCWE := strings.ReplaceAll(cweid, "CWE-", "")
	cwes, err := GetCWEs(ctx)
	if err != nil {
		return nil, err
	}

	for i := range cwes {
		cwe := cwes[i]
		if cwe.Id == normalizedCWE {
			return &cwes[i], nil
		}
	}

	return nil, errors.New(fmt.Sprintf("Missing or invalid CWE: %s", cweid))
}