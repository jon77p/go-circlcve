package circlcve

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

const (
	cwePath      = "/cwe"
	oldCWEPrefix = "CWE-"
	newCWEPrefix = ""
)

// fixDescription removes the duplicate description text found in circl.lu's CWE endpoint results
func fixDescription(cwe *CWE) {
	split := strings.Split(cwe.Description, ".")
	firstSent := split[0]
	repeatIdx := strings.LastIndex(cwe.Description, firstSent)
	fixed := cwe.Description[:repeatIdx]
	cwe.Description = fixed
}

// GetAllCWEs retrieves a list of all CWEs (Common Weakness Enumerations)
func GetAllCWEs(ctx context.Context) ([]CWE, error) {
	response := []CWE{}

	err := SafeJSONRequest(ctx, baseURL+cwePath, http.StatusOK, nil, &response)
	if err != nil {
		return nil, err
	}

	for i := range response {
		fixDescription(&response[i])
	}

	return response, err
}

func GetCWEs(ctx context.Context, cweids []string) (CirclResults, error) {
	normalizedCWEs := normalizeAll(cweids, oldCWEPrefix, newCWEPrefix)

	results := make(CirclResults)

	cwes, err := GetAllCWEs(ctx)
	if err != nil {
		return nil, err
	}

	for _, c := range cwes {
		results.insertCircl(normalizedCWEs, c, c.Id, nil, oldCWEPrefix)
	}

	results.insertCirclErrors(normalizedCWEs, oldCWEPrefix)

	return results, nil
}

// GetCWE retrieves the CWE entry for the specified cweid, or errors if nonexistent
// The input cweid must either be just the numerical id or in the CWE-x format
func GetCWE(ctx context.Context, cweid string) (*CWE, error) {
	normalizedCWE := normalizeAll([]string{cweid}, oldCWEPrefix, newCWEPrefix)[0]
	cwes, err := GetCWEs(ctx, []string{normalizedCWE})
	if err != nil {
		return nil, err
	}

	entry, ok := cwes[oldCWEPrefix+normalizedCWE]
	if !ok {
		return nil, fmt.Errorf("Missing or invalid CWE: %s", oldCWEPrefix+normalizedCWE)
	}
	return entry.ConvertCWE()
}
