package circlcve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

const capecPath = "/capec/"

// GetCAPEC retrieves the CAPEC information for the specified capecid
// The input capecid must either be just the numerical id or in the CAPEC-x format
func GetCAPEC(ctx context.Context, capecid string) (*CAPEC, error) {
	normalizedCAPEC := normalizeAll([]string{capecid}, "CAPEC-", "")[0]
	if normalizedCAPEC == "" {
		return nil, errors.New("missing CAPEC")
	}

	// Append the normalized CAPEC id to the full path for CAPEC retrieval
	path := baseURL + capecPath + normalizedCAPEC
	response := CAPEC{}

	err := SafeJSONRequest(ctx, path, http.StatusOK, nil, &response)
	if err != nil {
		return nil, err
	}

	if response.Id != normalizedCAPEC {
		return nil, fmt.Errorf("missing CAPEC %s", normalizedCAPEC)
	} else {
		return &response, err
	}
}
