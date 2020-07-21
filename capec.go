package circlcve

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

const capecPath = "/capec/"

// GetCAPEC retrieves the CAPEC information for the specified capecid
// The input capecid must either be just the numerical id or in the CAPEC-x format
func GetCAPEC(ctx context.Context, capecid string) (*CAPEC, error) {
	normalizedCAPEC := strings.ReplaceAll(capecid, "CAPEC-", "")
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

	return &response, err
}
