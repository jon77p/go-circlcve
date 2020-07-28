package circlcve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

const (
	capecPath      = "/capec/"
	oldCAPECPrefix = "CAPEC-"
	newCAPECprefix = ""
)

// GetCAPECs retrieves a map of CAPEC entries for all specified capecids
// If a capecid cannot be found, then an error will be attached to that entry
// The input capecids must all either be just the numerical id or in the CAPEC-x format
func GetCAPECs(ctx context.Context, capecids []string) (CirclResults, error) {
	currentPath := baseURL + capecPath

	results := make(CirclResults)

	normalizedCapecs := normalizeAll(capecids, oldCAPECPrefix, newCAPECprefix)

	for _, c := range normalizedCapecs {
		// Append the normalized CAPEC id to the full path for CAPEC retrieval
		path := currentPath + c
		response := CAPEC{}

		err := SafeJSONRequest(ctx, path, http.StatusOK, nil, &response)
		if err == nil && response.Id != c {
			err = fmt.Errorf("missing CAPEC %s", oldCAPECPrefix+c)
		}

		results.insertCircl(normalizedCapecs, response, c, err, oldCAPECPrefix)
	}

	results.insertCirclErrors(normalizedCapecs, oldCAPECPrefix)

	return results, nil
}

// GetCAPEC retrieves the CAPEC information for the specified capecid
// The input capecid must either be just the numerical id or in the CAPEC-x format
func GetCAPEC(ctx context.Context, capecid string) (*CAPEC, error) {
	normalizedCAPEC := normalizeAll([]string{capecid}, oldCAPECPrefix, newCAPECprefix)[0]
	if normalizedCAPEC == "" {
		return nil, errors.New("missing CAPEC")
	}

	capecs, err := GetCAPECs(ctx, []string{normalizedCAPEC})
	if err != nil {
		return nil, err
	}

	entry, ok := capecs[oldCAPECPrefix+normalizedCAPEC]
	if !ok {
		return nil, fmt.Errorf("missing or invalid CAPEC: %s", oldCAPECPrefix+normalizedCAPEC)
	}
	return entry.ConvertCAPEC()
}
