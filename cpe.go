package circlcve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// cve.circl.lu appears to have disabled their API functionality for CPEs, but those of nvd.nist.gov work instead
const (
	baseNVDURL   = "https://services.nvd.nist.gov/rest/json"
	oldCPEPrefix = ""
	newCPEPrefix = ""
)

type NVDResponse struct {
	ResultsPerPage int `json:"resultsPerPage"`
	StartIndex     int `json:"startIndex"`
	TotalResults   int `json:"totalResults"`
	Result         struct {
		DataType      string `json:"dataType"`
		FeedVersion   string `json:"feedVersion"`
		CPECount      int    `json:"cpeCount"`
		FeedTimeStamp string `json:"feedTimestamp"`
		CPEs          []CPE  `json:"cpes"`
	} `json:"result"`
}

func GetCPEs(ctx context.Context, cpeuris []string) (CirclResults, error) {
	path := baseNVDURL + "/cpes/1.0"

	results := make(CirclResults)

	normalizedCPEs := normalizeAll(cpeuris, oldCPEPrefix, newCPEPrefix)

	for _, n := range normalizedCPEs {
		params := url.Values{}
		params.Add("addOns", "cves")
		params.Add("cpeMatchString", n)

		response := NVDResponse{}

		err := SafeJSONRequest(ctx, path, http.StatusOK, &params, &response)

		matchedCPE := CPE{}

		if len(response.Result.CPEs) == 0 {
			err = fmt.Errorf("no matching CPE for %s", oldCPEPrefix + n)
		} else {
			// The first result should be the only result that matters
			matchedCPE = response.Result.CPEs[0]
		}

		results.insertCircl([]string{}, matchedCPE, n, err, oldCPEPrefix)
	}

	return results, nil
}

// GetCPE retrieves any available information from nvd.nist.gov for the input CPE
func GetCPE(ctx context.Context, cpeuri string) (*CPE, error) {
	if cpeuri == "" {
		return nil, errors.New("missing CPE")
	}
	cpes, err := GetCPEs(ctx, []string{cpeuri})
	if err != nil {
		return nil, err
	}

	entry, ok := cpes[oldCPEPrefix+cpeuri]
	if !ok {
		return nil, fmt.Errorf("missing or invalid CPE: %s", oldCPEPrefix+cpeuri)
	}
	return entry.ConvertCPE()
}

// todo: convert given product to CPE2.3 for use in GetCPE()
