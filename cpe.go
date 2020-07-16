package circlcve

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

// cve.circl.lu appears to have disabled their API functionality for CPEs, but those of nvd.nist.gov work instead
const (
	baseNVDURL = "https://services.nvd.nist.gov/rest/json"
)

// GetCPE retrieves any available information from nvd.nist.gov for the input CPE
func GetCPE(ctx context.Context, cpe string) (*CPE, error) {
	if cpe == "" {
		return nil, errors.New("missing CPE")
	}
	path := baseNVDURL + "/cpes/1.0"

	params := url.Values{}
	params.Add("addOns", "cves")
	params.Add("cpeMatchString", cpe)

	// Temporarily defined, since only a single result should be returned for any given CPE
	response := struct{
		ResultsPerPage	int			`json:"resultsPerPage"`
		StartIndex		int			`json:"startIndex"`
		TotalResults	int			`json:"totalResults"`
		Result			struct{
			DataType		string	`json:"dataType"`
			FeedVersion		string	`json:"feedVersion"`
			CPECount		int		`json:"cpeCount"`
			FeedTimeStamp	string	`json:"feedTimestamp"`
			CPEs			[]CPE	`json:"cpes"`
		}							`json:"result"`
	}{}

	err := safeJSONRequest(ctx, path, http.StatusOK, &params, &response)
	if err != nil {
		return nil, err
	}

	if len(response.Result.CPEs) == 0 {
		return nil, errors.New("no matching CPE")
	}

	// The first result should be the only result that matters
	matchedCPE := response.Result.CPEs[0]

	return &matchedCPE, err
}

// todo: convert given product to CPE2.3 for use in GetCPE()
