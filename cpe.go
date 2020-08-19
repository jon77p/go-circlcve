package circlcve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
)

// cve.circl.lu appears to have disabled their API functionality for CPEs, but those of nvd.nist.gov work instead
const (
	baseNVDURL   = "https://services.nvd.nist.gov/rest/json"
	oldCPEPrefix = ""
	newCPEPrefix = ""

	avstringRegex = `(?::([?*]?(?:(?:[a-z0-9\-._]|(?:[\\][\\?*!"#$%&'()+,/:;<=>@[\]^{|}~])|[%~])*[?*\-]?)))?`
)

var (
	// CPEComponents is a collection of names for all valid components within a valid CPE URI.
	CPEComponents = []string{"cpe_name", "cpe_version", "part", "vendor", "product", "version", "update", "edition", "lang", "sw_edition", "target_sw", "target_hw", "other"}

	// CPERegex is a regex that matches fully valid CPE 2.2/2.3-compliant URIs, separating each component into a submatch.
	CPERegex = regexp.MustCompile(`(?i)` +
		`(cpe)` + // cpe
		`(?::(2[.]3))?` + // cpe version
		`:[/]?([aoh*\-])` + // part
		avstringRegex + // vendor
		avstringRegex + // product
		avstringRegex + // version
		avstringRegex + // update
		avstringRegex + // edition
		`(?::((?:[a-z]{2,3}(?:-(?:[a-z]{2}|[0-9]{3}))?)|[*\-]))?` + // lang
		avstringRegex + // sw_edition
		avstringRegex + // target_sw
		avstringRegex + // target_hw
		avstringRegex) // other
)

// NVDResponse contains the necessary JSON definition for CPE responses from nvd.nist.gov
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

// GetCPEs retrieves a map of CPE entries for all specified cpeuris
// If a cpeuri cannot be found, then an error will be attached to that entry
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
			err = fmt.Errorf("no matching CPE for %s", oldCPEPrefix+n)
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

// ExtractCPE extracts information about the specified CPE into various components, returning any errors encountered.
func ExtractCPE(ctx context.Context, cpeuri string) (map[string]string, error) {
	result := map[string]string{}

	match := CPERegex.FindStringSubmatch(cpeuri)
	if len(match) <= 1 {
		return nil, fmt.Errorf("unable to extract components of CPE %s", cpeuri)
	}

	match = match[1:] // remove the complete cpeuri match
	for i, key := range CPEComponents {
		if i < len(match) {
			result[key] = match[i]
		}
	}

	return result, nil
}
