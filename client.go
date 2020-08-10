package circlcve

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-openapi/swag"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	baseURL = "https://cve.circl.lu/api"
)

// makeRequest is a helper function that
// The expectedStatus ensures that the API result's status code is the same, or an error is raised
// If params is nil, no URL parameters will be added
func makeRequest(ctx context.Context, path string, expectedStatus int, params *url.Values) (*http.Response, error) {
	var finalPath string
	if params != nil {
		finalPath, _ = url.QueryUnescape(path + "?" + params.Encode())
	} else {
		finalPath = path
	}

	req, err := http.NewRequestWithContext(ctx, "GET", finalPath, nil)
	if err != nil {
		return nil, err
	}

	// User-Agent field must exist so that request succeeds
	req.Header.Add("User-Agent", "")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != expectedStatus {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("Unexpected status code: %d. Body: %s", resp.StatusCode, string(body))
	}

	return resp, err
}

// UnmarshalJSON Implements a json.Unmarshaler on a *CirclDTime to perform custom date-time parsing
func (t *CirclDTime) UnmarshalJSON(buffer []byte) error {
	timestr := string(buffer)
	normalized := strings.Trim(timestr, `"`)

	var longForm string
	if strings.Index(normalized, "Z") == len(normalized)-1 {
		// time formats from NIST for CPEs are not really standard
		longForm = "2006-01-02T15:04Z"
	} else {
		longForm = "2006-01-02T15:04:05"
	}
	parsed, err := time.Parse(longForm, normalized)
	if err == nil {
		t.Time = parsed
	}
	return err
}

// unmarshal is a wrapper function that tries to decode the input HTTP Response's contents into the input struct
// The input HTTP Response connection will be closed on return
// If the Response cannot be unmarshalled, an error will be returned
func unmarshal(resp *http.Response, response interface{}) error {
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(response)
}

// SafeJSONRequest is a helper function that contains the logic to safely make an API request and decode the JSON response into the input response structure
// If the request is unable to be made or the response cannot be decoded, an error will be returned
func SafeJSONRequest(ctx context.Context, path string, expectedStatus int, params *url.Values, response interface{}) error {
	resp, err := makeRequest(ctx, path, expectedStatus, params)
	if err != nil {
		return err
	}

	return unmarshal(resp, response)
}

// normalizeAll is a helper function that allows for all input strings to be normalized to the same format and returned to the caller
// If the old parameter is an empty string, then the new parameter will be prefixed to all strings in the input string array that do not already have the prefix.
// If the old parameter is not an empty string, then all instances of old will be replaced with new for all strings in the input string array
func normalizeAll(inputs []string, old string, new string) []string {
	result := []string{}
	for _, s := range inputs {
		var normalized string
		if old != "" {
			normalized = strings.ReplaceAll(s, old, new)
		} else {
			if !strings.HasPrefix(s, new) {
				normalized = new + s
			} else {
				normalized = s
			}
		}

		result = append(result, normalized)
	}

	return result
}

func (c CWE) String() string {
	return "CWE-" + c.Id
}

func (c CVE) String() string {
	return c.Id
}

func (c CAPEC) String() string {
	return c.Id
}

func (c CPE) String() string {
	return c.CPE23URI
}

func (r CirclResult) String() string {
	if cwe, err := r.ConvertCWE(); cwe != nil && err != nil {
		return cwe.String()
	} else if cve, err := r.ConvertCVE(); cve != nil && err != nil {
		return cve.String()
	} else if capec, err := r.ConvertCAPEC(); capec != nil && err != nil {
		return capec.String()
	} else if cpe, err := r.ConvertCPE(); cpe != nil && err != nil {
		return cpe.String()
	} else {
		return ""
	}
}

func (results CirclResults) String() []string {
	var result []string
	for _, r := range results {
		result = append(result, r.String())
	}

	return result
}

// insertCircl adds the specified Circl result into the CirclResults map
// This only happens if there is a nonempty list of normalized identifiers or if the identifier is present in the input list of normalized identifiers, and also if the identifier is not already found in the CirclResults map
func (results CirclResults) insertCircl(normalized []string, c Circl, id string, err error, typestr string) {
	key := typestr + id
	_, ok := results[key]
	if (len(normalized) == 0 || swag.ContainsStrings(normalized, id)) && !ok {
		results[key] = CirclResult{c, err}
	}
}

// insertCirclErrors adds CirclResult entries with errors for all keys in the normalized identifiers array that are not in the CirclResults map
func (results CirclResults) insertCirclErrors(normalized []string, typestr string) {
	for _, n := range normalized {
		key := typestr + n
		if _, ok := results[key]; !ok {
			results[key] = CirclResult{nil, fmt.Errorf("Invalid %s", key)}
		}
	}
}

// ConvertCWE attempts to convert the CirclResult's data to a CWE and returns its related error (if present)
// If the CirclResult's data is not a CWE entry, an error will be returned.
func (e CirclResult) ConvertCWE() (*CWE, error) {
	if e.error != nil {
		return nil, e.error
	}

	result, ok := e.data.(CWE)
	if !ok {
		return nil, fmt.Errorf("cannot convert entry type to %s: %T", "CWE", e.data)
	}
	return &result, nil
}

// ConvertCVE attempts to convert the CirclResult's data to a CVE and returns its related error (if present)
// If the CirclResult's data is not a CVE entry, an error will be returned.
func (e CirclResult) ConvertCVE() (*CVE, error) {
	if e.error != nil {
		return nil, e.error
	}

	result, ok := e.data.(CVE)
	if !ok {
		return nil, fmt.Errorf("cannot convert entry type to %s: %T", "CVE", e.data)
	}
	return &result, nil
}

// ConvertCAPEC attempts to convert the CirclResult's data to a CAPEC and returns its related error (if present)
// If the CirclResult's data is not a CAPEC entry, an error will be returned.
func (e CirclResult) ConvertCAPEC() (*CAPEC, error) {
	if e.error != nil {
		return nil, e.error
	}

	result, ok := e.data.(CAPEC)
	if !ok {
		return nil, fmt.Errorf("cannot convert entry type to %s: %T", "CAPEC", e.data)
	}
	return &result, nil
}

// ConvertCPE attempts to convert the CirclResult's data to a CPE and returns its related error (if present)
// If the CirclResult's data is not a CPE entry, an error will be returned.
func (e CirclResult) ConvertCPE() (*CPE, error) {
	if e.error != nil {
		return nil, e.error
	}

	result, ok := e.data.(CPE)
	if !ok {
		return nil, fmt.Errorf("cannot convert entry type to %s: %T", "CPE", e.data)
	}
	return &result, nil
}
