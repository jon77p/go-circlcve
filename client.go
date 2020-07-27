package circlcve

import (
	"context"
	"encoding/json"
	"fmt"
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

// CirclDTime.UnmarshalJSON Implement a json.Unmarshaler to perform custom date-time parsing
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