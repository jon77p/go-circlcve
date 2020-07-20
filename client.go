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

// Client A circlcve client
type Client struct {
}

func (c *Client) makeRequest(ctx context.Context, path string, expectedStatus int, params *url.Values) (*http.Response, error) {
	return makeRequest(ctx, path, expectedStatus, params)
}

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
	return json.NewDecoder(resp.Body).Decode(&response)
}

// safeJSONRequest is a helper function that contains the logic to safely make an API request and decode the JSON response into the input response structure
// If the request is unable to be made or the response cannot be decoded, an error will be returned
func safeJSONRequest(ctx context.Context, path string, expectedStatus int, params *url.Values, response interface{}) error {
	resp, err := makeRequest(ctx, path, expectedStatus, params)
	if err != nil {
		return err
	}

	return unmarshal(resp, &response)
}
