package circlcve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

const (
	cvePath      = "/cve/"
	oldCVEPrefix = ""
	newCVEPrefix = "CVE-"
)

// GetCVEs retrieves a map of CVE entries for all specified cveids
// If a cveid cannot be found, then an error will be attached to that entry
// The input cveids must all either be just the numerical id or in the CVE-x format
func GetCVEs(ctx context.Context, cveids []string) (CirclResults, error) {
	currentPath := baseURL + cvePath

	results := make(CirclResults)

	// normalize the input cveids to the CVE-x format
	normalizedCVEs := normalizeAll(cveids, oldCVEPrefix, newCVEPrefix)

	for _, c := range normalizedCVEs {
		path := currentPath + c
		response := CVE{}

		err := SafeJSONRequest(ctx, path, http.StatusOK, nil, &response)

		if err == nil && response.Id != c {
			err = fmt.Errorf("missing CVE %s", oldCVEPrefix+c)
		}

		results.insertCircl(normalizedCVEs, response, c, err, oldCVEPrefix)
	}

	results.insertCirclErrors(normalizedCVEs, oldCVEPrefix)

	return results, nil
}

// GetCVE retrieves the CVE entry for the specified cveid
// The input cveid must either be just the numerical id or in the CVE-x format
func GetCVE(ctx context.Context, cveid string) (*CVE, error) {
	if cveid == "" {
		return nil, errors.New("missing CVE")
	}

	// normalize the input cveid to the CVE-x format
	normalizedCVE := normalizeAll([]string{cveid}, oldCVEPrefix, newCVEPrefix)[0]
	cves, err := GetCVEs(ctx, []string{normalizedCVE})
	if err != nil {
		return nil, err
	}

	entry, ok := cves[oldCVEPrefix+normalizedCVE]
	if !ok {
		return nil, fmt.Errorf("missing or invalid CVE: %s", oldCVEPrefix+normalizedCVE)
	}
	return entry.ConvertCVE()
}

func (vc CVEVulnerableConfiguration) String() string {
	return vc.ID
}

func (vcs CVEVulnerableConfigurations) Strings() []string {
	s := make([]string, 0)
	for _, vc := range vcs {
		s = append(s, vc.String())
	}

	return s
}
