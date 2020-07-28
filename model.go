package circlcve

import (
	"time"
)

// CirclDTime is a custom type used to implement date time parsing for JSON
type CirclDTime struct {
	time.Time
}

type Circl interface {
	String() string
}

type CirclResult struct {
	data  interface{}
	error error
}

type CirclResults map[string]CirclResult

// CVEAccess contains access information that scores the CVE's difficulty for attackers
type CVEAccess struct {
	Authentication string `json:"authentication"`
	Complexity     string `json:"complexity"`
	Vector         string `json:"vector"`
}

// CVECapec contains CAPEC-related information and summary information for a CVE response
type CVECapec struct {
	Id              string   `json:"id"`
	Name            string   `json:"name"`
	PreRequisites   string   `json:"prerequisites"`
	RelatedWeakness []string `json:"related_weakness"`
	Solutions       string   `json:"solutions"`
	Summary         string   `json:"summary"`
}

// CVEImpact contains scoring information for affected parts of the CIA security triad for a CVE response
type CVEImpact struct {
	Availability    string `json:"availability"`
	Confidentiality string `json:"confidentiality"`
	Integrity       string `json:"integrity"`
}

// CVERefMap contains lists of references for more information and reports about a CVE
type CVERefMap struct {
	BId     []string `json:"bid"`
	Confirm []string `json:"confirm"`
	Misc    []string `json:"misc"`
}

// CVEVulnerableConfiguration is a CPE id and a title, if available, of a product vulnerable to a specific CVE
type CVEVulnerableConfiguration struct {
	ID    string `json:"id"`
	title string `json:"title"`
}

// CVE is the raw CVE response from circl.lu
type CVE struct {
	Circl
	Modified                      CirclDTime                   `json:"Modified"`
	Published                     CirclDTime                   `json:"Published"`
	Access                        CVEAccess                    `json:"access"`
	Assigner                      string                       `json:"assigner"`
	Capec                         []CVECapec                   `json:"capec"`
	CVSS                          float64                      `json:"cvss"`
	CVSSTime                      CirclDTime                   `json:"cvss-time"`
	CVSSVector                    string                       `json:"cvss-vector"`
	CWE                           string                       `json:"cwe"`
	Id                            string                       `json:"id"`
	Impact                        CVEImpact                    `json:"impact"`
	References                    []string                     `json:"references"`
	RefMap                        CVERefMap                    `json:"refmap"`
	Summary                       string                       `json:"summary"`
	VulnerableConfiguration       []CVEVulnerableConfiguration `json:"vulnerable_configuration"`
	VulnerableConfigurationCPE2_2 []string                     `json:"vulnerable_configuration_cpe_2_2"`
	VulnerableProduct             []string                     `json:"vulnerable_product"`
}

// CWE is the raw CWE response from circl.lu
type CWE struct {
	Circl
	Description string `json:"Description"`
	Id          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	WeaknessABS string `json:"weaknessabs"`
}

// CAPEC is the raw CAPEC response from circl.lu
type CAPEC struct {
	Circl
	Id                string   `json:"id"`
	Name              string   `json:"name"`
	PreRequisites     string   `json:"prerequisites"`
	RelatedWeaknesses []string `json:"related_weakness"`
	Solutions         string   `json:"solutions"`
	Summary           string   `json:"summary"`
}

// CPETitle is the formal name in the specified language for a certain CPE
type CPETitle struct {
	Title string `json:"title"`
	Lang  string `json:"lang"`
}

// CPERef contains a reference link and a description of its type for a certain CPE
type CPERef struct {
	Ref  string `json:"ref"`
	Type string `json:"type"`
}

// CPE is the raw CPE response from nvd.nist.gov
type CPE struct {
	Circl
	Deprecated       bool       `json:"deprecated"`
	CPE22URI         string     `json:"cpe22Uri"`
	CPE23URI         string     `json:"cpe23Uri"`
	LastModifiedDate CirclDTime `json:"lastModifiedDate"`
	Titles           []CPETitle `json:"titles"`
	Refs             []CPERef   `json:"refs"`
	DeprecatedBy     []string   `json:"deprecatedBy"`
	Vulnerabilities  []string   `json:"vulnerabilities"`
}
