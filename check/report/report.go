package report

import (
	"encoding/json"
	"errors"
	"sort"
	"time"
)

const (
	CategoryIssue          = "ISSUE"
	CategoryPotentialIssue = "POTENTIAL_ISSUE"
	CategoryCompliance     = "COMPLIANCE"
	CategoryInformational  = "INFORMATIONAL"

	layout = "2006-01-02 15:04:05"
)

// Report represents a check vulnerability report.
type Report struct {
	CheckData
	ResultData
}

// ResultData contains the data regarding result of the execution of a check, for instance: vulnerabilities, notes, etc.
type ResultData struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"` // Array of identified vulnerabilities.

	Data  []byte `json:"data,omitempty"`  // Free field for additional data.
	Notes string `json:"notes,omitempty"` // Free field for additional notes.
	Error string `json:"error"`           // Error message, if any.

	NotApplicable bool `json:"not_applicable,omitempty"` // If the check was not really applicable.
}

// CheckData defines the data about the execution of the check that generated the report.
type CheckData struct {
	CheckID          string `json:"check_id"`          // Mandatory.
	ChecktypeName    string `json:"checktype_name"`    // Mandatory.
	ChecktypeVersion string `json:"checktype_version"` // Mandatory.

	Status string `json:"status"` // Mandatory.

	Target  string `json:"target"` // Mandatory.
	Options string `json:"options"`
	Tag     string `json:"tag"`

	StartTime time.Time `json:"start_time"` // Mandatory.
	EndTime   time.Time `json:"end_time"`
}

// AddVulnerabilities is a handy method to add one or more Vulnerabilities to the ResultData.Vulnerability array.
// It's equivalent to r.Vulnerabilities = append(r.Vulnerabilities,v).
func (r *ResultData) AddVulnerabilities(v ...Vulnerability) {
	r.Vulnerabilities = append(r.Vulnerabilities, v...)
}

// MarshalJSONTimeAsString marshals a Report to JSON using time as string
// A custom marshaler is used to rewrite times for Athena and Rails.
// TODO: Discuss if this is necessary or if we can drop it.
func (r *Report) MarshalJSONTimeAsString() ([]byte, error) {
	return json.Marshal(struct {
		Report
		StartTime string `json:"start_time"`
		EndTime   string `json:"end_time"`
	}{
		Report:    *r,
		StartTime: formatTime(&r.StartTime, layout),
		EndTime:   formatTime(&r.EndTime, layout),
	})
}

// UnmarshalJSONTimeAsString unmarshals a JSON to a Report using time as string
func (r *Report) UnmarshalJSONTimeAsString(data []byte) error {
	aux := &struct {
		*Report
		StartTime string `json:"start_time"`
		EndTime   string `json:"end_time"`
	}{
		Report: r,
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if len(aux.StartTime) > 0 {
		startTime, err := time.Parse(layout, aux.StartTime)
		if err != nil {
			return err
		}
		r.StartTime = startTime
	}

	if len(aux.EndTime) > 0 {
		endTime, err := time.Parse(layout, aux.EndTime)
		if err != nil {
			return err
		}
		r.EndTime = endTime
	}

	return nil
}

func formatTime(t *time.Time, layout string) string {
	if t != nil {
		return t.Format(layout)
	}
	return ""
}

func (r Report) Validate() error {
	return ValidateReport(r)
}

// Vulnerability represents a single security vulnerability found while running a check.
type Vulnerability struct {
	ID string `json:"id"` // Arbitrary UUID that uniquely identifies the vulnerability in every scan.

	Summary                string  `json:"summary"`                  // Mandatory. Vulnerability title.
	Score                  float32 `json:"score"`                    // Vulnerability severity score. According to CVSSv3 base score.
	AffectedResource       string  `json:"affected_resource"`        // Indicates the concrete resource affected by the vulnerability.
	AffectedResourceString string  `json:"affected_resource_string"` // Optionally indicates a human-readable meaningful version of the AffectedResource.
	Fingerprint            string  `json:"fingerprint"`              // Fingerprint defines the context in where the vulnerability has been found.

	CWEID         uint32   `json:"cwe_id,omitempty"`         // CWE-ID.
	Description   string   `json:"description,omitempty"`    // Vulnerability description.
	Details       string   `json:"details,omitempty"`        // Vulnerability details generated when running the check against the target.
	ImpactDetails string   `json:"impact_details,omitempty"` // Vulnerability impact details.
	Labels        []string `json:"labels,omitempty"`         // A list of labels (strings) to enrich the vulnerability.

	Recommendations []string         `json:"recommendations,omitempty"` // Vulnerability remediation suggestions.
	References      []string         `json:"references,omitempty"`      // Reference URLs for more information.
	Resources       []ResourcesGroup `json:"resources,omitempty"`       // ResourcesGroups found when running the check.
	Attachments     []Attachment     `json:"attachments,omitempty"`     // Attachments found when running the check

	Vulnerabilities []Vulnerability `json:"vulnerabilities"` // Mandatory. Array of identified vulnerabilities.
}

// AddVulnerabilities is a handy method to add one or more Vulnerabilities to the Vulnerability.Vulnerabilities array.
// It's equivalent to v.Vulnerabilities = append(v.Vulnerabilities,vulnerabilities)
func (v *Vulnerability) AddVulnerabilities(vulnerabilities ...Vulnerability) {
	v.Vulnerabilities = append(v.Vulnerabilities, vulnerabilities...)
}

// AggregateScore recalculates the score field for a parent vulnerability.
func (v *Vulnerability) AggregateScore() {
	if len(v.Vulnerabilities) > 0 {
		v.Score = AggregateScore(v.Vulnerabilities)
	}
}

// Severity returns the severity rank for a vulnerability.
func (v Vulnerability) Severity() SeverityRank {
	return RankSeverity(v.Score)
}

// Validate checks if a vulnerability is valid.
func (v Vulnerability) Validate() error {
	return ValidateVulnerability(v)
}

// Attachment found when running the check
type Attachment struct {
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Data        []byte `json:"data"`
}

// ResourcesGroup a self-defined table for resources sharing the same attributes.
// Example:
// Name: Network Resource
// Header: | Hostname | Port | Protocol | Service |
// Rows:
//
//	| www.adevinta.com | 80  | tcp | http |
//	| www.adevinta.com | 443 | tcp | http |
//
// The way the Rows are defined is using a map with values for every key defined
// at the Header attribute.
type ResourcesGroup struct {
	Name   string
	Header []string
	Rows   []map[string]string
}

// https://nvd.nist.gov/vuln-metrics/cvss/
// CVSS v3.0 Ratings
//
// Severity   Base Score Range
// None       0.0
// Low        0.1 - 3.9
// Medium     4.0 - 6.9
// High       7.0 - 8.9
// Critical   9.0 -10.0
const (
	// SeverityThresholdNone defines interesting findings that are not vulnerabilities.
	SeverityThresholdNone = 0
	// SeverityThresholdLow defines vulnerabilities with low impact.
	SeverityThresholdLow = 3.9
	// SeverityThresholdMedium defines vulnerabilities with medium impact.
	SeverityThresholdMedium = 6.9
	// SeverityThresholdHigh defines vulnerabilities with high impact.
	SeverityThresholdHigh = 8.9
	// SeverityThresholdCritical defines vulnerabilities with critical impact.
	SeverityThresholdCritical = 10
)

type SeverityRank int

const (
	// SeverityNone defines interesting findings that are not vulnerabilities.
	SeverityNone SeverityRank = iota
	// SeverityLow defines vulnerabilities with low impact.
	SeverityLow
	// SeverityMedium defines vulnerabilities with medium impact.
	SeverityMedium
	// SeverityHigh defines vulnerabilities with high impact.
	SeverityHigh
	// SeverityCritical defines vulnerabilities with critical impact.
	SeverityCritical
)

type ByScore []Vulnerability

func (v ByScore) Len() int {
	return len(v)
}
func (v ByScore) Swap(i, j int) {
	v[i], v[j] = v[j], v[i]
}
func (v ByScore) Less(i, j int) bool {
	return v[i].Score > v[j].Score
}

// AggregateScore returns an aggregated score for a group of vulnerabilities.
// NOTE: This is currently a placeholder function which returns the maximum severity score.
func AggregateScore(vulnerabilities []Vulnerability) float32 {
	if len(vulnerabilities) == 0 {
		return 0
	}
	sort.Sort(ByScore(vulnerabilities))
	return vulnerabilities[0].Score
}

// RankSeverity returns the severity rank according to predefined score thresholds.
func RankSeverity(score float32) SeverityRank {
	switch {
	case score <= SeverityThresholdNone:
		return SeverityNone
	case score <= SeverityThresholdLow:
		return SeverityLow
	case score <= SeverityThresholdMedium:
		return SeverityMedium
	case score <= SeverityThresholdHigh:
		return SeverityHigh
	default:
		return SeverityCritical
	}
}

// ScoreSeverity returns the maximum score according to a severity rank.
func ScoreSeverity(severity SeverityRank) float32 {
	switch severity {
	case SeverityNone:
		return SeverityThresholdNone
	case SeverityLow:
		return SeverityThresholdLow
	case SeverityMedium:
		return SeverityThresholdMedium
	case SeverityHigh:
		return SeverityThresholdHigh
	case SeverityCritical:
		return SeverityThresholdCritical
	default:
		return SeverityThresholdCritical
	}
}

// SecurityStatus returns a grade from A to F (A is good, F is bad) given a target aggregated score
func SecurityStatus(score float32) string {
	switch {
	case score < 2.0:
		return "A"
	case score <= 3.5:
		return "B"
	case score <= 5.0:
		return "C"
	case score <= 6.5:
		return "D"
	case score <= 8.0:
		return "E"
	default:
		return "F"
	}
}

// ValidateReport validates a Report.
func ValidateReport(r Report) error {
	// Must have basic check information.
	if r.CheckID == "" {
		return errors.New("report is missing check ID")
	}
	if r.ChecktypeName == "" {
		return errors.New("report is missing check type name")
	}
	if r.ChecktypeVersion == "" {
		return errors.New("report is missing check type version")
	}

	// Must have basic check job information.
	if r.Target == "" {
		return errors.New("report is missing target")
	}
	if r.Status == "" {
		return errors.New("report is missing status")
	}

	// Must have a start time.
	if r.StartTime == (time.Time{}) {
		return errors.New("report is missing start time")
	}

	// All vulnerabilities must be valid.
	for _, v := range r.Vulnerabilities {
		err := v.Validate()
		if err != nil {
			return err
		}
	}

	return nil
}

// ValidateVulnerability validates a Vulnerability.
func ValidateVulnerability(v Vulnerability) error {
	if v.Summary == "" {
		return errors.New("vulnerability group is missing summary")
	}
	if v.AffectedResource == "" {
		return errors.New("vulnerability affected resource is missing")
	}
	// Validate vulnerabilities.
	for _, vulnerability := range v.Vulnerabilities {
		err := vulnerability.Validate()
		if err != nil {
			return err
		}

		if len(vulnerability.Vulnerabilities) > 0 {
			return errors.New("child vulnerabilities are not allowed to have children")
		}
	}

	return nil
}
