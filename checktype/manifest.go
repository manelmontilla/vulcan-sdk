package checktype

import (
	"fmt"

	"database/sql/driver"
	"encoding/json"
	"errors"

	"github.com/manelmontilla/toml"
)

// AssetType defines the valid types of assets a check can accept.
type AssetType int

const (
	// IP represents an IP assettype.
	IP AssetType = iota
	// Hostname represents a hostname assettype.
	Hostname
	// DomainName represents an domain name assettype.
	DomainName
	// AWSAccount represents an AWS account assettype.
	AWSAccount
	// IPRange represents an IP range assettype.
	IPRange
	// DockerImage represents a DockerImage asset type.
	DockerImage
	// WebAddress represents a WebAddress asset type.
	WebAddress
	// GitRepository represents a git repo asset type.
	GitRepository
)

// AssetTypeStrings contains the mappings between an [AssetType] and its string
// representation.
var AssetTypeStrings = map[AssetType]string{
	IP:            "IP",
	Hostname:      "Hostname",
	DomainName:    "DomainName",
	AWSAccount:    "AWSAccount",
	IPRange:       "IPRange",
	DockerImage:   "DockerImage",
	WebAddress:    "WebAddress",
	GitRepository: "GitRepository",
}

// MarshalText returns string representation of a AssetType instance.
func (a *AssetType) MarshalText() (text []byte, err error) {
	s, err := a.String()
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// UnmarshalText creates a AssetType from its string representation.
func (a *AssetType) UnmarshalText(text []byte) error {
	val := string(text)
	for k, v := range AssetTypeStrings {
		if v == val {
			*a = k
			return nil
		}
	}
	return fmt.Errorf("Error value %s is not a valid AssetType value", val)
}

func (a *AssetType) String() (string, error) {
	if _, ok := AssetTypeStrings[*a]; !ok {
		return "", fmt.Errorf("value: %d is not a valid string representation of AssetType", a)
	}
	return AssetTypeStrings[*a], nil
}

// MarshalJSON encodes an [AssetType] value as JSON.
func (a AssetType) MarshalJSON() ([]byte, error) {
	content, err := a.String()
	if err != nil {
		return nil, err
	}
	return []byte(content), nil
}

// UnmarshalJSON sets an [*AssetType] to the value represented by
// the specified data.
func (a *AssetType) UnmarshalJSON(data []byte) error {
	if a == nil {
		return errors.New("AssetType set to a nil pointer")
	}
	name := string(data)
	at, err := NewAssetType(name)
	if err != nil {
		return err
	}
	*a = at
	return nil
}

// Value returns an AssetType as a value suitable to be stored in a db.
func (a AssetType) Value() (driver.Value, error) {
	value, err := a.String()
	if err != nil {
		return nil, err
	}
	return []byte(value), nil
}

// Scan stores a value stored in a db into an AssetType.
func (a *AssetType) Scan(src interface{}) error {
	var source string
	switch t := src.(type) {
	case string:
		source = t
	case []byte:
		source = string(t)
	case nil:
		source = ""
	default:
		return errors.New("invalid db value for an AssetType")
	}
	at, err := NewAssetType(source)
	if err != nil {
		return err
	}
	*a = at
	return nil
}

// NewAssetType creates a new [AssetType] from its string representation.
func NewAssetType(str string) (AssetType, error) {
	at := AssetType(0)
	err := at.UnmarshalText([]byte(str))
	if err != nil {
		return 0, err
	}
	return at, nil
}

// AssetTypes represents and array of asset types supported by a concrete
// checktype.
type AssetTypes []*AssetType

// Strings converts a slice of AssetType's into a slice of strings.
func (a AssetTypes) Strings() ([]string, error) {
	res := []string{}
	for _, s := range a {
		txt, err := s.String()
		if err != nil {
			return nil, err
		}
		res = append(res, txt)
	}
	return res, nil
}

// Returns a representation of [AssetTypes] as a string, which is a JSON array.
func (a AssetTypes) String() (string, error) {
	names, err := a.Strings()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s", names), nil
}

// MarshalJSON encodes an [AssetType] as a json value, that is: a string.
func (a AssetTypes) MarshalJSON() ([]byte, error) {
	atypes, err := a.Strings()
	if err != nil {
		return nil, err
	}
	content := "["
	first := true
	for _, at := range atypes {
		if !first {
			content = content + ","
		} else {
			first = false
		}
		content = fmt.Sprintf("%s\"%s\"", content, at)
	}
	content = content + "]"
	return []byte(content), nil
}

// UnmarshalJSON sets an [*AssetTypes] to the value represented by
// the specified data.
func (a *AssetTypes) UnmarshalJSON(data []byte) error {
	if a == nil {
		return errors.New("AssetType set to a nil pointer")
	}
	var names []string
	err := json.Unmarshal(data, &names)
	if err != nil {
		return err
	}
	at, err := NewAssetTypes(names...)
	if err != nil {
		return err
	}
	*a = at
	return nil
}

// Value returns an [*AssetTypes] as a value suitable to be stored in a db.
func (a AssetTypes) Value() (driver.Value, error) {
	names, err := a.Strings()
	if err != nil {
		return nil, err
	}
	value, err := json.Marshal(names)
	if err != nil {
		return nil, err
	}
	return []byte(value), nil
}

// Scan stores a value stored in a db into an [*AssetTypes].
func (a *AssetTypes) Scan(src interface{}) error {
	var source []byte
	switch t := src.(type) {
	case string:
		source = []byte(t)
	case []byte:
		source = t
	case nil:
		source = nil
	default:
		return errors.New("invalid db value for an AssetType")
	}
	var names []string
	err := json.Unmarshal(source, &names)
	if err != nil {
		return err
	}
	at, err := NewAssetTypes(names...)
	if err != nil {
		return err
	}
	*a = at
	return nil
}

// NewAssetTypes returns set of [AssetType]s from a list of strings. If any of
// the strings iin the list is not the name of a valid [AssetType] the function
// returns an error.
func NewAssetTypes(strs ...string) (AssetTypes, error) {
	var ats AssetTypes
	for _, str := range strs {
		at, err := NewAssetType(str)
		if err != nil {
			return nil, err
		}
		ats = append(ats, &at)
	}
	return ats, nil
}

// Manifest contains all the data defined in the manifest.
type Manifest struct {
	Description  string
	Timeout      int
	Options      string
	RequiredVars []string
	QueueName    string
	AssetTypes   AssetTypes
}

// UnmarshalOptions returns the options interpreted as json.
func (m Manifest) UnmarshalOptions() (map[string]interface{}, error) {
	if m.Options == "" {
		return nil, nil
	}
	var options = make(map[string]interface{})
	err := json.Unmarshal([]byte(m.Options), &options)
	if err != nil {
		return nil, err
	}
	return options, nil
}

// ReadManifest reads a manifest file.
func ReadManifest(path string) (Manifest, error) {
	d := Manifest{}
	m, err := toml.DecodeFile(path, &d)
	if err != nil {
		return d, err
	}
	if !m.IsDefined("Description") {
		return d, errors.New("Description field is mandatory")
	}

	if m.IsDefined("Options") {
		dummy := make(map[string]interface{})
		err = json.Unmarshal([]byte(d.Options), &dummy)
		if err != nil {
			err = fmt.Errorf("Error reading manifest file, Options field is not a valid json: %v", err)
			return d, err
		}
	}
	return d, nil
}
