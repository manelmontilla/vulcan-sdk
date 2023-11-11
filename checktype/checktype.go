// Package checktype allows to define and parse checktypes that implement
// [Vulcan security checks]
//
// [Vulcan security checks]: https://github.com/adevinta/vulcan-checks
package checktype

import (
	"encoding/json"
	"errors"
	"fmt"
)

var (
	// MetadataLabel defines the name of the label of a container image that
	// stores the toml representation of the metadata of a checktype.
	MetadataLabel = "metadata"
)

// Options represents the options defined for a checktype
type Options struct {
	Options map[string]interface{}
}

// NewOptions returns options initialized with the provided values.
func NewOptions(values map[string]interface{}) Options {
	return Options{Options: values}
}

// MarshalJSON encodes an [Options] value as JSON.
func (o Options) MarshalJSON() ([]byte, error) {
	content, err := json.Marshal(o.Options)
	if err != nil {
		return nil, err
	}
	return []byte(content), nil
}

// UnmarshalJSON sets the contents of [*Options] to the value represented by
// the specified data.
func (o *Options) UnmarshalJSON(data []byte) error {
	if o == nil {
		return errors.New("AssetType set to a nil pointer")
	}
	var options map[string]interface{}
	err := json.Unmarshal(data, &options)
	if err != nil {
		return err
	}
	*&o.Options = options
	return nil
}

// RequiredVars define the  list of required vars of a checktype.
type RequiredVars struct {
	RequiredVars []string
}

// NewRequiredVars creates a [RequiredVars] value from a slice of required
// environments variable names.
func NewRequiredVars(rv []string) RequiredVars {
	return RequiredVars{rv}
}

// MarshalJSON encodes a [RequiredVars] value as JSON.
func (r RequiredVars) MarshalJSON() ([]byte, error) {
	content, err := json.Marshal(r.RequiredVars)
	if err != nil {
		return nil, err
	}
	return []byte(content), nil
}

// UnmarshalJSON sets the contents of the [*RequiredVars] to the value
// represented by the specified data.
func (r *RequiredVars) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("AssetType set to a nil pointer")
	}
	var rv []string
	err := json.Unmarshal(data, &rv)
	if err != nil {
		return err
	}
	*r = RequiredVars{RequiredVars: rv}
	return nil
}

// Checktype contains the information of a security check.
type Checktype struct {
	Name         string       `json:"name"`
	Description  string       `json:"description"`
	Timeout      int          `json:"timeout"`
	Image        string       `json:"image"`
	Options      Options      `json:"options,omitempty"`
	RequiredVars RequiredVars `json:"required_vars" db:"required_vars"`
	Assets       AssetTypes   `json:"assets" db:"assets"`
}

// FromManifest returns the [CheckType] representing the given manifest
// with the specified name and image.
func FromManifest(m Manifest, image, name string) (Checktype, error) {
	options, err := m.UnmarshalOptions()
	if err != nil {
		return Checktype{}, fmt.Errorf("invalid options in manifest %w", err)
	}
	_, err = m.AssetTypes.Strings()
	if err != nil {
		return Checktype{}, fmt.Errorf("invalid asset types in manifest %w", err)
	}
	ct := Checktype{
		Name:         name,
		Description:  m.Description,
		Timeout:      m.Timeout,
		Image:        image,
		Options:      NewOptions(options),
		RequiredVars: NewRequiredVars(m.RequiredVars),
		Assets:       m.AssetTypes,
	}
	return ct, nil
}
