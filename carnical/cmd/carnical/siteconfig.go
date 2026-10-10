// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"time"
	"unicode/utf8"
)

const maxSiteConfigBytes = 64 << 10

// loadSiteConfig uses registered CLI types and validators rather than a second
// set of defaults. Explicit CLI flags override file settings. Files are operator
// configuration, never customer-submitted or automatically fetched. It returns
// the settings that were stored encrypted, so that errors can leave them out.
func loadSiteConfig(path string, flags *flag.FlagSet) (map[string]string, error) {
	data, err := readSiteFile(path, maxSiteConfigBytes, false)
	if err != nil {
		return nil, fmt.Errorf("site configuration: %w", err)
	}
	if !utf8.Valid(data) {
		return nil, errors.New("site configuration is not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("site configuration must be a JSON object")
	}
	seen := map[string]bool{}
	values := map[string]string{}
	var encrypted *sitePrivate
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, errors.New("invalid site configuration field")
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return nil, errors.New("duplicate site configuration field")
		}
		seen[name] = true
		switch name {
		case "version":
			value, err := dec.Token()
			if err != nil || value != json.Number("1") {
				return nil, errors.New("site configuration version must be 1")
			}
		case "flags":
			if err := readSiteFlags(dec, flags, values, false); err != nil {
				return nil, err
			}
		case "private":
			private, err := readSitePrivate(dec)
			if err != nil {
				return nil, err
			}
			encrypted = private

		default:
			return nil, fmt.Errorf("unknown site configuration field %q", name)
		}
	}
	if token, err := dec.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("invalid site configuration object")
	}
	if !seen["version"] || !seen["flags"] {
		return nil, errors.New("site configuration requires version and flags")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data in site configuration")
	}
	private := map[string]string{}
	if encrypted != nil {
		keyPath := ""
		if keyFlag := flags.Lookup("config-key-file"); keyFlag != nil {
			keyPath = keyFlag.Value.String()
		}
		plain, err := openSiteSettings(encrypted, keyPath)
		if err != nil {
			return nil, err
		}
		defer clear(plain)
		if !utf8.Valid(plain) {
			return nil, errors.New("encrypted site settings are not UTF-8")
		}
		privateDec := json.NewDecoder(bytes.NewReader(plain))
		privateDec.UseNumber()
		inClear := make(map[string]bool, len(values))
		for name := range values {
			inClear[name] = true
		}
		if err := readSiteFlags(privateDec, flags, values, true); err != nil {
			return nil, err
		}
		if _, err := privateDec.Token(); err != io.EOF {
			return nil, errors.New("trailing encrypted site settings")
		}
		for name, value := range values {
			if !inClear[name] {
				private[name] = value
			}
		}
	}
	explicit := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	for name, value := range values {
		if !explicit[name] {
			if err := flags.Set(name, value); err != nil {
				return nil, fmt.Errorf("invalid site configuration flag %q", name)
			}
		}
	}
	return private, nil
}

// Both clear and encrypted settings use the same strict parser. Duplicate names
// across the two sections are refused, including when CLI flags override them.
func readSiteFlags(dec *json.Decoder, flags *flag.FlagSet, values map[string]string, private bool) error {
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return errors.New("site configuration flags must be an object")
	}
	for dec.More() {
		key, err := dec.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return errors.New("invalid site configuration flag")
		}
		if _, duplicate := values[name]; duplicate {
			return fmt.Errorf("duplicate site configuration flag %q", name)
		}
		setting := flags.Lookup(name)
		if setting == nil || name == "config" || name == "config-key-file" || name == "check" || name == "check-origin" || name == "check-origin-http" || name == "probe" || name == "version" || (private && !privateSiteFlag(name)) {
			return fmt.Errorf("unsupported site configuration flag %q", name)
		}
		value, err := dec.Token()
		if err != nil {
			return fmt.Errorf("invalid site configuration flag %q", name)
		}
		text, err := siteFlagValue(setting, value)
		if err != nil {
			return fmt.Errorf("site configuration flag %q: %w", name, err)
		}
		values[name] = text
	}
	if token, err := dec.Token(); err != nil || token != json.Delim('}') {
		return errors.New("invalid site configuration flags")
	}
	return nil
}

func readSitePrivate(dec *json.Decoder) (*sitePrivate, error) {
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return nil, errors.New("encrypted site settings must be an object")
	}
	values := map[string]string{}
	for dec.More() {
		key, err := dec.Token()
		name, ok := key.(string)
		if err != nil || !ok || (name != "key-id" && name != "sealed") {
			return nil, errors.New("unknown encrypted site field")
		}
		if _, duplicate := values[name]; duplicate {
			return nil, errors.New("duplicate encrypted site field")
		}
		value, err := dec.Token()
		text, ok := value.(string)
		if err != nil || !ok || text == "" {
			return nil, errors.New("invalid encrypted site field")
		}
		values[name] = text
	}
	if token, err := dec.Token(); err != nil || token != json.Delim('}') || len(values) != 2 {
		return nil, errors.New("encrypted site settings require key-id and sealed")
	}
	return &sitePrivate{KeyID: values["key-id"], Sealed: values["sealed"]}, nil
}

func siteFlagValue(setting *flag.Flag, value any) (string, error) {
	getter, ok := setting.Value.(flag.Getter)
	if !ok {
		return "", errors.New("unsupported flag type")
	}
	switch getter.Get().(type) {
	case string:
		if text, ok := value.(string); ok {
			return text, nil
		}
		return "", errors.New("must be a JSON string")
	case bool:
		if b, ok := value.(bool); ok {
			return strconv.FormatBool(b), nil
		}
		return "", errors.New("must be a JSON boolean")
	case time.Duration:
		if text, ok := value.(string); ok {
			if _, err := time.ParseDuration(text); err == nil {
				return text, nil
			}
		}
		return "", errors.New("must be a duration string such as 2s")
	case int, int64:
		if n, ok := value.(json.Number); ok {
			bits := 64
			if _, native := getter.Get().(int); native {
				bits = strconv.IntSize
			}
			if _, err := strconv.ParseInt(string(n), 10, bits); err == nil {
				return string(n), nil
			}
		}
		return "", errors.New("must be a representable JSON integer")
	case float64:
		if n, ok := value.(json.Number); ok {
			if _, err := strconv.ParseFloat(string(n), 64); err == nil {
				return string(n), nil
			}
		}
		return "", errors.New("must be a finite JSON number")
	default:
		return "", errors.New("unsupported flag type")
	}
}
