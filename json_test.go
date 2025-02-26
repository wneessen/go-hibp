// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev> et al
//
// SPDX-License-Identifier: MIT

package hibp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAPIDate_UnmarshalJSON(t *testing.T) {
	type data struct {
		String string  `json:"string"`
		Date   APIDate `json:"date"`
	}
	t.Run("API date in format 2006-01-02", func(t *testing.T) {
		jsonString := `{"string":"test","date":"2021-01-02"}`
		var d data
		err := json.Unmarshal([]byte(jsonString), &d)
		if err != nil {
			t.Error(err)
		}
		if d.String != "test" {
			t.Errorf("String is not test")
		}
		if d.Date.Time.Year() != 2021 {
			t.Errorf("expected year to be %d, got %d", 2021, d.Date.Time.Year())
		}
		if d.Date.Time.Month() != 1 {
			t.Errorf("expected month to be %d, got %d", 1, d.Date.Time.Month())
		}
		if d.Date.Time.Day() != 2 {
			t.Errorf("expected day to be %d, got %d", 2, d.Date.Time.Day())
		}
	})
	t.Run("API date in format ISO8601", func(t *testing.T) {
		jsonString := `{"string":"test","date":"2021-01-02T00:00:00"}`
		var d data
		err := json.Unmarshal([]byte(jsonString), &d)
		if err != nil {
			t.Error(err)
		}
		if d.String != "test" {
			t.Errorf("String is not test")
		}
		if d.Date.Time.Year() != 2021 {
			t.Errorf("expected year to be %d, got %d", 2021, d.Date.Time.Year())
		}
		if d.Date.Time.Month() != 1 {
			t.Errorf("expected month to be %d, got %d", 1, d.Date.Time.Month())
		}
		if d.Date.Time.Day() != 2 {
			t.Errorf("expected day to be %d, got %d", 2, d.Date.Time.Day())
		}
	})
	t.Run("API date in unsupported format", func(t *testing.T) {
		jsonString := `{"string":"test","date":"2021-01-02T00:00:00Z"}`
		var d data
		err := json.Unmarshal([]byte(jsonString), &d)
		if err == nil {
			t.Errorf("expected error, got nil")
		}
		expErr := "failed to parse JSON string as API date: unknown date format"
		if !strings.EqualFold(err.Error(), expErr) {
			t.Errorf("expected error %q, got %q", expErr, err.Error())
		}
	})
	t.Run("API date with invalid date should fail", func(t *testing.T) {
		jsonString := `{"string":"test","date":"2020-00-02T00:00:00"}`
		var d data
		err := json.Unmarshal([]byte(jsonString), &d)
		if err == nil {
			t.Error("expected date parsing to fail")
		}
		if !strings.Contains(err.Error(), "failed to parse JSON string as API date") {
			t.Errorf("expected error to contain 'failed to parse JSON string as API date', got %q", err.Error())
		}
	})
	t.Run("API date with null value should be nil", func(t *testing.T) {
		jsonString := `{"string":"test","date":null}`
		var d data
		err := json.Unmarshal([]byte(jsonString), &d)
		if err != nil {
			t.Error(err)
		}
		if d.String != "test" {
			t.Errorf("String is not test")
		}
		if d.Date.Time.Year() != 1 {
			t.Errorf("expected year to be %d, got %d", 1, d.Date.Time.Year())
		}
		if d.Date.Time.Month() != 1 {
			t.Errorf("expected month to be %d, got %d", 1, d.Date.Time.Month())
		}
		if d.Date.Time.Day() != 1 {
			t.Errorf("expected day to be %d, got %d", 1, d.Date.Time.Day())
		}
	})
}
