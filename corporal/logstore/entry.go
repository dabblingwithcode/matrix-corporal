package logstore

import "time"

// Entry is a single stored log entry.
type Entry struct {
	ID        string                 `json:"id"`
	Time      time.Time              `json:"time"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}
