package logstore

import (
	"github.com/sirupsen/logrus"
)

// Hook is a logrus hook that forwards log entries to a Store.
type Hook struct {
	store *Store
}

// NewHook returns a logrus hook that adds entries to the given store.
func NewHook(store *Store) *Hook {
	return &Hook{store: store}
}

// Levels returns the log levels this hook handles.
func (h *Hook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire is called when a log entry is emitted.
func (h *Hook) Fire(entry *logrus.Entry) error {
	if !h.store.shouldStoreLevel(entry.Level.String()) {
		return nil
	}

	fields := make(map[string]interface{}, len(entry.Data))
	for k, v := range entry.Data {
		fields[k] = v
	}
	h.store.Add(Entry{
		Time:    entry.Time,
		Level:   entry.Level.String(),
		Message: entry.Message,
		Fields:  fields,
	})
	return nil
}
