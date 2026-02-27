package handler

import (
	"devture-matrix-corporal/corporal/httphelp"
	"devture-matrix-corporal/corporal/logstore"
	"devture-matrix-corporal/corporal/matrix"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

const (
	defaultLogsLimit  = 50
	maxLogsLimit     = 500
	defaultLogsOffset = 0
)

type LogsApiHandlerRegistrator struct {
	store *logstore.Store
}

func NewLogsApiHandlerRegistrator(store *logstore.Store) *LogsApiHandlerRegistrator {
	return &LogsApiHandlerRegistrator{store: store}
}

func (me *LogsApiHandlerRegistrator) RegisterRoutesWithRouter(router *mux.Router) {
	// Register specific path before generic so DELETE /_matrix/corporal/logs/{logId} is matched first
	router.HandleFunc("/_matrix/corporal/logs/{logId}", me.actionLogDeleteOne).Methods("DELETE")
	router.HandleFunc("/_matrix/corporal/logs", me.actionLogsList).Methods("GET")
	router.HandleFunc("/_matrix/corporal/logs", me.actionLogsDeleteAll).Methods("DELETE")
	router.HandleFunc("/_matrix/corporal/logs/config", me.actionLogsConfigGet).Methods("GET")
	router.HandleFunc("/_matrix/corporal/logs/config", me.actionLogsConfigPut).Methods("PUT")
}

type apiLogsConfigPayload struct {
	Levels map[string]bool `json:"levels"`
}

func (me *LogsApiHandlerRegistrator) actionLogsList(w http.ResponseWriter, r *http.Request) {
	limit := defaultLogsLimit
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
			if limit > maxLogsLimit {
				limit = maxLogsLimit
			}
		}
	}
	offset := defaultLogsOffset
	if s := r.URL.Query().Get("offset"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			offset = n
		}
	}

	logs, total := me.store.List(limit, offset)
	Respond(w, http.StatusOK, map[string]interface{}{
		"logs":  logs,
		"total": total,
	})
}

func (me *LogsApiHandlerRegistrator) actionLogDeleteOne(w http.ResponseWriter, r *http.Request) {
	logId := mux.Vars(r)["logId"]
	if logId == "" {
		Respond(w, http.StatusBadRequest, ApiResponseError{
			ErrorCode:    matrix.ErrorMissingParameter,
			ErrorMessage: "Missing log id",
		})
		return
	}
	if !me.store.Delete(logId) {
		Respond(w, http.StatusNotFound, ApiResponseError{
			ErrorCode:    matrix.ErrorNotFound,
			ErrorMessage: "Log entry not found",
		})
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusNoContent)
}

func (me *LogsApiHandlerRegistrator) actionLogsDeleteAll(w http.ResponseWriter, r *http.Request) {
	me.store.DeleteAll()
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusNoContent)
}

func (me *LogsApiHandlerRegistrator) actionLogsConfigGet(w http.ResponseWriter, r *http.Request) {
	levels := me.store.LevelsEnabled()
	Respond(w, http.StatusOK, map[string]interface{}{
		"levels": levels,
	})
}

func (me *LogsApiHandlerRegistrator) actionLogsConfigPut(w http.ResponseWriter, r *http.Request) {
	var payload apiLogsConfigPayload

	err := httphelp.GetJsonFromRequestBody(r, &payload)
	if err != nil {
		Respond(w, http.StatusBadRequest, ApiResponseError{
			ErrorCode:    ErrorCodeBadJson,
			ErrorMessage: "Bad body payload",
		})
		return
	}

	if len(payload.Levels) == 0 {
		Respond(w, http.StatusBadRequest, ApiResponseError{
			ErrorCode:    ErrorCodeMissingParameter,
			ErrorMessage: "Missing levels",
		})
		return
	}

	me.store.SetLevelsEnabled(payload.Levels)

	Respond(w, http.StatusOK, map[string]interface{}{
		"levels": me.store.LevelsEnabled(),
	})
}

// Ensure interface is implemented
var _ httphelp.HandlerRegistrator = &LogsApiHandlerRegistrator{}
