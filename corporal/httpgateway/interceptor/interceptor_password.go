package interceptor

import (
	"bytes"
	"devture-matrix-corporal/corporal/configuration"
	"devture-matrix-corporal/corporal/httphelp"
	"devture-matrix-corporal/corporal/matrix"
	"devture-matrix-corporal/corporal/util"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

// PasswordChangeInterceptor handles POST .../account/encryptedPassword:
// decrypts auth, composes canonical account/password body, rewrites path and proxies.
type PasswordChangeInterceptor struct {
	config configuration.Misc
}

// NewPasswordChangeInterceptor creates an interceptor that decrypts encrypted password-change payloads and proxies to account/password.
func NewPasswordChangeInterceptor(config configuration.Misc) *PasswordChangeInterceptor {
	return &PasswordChangeInterceptor{config: config}
}

// Intercept implements interceptor.Interceptor.
func (me *PasswordChangeInterceptor) Intercept(r *http.Request) InterceptorResponse {
	if me.config.DecryptKey == "" {
		return createInterceptorErrorResponseWithStatus(
			logrus.Fields{"config": me.config},
			http.StatusInternalServerError,
			matrix.ErrorUnknown,
			"Decryption keys missing in config.json",
		)
	}

	loggingContextFields := logrus.Fields{}

	var payload matrix.ApiAccountPasswordEncryptedRequestPayload
	err := httphelp.GetJsonFromRequestBody(r, &payload)
	if err != nil {
		loggingContextFields["err"] = err.Error()
		return createInterceptorErrorResponseWithStatus(loggingContextFields, http.StatusBadRequest, matrix.ErrorBadJson, "Bad input")
	}

	var authObj map[string]interface{}
	if len(payload.Auth) == 0 {
		return createInterceptorErrorResponseWithStatus(loggingContextFields, http.StatusBadRequest, matrix.ErrorBadJson, "Missing auth")
	}
	if err = json.Unmarshal(payload.Auth, &authObj); err != nil {
		loggingContextFields["err"] = err.Error()
		return createInterceptorErrorResponseWithStatus(loggingContextFields, http.StatusBadRequest, matrix.ErrorBadJson, "Invalid auth object")
	}

	encryptedPassword, ok := authObj["password"].(string)
	if !ok || encryptedPassword == "" {
		return createInterceptorErrorResponseWithStatus(loggingContextFields, http.StatusBadRequest, matrix.ErrorBadJson, "Missing auth.password")
	}

	identifierRaw, ok := authObj["identifier"]
	if !ok {
		return createInterceptorErrorResponseWithStatus(loggingContextFields, http.StatusBadRequest, matrix.ErrorBadJson, "Missing auth.identifier")
	}
	identifierBytes, err := json.Marshal(identifierRaw)
	if err != nil {
		loggingContextFields["err"] = err.Error()
		return createInterceptorErrorResponseWithStatus(loggingContextFields, http.StatusBadRequest, matrix.ErrorBadJson, "Invalid auth.identifier")
	}

	pin, err := parseIdentifierPIN(identifierBytes)
	if err != nil {
		loggingContextFields["err"] = err.Error()
		return createInterceptorErrorResponseWithStatus(loggingContextFields, http.StatusBadRequest, matrix.ErrorBadJson, "Invalid auth.identifier")
	}

	decryptedUsername, decryptedPassword, err := util.ProcessEncryptedUserAuth(encryptedPassword, me.config.DecryptKey)
	if err != nil {
		logrus.Errorf("Failed to process encrypted user auth: %v", err)
		return createInterceptorErrorResponseWithStatus(loggingContextFields, http.StatusBadRequest, matrix.ErrorBadJson, "Failed to process authentication")
	}

	composedPassword := fmt.Sprintf("%s%s", decryptedPassword, pin)
	loggingContextFields["userId"] = decryptedUsername

	// Keep the existing auth object (including UIA `session` and unknown keys),
	// only replacing credential-specific fields.
	authObj["password"] = composedPassword
	authObj["identifier"] = matrix.ApiLoginRequestIdentifier{
		Type: matrix.LoginIdentifierTypeUser,
		User: decryptedUsername,
	}

	authBytes, err := json.Marshal(authObj)
	if err != nil {
		return createInterceptorErrorResponseWithStatus(loggingContextFields, http.StatusInternalServerError, matrix.ErrorUnknown, "Internal error")
	}

	out := matrix.ApiAccountPasswordRequestPayload{
		Auth:          authBytes,
		LogoutDevices: payload.LogoutDevices,
		NewPassword:   payload.NewPassword,
	}

	newBodyBytes, err := json.Marshal(out)
	if err != nil {
		return createInterceptorErrorResponseWithStatus(loggingContextFields, http.StatusInternalServerError, matrix.ErrorUnknown, "Internal error")
	}

	r.Body = io.NopCloser(bytes.NewReader(newBodyBytes))
	r.ContentLength = int64(len(newBodyBytes))
	r.URL.Path = strings.Replace(r.URL.Path, "/encryptedPassword", "/password", 1)
	r.RequestURI = strings.Replace(r.RequestURI, "/encryptedPassword", "/password", 1)

	return InterceptorResponse{
		Result:               InterceptorResultProxy,
		LoggingContextFields: loggingContextFields,
	}
}

// parseIdentifierPIN extracts the PIN from identifier (string or { "user": "<PIN>" }).
func parseIdentifierPIN(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("empty identifier")
	}
	// Try as string first (e.g. "1234")
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	// Try as object with user (e.g. { "user": "1234" })
	var o struct {
		User string `json:"user"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		return "", fmt.Errorf("identifier must be string or { \"user\": \"<PIN>\" }: %w", err)
	}
	if o.User == "" {
		return "", fmt.Errorf("identifier.user is empty")
	}
	return o.User, nil
}
