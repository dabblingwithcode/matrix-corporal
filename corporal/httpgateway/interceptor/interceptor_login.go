package interceptor

import (
	"bytes"
	"devture-matrix-corporal/corporal/configuration"
	"devture-matrix-corporal/corporal/httphelp"
	"devture-matrix-corporal/corporal/matrix"
	"devture-matrix-corporal/corporal/policy"
	"devture-matrix-corporal/corporal/userauth"
	"devture-matrix-corporal/corporal/util"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

// LoginInterceptor is an HTTP request interceptor that handles the /login API path.
//
// Its goal is to authenticate users described in the policy and let them get an access token
// if credentials match.
//
// Requests by users which are not described in the policy (also called non-managed-users) are
// forwarded as-is to the Matrix API server. They may get authenticated or not (we don't care about them).
//
// Managed users (those in the policy), however, are authenticated with us.
// Authentication can happen differently for each user described the policy,
// depending on the user's `authType` and `authCredential` fields.
//
// In any case, if authentication is successful, a special fake "password" is generated,
// and the request is forwarded to the Matrix server's /login API with that password.
// The remote server is expected to be configured properly, so it would understand and trust
// our fake passwords and grant access.
// Those passwords are verified and trusted through the `matrix-shared-secret-auth` plugin for Synapse
// and are generated to match via SharedSecretAuthPasswordGenerator.
type LoginInterceptor struct {
	policyStore                       *policy.Store
	homeserverDomainName              string
	userAuthChecker                   *userauth.Checker
	sharedSecretAuthPasswordGenerator *matrix.SharedSecretAuthPasswordGenerator
	config                            configuration.Misc
}

func NewLoginInterceptor(
	policyStore *policy.Store,
	homeserverDomainName string,
	userAuthChecker *userauth.Checker,
	sharedSecretAuthPasswordGenerator *matrix.SharedSecretAuthPasswordGenerator,
	config configuration.Misc,
) *LoginInterceptor {
	return &LoginInterceptor{
		policyStore:                       policyStore,
		homeserverDomainName:              homeserverDomainName,
		userAuthChecker:                   userAuthChecker,
		sharedSecretAuthPasswordGenerator: sharedSecretAuthPasswordGenerator,
		config:                            config,
	}
}

func (me *LoginInterceptor) Intercept(r *http.Request) InterceptorResponse {

	// Check first if decrypt key and iv are set
	if me.config.DecryptKey == "" || me.config.DecryptIv == "" {
		return createInterceptorErrorResponse(
			logrus.Fields{"config": me.config},
			matrix.ErrorUnknown,
			"Decryption keys missing in config.json",
		)

	}

	loggingContextFields := logrus.Fields{}

	var payload matrix.ApiLoginRequestPayload

	err := httphelp.GetJsonFromRequestBody(r, &payload)
	if err != nil {
		loggingContextFields["err"] = err.Error()
		return createInterceptorErrorResponse(loggingContextFields, matrix.ErrorBadJson, "Bad input")
	}

	loggingContextFields["type"] = payload.Type

	if payload.Type == matrix.LoginTypeToken {
		// This is a Token Authentication request related to SSO (CAS or SAML).
		// Let it pass as-is to the upstream server in order to avoid breaking such login flows.
		return InterceptorResponse{
			Result:               InterceptorResultProxy,
			LoggingContextFields: loggingContextFields,
		}
	}

	if payload.Type != matrix.LoginTypePassword {
		// This is some other unrecognized login flow.
		// It's unknown whether we should let it pass or block it.
		// We'll block it to be on the safe side.
		message := fmt.Sprintf("Denying login type: %s", payload.Type)
		return createInterceptorErrorResponse(loggingContextFields, matrix.ErrorForbidden, message)
	}

	// Proceed handling password authentication..

	policyObj := me.policyStore.Get()
	if policyObj == nil {
		return createInterceptorErrorResponse(loggingContextFields, matrix.ErrorUnknown, "Missing policy")
	}

	if util.IsStringInArray(payload.Identifier.Type, []string{matrix.LoginIdentifierTypeThirdParty, matrix.LoginIdentifierTypePhone}) {
		// This is some 3pid login request.
		// Letting it go through may have security implications, so we only do it if explicitly enabled.

		if policyObj.Flags.Allow3pidLogin {
			// Let it pass as-is to the upstream server in order to avoid breaking such login flows.
			return InterceptorResponse{
				Result:               InterceptorResultProxy,
				LoggingContextFields: loggingContextFields,
			}
		}

		return createInterceptorErrorResponse(loggingContextFields, matrix.ErrorUnknown, "3pid login requests are not allowed on this server")
	}

	userId := ""
	if payload.Identifier.User != "" {
		// New, preferred field
		userId = payload.Identifier.User
	} else {
		// Old deprecated field
		userId = payload.User
	}
	// If it's an encrypted login request, we need to decrypt the credentials.
	if strings.Contains(r.URL.Path, "/encryptedLogin") {

		// We get key and iv from the config, so we can decrypt the credentials
		key := me.config.DecryptKey
		iv := me.config.DecryptIv

		// The userId is the PIN number that we will add to the password later.

		// We decrypt the password field, which contains the encrypted credentials.
		decryptedUsername, decryptedPassword, err := util.ProcessEncryptedUserAuth(payload.Password, key, iv)
		if err != nil {
			logrus.Errorf("Failed to process encrypted user auth: %v", err)
			return createInterceptorErrorResponse(loggingContextFields, matrix.ErrorBadJson, "Failed to process authentication")
		}

		// We append the userId - which is in fact a PIN number that has to be appended to the decryptedPassword
		decryptedPassword = fmt.Sprintf("%s%s", decryptedPassword, userId)
		userId = decryptedUsername
		// Update the payload with the decrypted values
		payload.User = decryptedUsername
		payload.Identifier.User = decryptedUsername
		payload.Password = decryptedPassword

	}

	loggingContextFields["userId"] = payload.User

	userIdFull, err := matrix.DetermineFullUserId(userId, me.homeserverDomainName)
	if err != nil {
		return createInterceptorErrorResponse(loggingContextFields, matrix.ErrorForbidden, "Cannot interpret user id")
	}

	// Replace the logging field with a (potentially) better one
	loggingContextFields["userId"] = userIdFull

	if !matrix.IsFullUserIdOfDomain(userIdFull, me.homeserverDomainName) {
		return createInterceptorErrorResponse(loggingContextFields, matrix.ErrorForbidden, "Rejecting non-own domains")
	}

	userPolicy := policyObj.GetUserPolicyByUserId(userIdFull)
	if userPolicy == nil {
		// Not a user we manage.
		// Let it go through and let the upstream server's policies apply, whatever they may be.
		return InterceptorResponse{
			Result:               InterceptorResultProxy,
			LoggingContextFields: loggingContextFields,
		}
	}

	if !userPolicy.Active {
		return createInterceptorErrorResponse(loggingContextFields, matrix.ErrorUserDeactivated, "Deactivated in policy")
	}

	if userPolicy.AuthType == userauth.UserAuthTypePassthrough {
		// UserAuthTypePassthrough is a special AuthType, authentication for which is not meant to be handled by us.
		// Users are created with an initial password as defined in userPolicy.AuthCredential,
		// but password-management is then potentially left to the homeserver (depending on policyObj.Flags.AllowCustomPassthroughUserPasswords).
		// Authentication always happens at the homeserver.

		// In case the request was encrypted, we need to ensure the payload forwarded to the matrix server contains the modified values.

		newBodyBytes, err := json.Marshal(payload)
		if err != nil {
			return createInterceptorErrorResponse(loggingContextFields, matrix.ErrorUnknown, "Internal error")
		}

		r.Body = io.NopCloser(bytes.NewReader(newBodyBytes))
		r.ContentLength = int64(len(newBodyBytes))

		// If encrypted request, we will also have to redirect the request to the Matrix server's /login API.
		if strings.Contains(r.URL.Path, "/encryptedLogin") {

			r.URL.Path = strings.Replace(r.URL.Path, "/encryptedLogin", "/login", 1)
			r.RequestURI = strings.Replace(r.RequestURI, "/encryptedLogin", "/login", 1)

		}
		return InterceptorResponse{
			Result:               InterceptorResultProxy,
			LoggingContextFields: loggingContextFields,
		}

	}

	// Authentication for all other auth types is handled by us (below)

	loggingContextFields["authType"] = userPolicy.AuthType

	isAuthenticated, err := me.userAuthChecker.Check(
		userIdFull,
		payload.Password,
		userPolicy.AuthType,
		userPolicy.AuthCredential,
	)
	if err != nil {
		loggingContextFields["err"] = err.Error()
		return createInterceptorErrorResponse(loggingContextFields, matrix.ErrorUnknown, "Internal authenticator error")
	}

	if !isAuthenticated {
		return createInterceptorErrorResponse(loggingContextFields, matrix.ErrorForbidden, "Failed authentication")
	}

	// We don't need to do it, but let's ensure the payload uses the full user id.
	payload.User = userIdFull
	payload.Password = me.sharedSecretAuthPasswordGenerator.GenerateForUserId(userIdFull)

	newBodyBytes, err := json.Marshal(payload)
	if err != nil {
		return createInterceptorErrorResponse(loggingContextFields, matrix.ErrorUnknown, "Internal error")
	}

	r.Body = io.NopCloser(bytes.NewReader(newBodyBytes))
	r.ContentLength = int64(len(newBodyBytes))

	return InterceptorResponse{
		Result:               InterceptorResultProxy,
		LoggingContextFields: loggingContextFields,
	}
}
