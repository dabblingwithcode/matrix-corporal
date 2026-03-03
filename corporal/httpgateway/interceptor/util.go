package interceptor

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

func createInterceptorErrorResponse(loggingContextFields logrus.Fields, errorCode, errorMessage string) InterceptorResponse {
	return createInterceptorErrorResponseWithStatus(loggingContextFields, http.StatusForbidden, errorCode, errorMessage)
}

func createInterceptorErrorResponseWithStatus(loggingContextFields logrus.Fields, statusCode int, errorCode, errorMessage string) InterceptorResponse {
	return InterceptorResponse{
		Result:               InterceptorResultDeny,
		LoggingContextFields: loggingContextFields,
		StatusCode:           statusCode,
		ErrorCode:            errorCode,
		ErrorMessage:         errorMessage,
	}
}
