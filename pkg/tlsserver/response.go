package tlsserver

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

// WriteBadRequest logs and respond with bad request error status code and log error
func (srv *TLSServer) WriteBadRequest(resp http.ResponseWriter, errMsg string) {
	logrus.Errorf(errMsg)
	http.Error(resp, errMsg, http.StatusBadRequest)
}

// WriteInternalError logs and responds with internal server error status code and log error
func (srv *TLSServer) WriteInternalError(resp http.ResponseWriter, errMsg string) {
	logrus.Errorf(errMsg)
	http.Error(resp, errMsg, http.StatusInternalServerError)
}

// WriteNotFound logs and respond with 404 resource not found
func (srv *TLSServer) WriteNotFound(resp http.ResponseWriter, errMsg string) {
	logrus.Errorf(errMsg)
	http.Error(resp, errMsg, http.StatusNotFound)
}

// WriteNotImplemented respond with 501 not implemented
func (srv *TLSServer) WriteNotImplemented(resp http.ResponseWriter, errMsg string) {
	logrus.Errorf(errMsg)
	http.Error(resp, errMsg, http.StatusNotImplemented)
}

// WriteUnauthorized logs and respond with unauthorized status code and log error
func (srv *TLSServer) WriteUnauthorized(resp http.ResponseWriter, errMsg string) {
	logrus.Errorf(errMsg)
	http.Error(resp, errMsg, http.StatusUnauthorized)
}
