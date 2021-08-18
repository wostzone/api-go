package tlsserver

import (
	"fmt"
	"net/http"
)

// BasicAuthenticator decodes the authentication method used in the request and authenticates the user
type BasicAuthenticator struct {
	// the password verification handler
	verifyUsernamePassword func(username, password string) error
}

// AuthenticateRequest
// Checks in order: client certificate, JWT bearer, Basic
// Returns an error if authentication failed
func (bauth *BasicAuthenticator) AuthenticateRequest(resp http.ResponseWriter, req *http.Request) error {
	username, password, ok := req.BasicAuth()
	if !ok {
		return fmt.Errorf("BasicAuthenticator:Missing Basic Auth")
	}
	err := bauth.verifyUsernamePassword(username, password)
	if err != nil {
		return err
	}
	return nil
}

// NewBasicAuthenticator creates a new HTTP Basic authenticator
//  verifyUsernamePassword is the handler that validates the loginID and secret
func NewBasicAuthenticator(verifyUsernamePassword func(loginID, secret string) error) *BasicAuthenticator {
	ba := &BasicAuthenticator{
		verifyUsernamePassword: verifyUsernamePassword,
	}
	return ba
}
