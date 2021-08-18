package tlsserver

import (
	"fmt"
	"net/http"
)

const AuthTypeBasic = "basic"
const AuthTypeDigest = "digest"
const AuthTypeJWT = "jwt"
const AuthTypeCert = "cert"

// HttpAuthenticator chains the selected authenticators
type HttpAuthenticator struct {
	BasicAuth *BasicAuthenticator
	CertAuth  *CertAuthenticator
	JwtAuth   *JWTAuthenticator
}

// AuthenticateRequest
// Checks in order: client certificate, JWT bearer, Basic
// Returns an error if authentication failed
func (hauth *HttpAuthenticator) AuthenticateRequest(resp http.ResponseWriter, req *http.Request) error {
	if hauth.CertAuth != nil {
		err := hauth.CertAuth.AuthenticateRequest(resp, req)
		if err == nil {
			return nil
		}
	}
	if hauth.JwtAuth != nil {
		err := hauth.JwtAuth.AuthenticateRequest(resp, req)
		if err == nil {
			return nil
		}
	}
	if hauth.BasicAuth != nil {
		err := hauth.BasicAuth.AuthenticateRequest(resp, req)
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("Unauthenticated")
}

// Create a new HTTP authenticator
// Use .AuthenticateRequest() to authenticate the incoming request
//  verifyUsernamePassword is the handler that validates the loginID and secret
func NewHttpAuthenticator(
	verifyUsernamePassword func(loginID, secret string) error) *HttpAuthenticator {
	ha := &HttpAuthenticator{
		BasicAuth: NewBasicAuthenticator(verifyUsernamePassword),
		JwtAuth:   NewJWTAuthenticator(nil, verifyUsernamePassword),
		CertAuth:  NewCertAuthenticator(),
	}
	return ha
}
