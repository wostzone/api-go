package tlsserver

import (
	"fmt"
	"net/http"
)

// CertAuthenticator verifies the client certificate authentication is used
// This simply checks if a client certificate is active and assumes that having one is sufficient to pass auth
type CertAuthenticator struct {
}

// AuthenticateRequest
// The real check happens by the TLS server that verifies it is signed by the CA.
// Returns an error if no client certificate is used
func (hauth *CertAuthenticator) AuthenticateRequest(resp http.ResponseWriter, req *http.Request) error {
	if len(req.TLS.PeerCertificates) == 0 {
		return fmt.Errorf("CertAuthentication: No client certificate used")
	}

	return nil
}

// Create a new HTTP authenticator
// Use .AuthenticateRequest() to authenticate the incoming request
func NewCertAuthenticator() *CertAuthenticator {
	ca := &CertAuthenticator{}
	return ca
}
