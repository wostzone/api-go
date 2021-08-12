// Package servetls with TLS server for use by plugins and testing
package tlsserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// Simple TLS Server
type TLSServer struct {
	address        string
	port           uint
	caCertPath     string
	serverCertPath string
	serverKeyPath  string
	httpServer     *http.Server
	router         *mux.Router
	authenticator  func(http.ResponseWriter, *http.Request) error
}

// AddHandler adds a new handler for a path.
// The server is configured to verify provided client certificate but does not require
// that the client uses one. It is up to the application to decide which paths can be used
// without client certificate and which paths do require a client certificate.
// See the http.Request object to determine if a client cert is provided.
//
// The server authenticator is used to authenticate the connection before passing it to the handler
// in theory this allows for different authentications depending on the path, but for WoST we simply
// require full authentication for all methods.
//
//  path to listen on. This supports wildcards
//  handler to invoke with the request
func (srv *TLSServer) AddHandler(path string, handler func(http.ResponseWriter, *http.Request)) {

	// do we need a local copy of handler? not sure
	local_handler := handler
	if srv.authenticator != nil {
		// the internal authenticator performs certificate based, basic or digest authentication if needed
		srv.router.HandleFunc(path, func(resp http.ResponseWriter, req *http.Request) {
			err := srv.authenticator(resp, req)
			if err != nil {
				srv.WriteUnauthorized(resp, fmt.Sprintf("TLSServer.HandleFunc %s: Invalid credentials", path))
			} else {
				local_handler(resp, req)
			}
		})
	} else {
		// the internal authenticator performs certificate based, basic or digest authentication if needed
		srv.router.HandleFunc(path, handler)
	}
}

// AddJWTLogin adds a handler for obtaining a JWT token.
//  path to login with.
//  handler that verifies login credentials and produces a JWT token
// FIXME: this is ugly. The JWT domain doesn't belong here
func (srv *TLSServer) AddJWTLogin(path string, handler func(http.ResponseWriter, *http.Request)) {
	// don't authenticate this request
	srv.router.HandleFunc(path, handler)
}

// Start the TLS server using CA and Hub certificates from the certfolder
// The server will request but not require a client certificate. If one is provided it must be valid.
func (srv *TLSServer) Start() error {
	logrus.Infof("TLSServer.Start: Starting TLS server on address: %s:%d", srv.address, srv.port)

	hubCertPEM, err := ioutil.ReadFile(srv.serverCertPath)
	hubKeyPEM, err2 := ioutil.ReadFile(srv.serverKeyPath)
	hubCert, err3 := tls.X509KeyPair(hubCertPEM, hubKeyPEM)
	if err != nil || err2 != nil || err3 != nil {
		err := fmt.Errorf("TLSServer.Start: Server certificate pair not found")
		logrus.Error(err)
		return err
	}
	caCertPEM, err := ioutil.ReadFile(srv.caCertPath)
	if err != nil {
		err = fmt.Errorf("TLSServer.Start: Missing CA file: %s", err)
		logrus.Error(err)
		return err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertPEM)

	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{hubCert},
		// ClientAuth: tls.RequireAnyClientCert, // Require CA signed cert
		// ClientAuth: tls.RequestClientCert, //optional
		ClientAuth: tls.VerifyClientCertIfGiven,
		// ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:          caCertPool,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,

		// VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// 	logrus.Infof("***TLS server VerifyPeerCertificate called")
		// 	return nil
		// },
	}

	srv.httpServer = &http.Server{
		Addr: fmt.Sprintf("%s:%d", srv.address, srv.port),
		// ReadTimeout:  5 * time.Minute, // 5 min to allow for delays when 'curl' on OSx prompts for username/password
		// WriteTimeout: 10 * time.Second,
		Handler:   srv.router,
		TLSConfig: serverTLSConf,
	}

	go func() {
		err2 := srv.httpServer.ListenAndServeTLS("", "")
		// err := cs.httpServer.ListenAndServeTLS(serverCertFile, serverKeyFile)
		if err2 != nil && err2 != http.ErrServerClosed {
			err = fmt.Errorf("TLSServer.Start: ListenAndServeTLS: %s", err2)
			logrus.Error(err)
			// logrus.Fatalf("ServeMsgBus.Start: ListenAndServeTLS error: %s", err)
		}
	}()
	// Make sure the server is listening before continuing
	// Not pretty but it handles it
	time.Sleep(time.Second)
	return err
}

// Stop the TLS server and close all connections
func (srv *TLSServer) Stop() {
	// cs.updateMutex.Lock()
	// defer cs.updateMutex.Unlock()
	logrus.Infof("TLSServer.Stop: Stopping TLS server")

	if srv.httpServer != nil {
		srv.httpServer.Shutdown(context.Background())
	}
}

// Create a new TLS Server instance. Use Start/Stop to run and close connections
// The authenticator is optional to authenticate and authorize each of the requests. It returns
// an error if auth fails, after it writes the error message to the ResponseWriter.
//
//  address          server listening address
//  port             listening port
//  caCertPath       CA certificate
//  serverCertPath   Server certificate of this server
//  serverKeyPath    Server key of this server
//  authenticator    optional, for authenticating and authorizing requests
//
// returns TLS server for handling requests
func NewTLSServer(address string, port uint,
	serverCertPath string, serverKeyPath string, caCertPath string,
	authenticator func(http.ResponseWriter, *http.Request) error) *TLSServer {

	srv := &TLSServer{
		router:         mux.NewRouter(),
		caCertPath:     caCertPath,
		serverCertPath: serverCertPath,
		serverKeyPath:  serverKeyPath,
		authenticator:  authenticator,
	}
	srv.address = address
	srv.port = port
	return srv
}
