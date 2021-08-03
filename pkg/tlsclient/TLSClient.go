// Package tlsclient with a simple TLS client helper for mutual authentication
package tlsclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/wostzone/wostlib-go/pkg/certsetup"
)

// Simple TLS Client with authentication using certificates and login/pw methods
type TLSClient struct {
	address    string
	port       uint
	clientCert *x509.Certificate
	caCertPath string
	httpClient *http.Client
	timeout    time.Duration
}

// ClientCertificate returns the client certificate or nil if none is used
func (cl *TLSClient) Certificate() *x509.Certificate {
	return cl.clientCert
}

// Close the connection with the server
func (cl *TLSClient) Close() {
	logrus.Infof("TLSClient.Close: Closing client connection")

	if cl.httpClient != nil {
		cl.httpClient.CloseIdleConnections()
		cl.httpClient = nil
	}
}

// Connect connection with the server using a client certificate for mutual authentication.
// This requires a matching CA certificate
//  clientCertFile path to client certificate PEM file if available, "" if not available
//  clientKeyFile path to client key PEM file if available, "" if not available
// Returns nil if successful, or an error if connection failed
func (cl *TLSClient) ConnectWithClientCert(clientCertPath string, clientKeyPath string) (err error) {
	var clientCertList []tls.Certificate = []tls.Certificate{}
	var checkServerCert = false

	// Use CA certificate for server authentication if it exists
	// caCertPEM, err := certsetup.LoadPEM(cl.certFolder, certsetup.CaCertFile)
	caCertPEM, err := certsetup.LoadPEM("", cl.caCertPath)
	caCertPool := x509.NewCertPool()
	if err == nil {
		logrus.Infof("TLSClient.ConnectWithClientCert: destination '%s:%d'. CA certificate '%s'",
			cl.address, cl.port, cl.caCertPath)
		caCertPool.AppendCertsFromPEM([]byte(caCertPEM))
		checkServerCert = true
	} else {
		logrus.Infof("TLSClient.ConnectWithClientCert: destination '%s:%d'. No CA certificate at '%s'. InsecureSkipVerify used",
			cl.address, cl.port, cl.caCertPath)
		checkServerCert = false
	}

	// Use client certificate for mutual authentication with the server
	clientCertPEM, _ := certsetup.LoadPEM("", clientCertPath)
	clientKeyPEM, _ := certsetup.LoadPEM("", clientKeyPath)
	if clientCertPEM != "" && clientKeyPEM != "" {
		logrus.Infof("TLSClient.ConnectWithClientCert: Using client certificate from %s for mutual auth", certsetup.PluginCertFile)
		cl.clientCert, err = certsetup.CertFromPEM(clientCertPEM)
		if err != nil {
			logrus.Error("TLSClient.ConnectWithClientCert: Invalid client certificate PEM: ", err)
			return err
		}
		tlsCert, err := tls.X509KeyPair([]byte(clientCertPEM), []byte(clientKeyPEM))

		if err != nil {
			logrus.Errorf("TLSClient.ConnectWithClientCert: Cannot create TLS certificate from PEM: %s", err)
			return err
		}
		clientCertList = append(clientCertList, tlsCert)
	} else {
		logrus.Infof("TLSClient.ConnectWithClientCert, No client key/certificate in '%s'. Mutual auth disabled.", clientKeyPath)
	}
	tlsConfig := &tls.Config{
		RootCAs:            caCertPool,
		Certificates:       clientCertList,
		InsecureSkipVerify: !checkServerCert,
	}

	tlsTransport := http.DefaultTransport
	tlsTransport.(*http.Transport).TLSClientConfig = tlsConfig

	cl.httpClient = &http.Client{
		Transport: tlsTransport,
		Timeout:   cl.timeout,
	}
	return nil
}

// Connect with the server using loginID/password authentication.
// If a CA certificate is not available then insecure-skip-verify is used to allow
// connection to an unverified server (leap of faith).
//  loginID username or application ID to identify as.
//  password to authenticate with. Use "" if the server does not require authentication
// Returns nil if successful, or an error if connection failed
func (cl *TLSClient) ConnectWithLoginID(loginID string, password string) (err error) {
	var checkServerCert = false

	// Use CA certificate for server authentication if it exists
	// caCertPEM, err := certsetup.LoadPEM(cl.certFolder, certsetup.CaCertFile)
	caCertPEM, err := certsetup.LoadPEM("", cl.caCertPath)
	caCertPool := x509.NewCertPool()
	if err == nil {
		logrus.Infof("TLSClient.ConnectWithLoginID: destination '%s:%d'. CA certificate '%s' for server verification",
			cl.address, cl.port, cl.caCertPath)
		caCertPool.AppendCertsFromPEM([]byte(caCertPEM))
		checkServerCert = true
	} else {
		logrus.Infof("TLSClient.ConnectWithLoginID, destination '%s:%d'. No CA certificate at '%s'. InsecureSkipVerify used",
			cl.address, cl.port, cl.caCertPath)
		checkServerCert = false
	}

	tlsConfig := &tls.Config{
		RootCAs:            caCertPool,
		InsecureSkipVerify: !checkServerCert,
	}
	// tlsTransport := http.Transport{
	// 	TLSClientConfig: tlsConfig,
	// }
	tlsTransport := http.DefaultTransport
	tlsTransport.(*http.Transport).TLSClientConfig = tlsConfig

	cl.httpClient = &http.Client{
		Transport: tlsTransport,
		Timeout:   cl.timeout,
	}
	return nil
}

// Get is a convenience function to send a request
//  path to invoke
func (cl *TLSClient) Get(path string) ([]byte, error) {
	return cl.Invoke("GET", path, nil)
}

// invoke a HTTPS method and read response
//  client is the http client to use
//  method: GET, PUT, POST, ...
//  addr the server to connect to
//  path to invoke
//  msg message object to include. This will be marshalled to json
func (cl *TLSClient) Invoke(method string, path string, msg interface{}) ([]byte, error) {
	var body io.Reader = http.NoBody
	var err error
	var req *http.Request
	contentType := "application/json"

	if cl == nil || cl.httpClient == nil {
		logrus.Errorf("Invoke: '%s'. Client is not started", path)
		return nil, errors.New("Invoke: client is not started")
	}
	logrus.Infof("TLSClient.Invoke: %s: %s", method, path)

	// careful, a double // in the path causes a 301 and changes post to get
	url := fmt.Sprintf("https://%s:%d%s", cl.address, cl.port, path)
	if msg != nil {
		bodyBytes, _ := json.Marshal(msg)
		body = bytes.NewReader(bodyBytes)
	}
	req, err = http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	// set headers
	req.Header.Set("Content-Type", contentType)

	resp, err := cl.httpClient.Do(req)
	if err != nil {
		logrus.Errorf("TLSClient.Invoke: %s %s: %s", method, path, err)
		return nil, err
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		msg := fmt.Sprintf("%s: %s", resp.Status, respBody)
		if resp.Status == "" {
			msg = fmt.Sprintf("%d (%s): %s", resp.StatusCode, resp.Status, respBody)
		}
		err = errors.New(msg)
	}
	if err != nil {
		logrus.Errorf("TLSClient:Invoke: Error %s %s: %s", method, path, err)
		return nil, err
	}
	return respBody, err
}

// Post a message with json payload
//  path to invoke
//  msg message object to include. This will be marshalled to json
func (cl *TLSClient) Post(path string, msg interface{}) ([]byte, error) {
	return cl.Invoke("POST", path, msg)
}

// Put a message with json payload
//  path to invoke
//  msg message object to include. This will be marshalled to json
func (cl *TLSClient) Put(path string, msg interface{}) ([]byte, error) {
	return cl.Invoke("PUT", path, msg)
}

// Create a new TLS Client instance.
// If the certFolder contains a CA certificate, then server authentication is used.
// If the certFolder also contains a client certificate and key then the client is
// configured for mutual authentication.
// Use Start/Stop to run and close connections
//  address is the server hostname or IP address to connect to
//  port to connect to
//  caCertFile path to CA certificate PEM file, if available, "" if not available
// returns TLS client for submitting requests
func NewTLSClient(address string, port uint, caCertPath string) *TLSClient {
	cl := &TLSClient{
		address:    address,
		port:       port,
		timeout:    time.Second,
		caCertPath: caCertPath,
	}
	return cl
}
