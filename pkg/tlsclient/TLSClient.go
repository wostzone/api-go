// Package client with a simple TLS client helper for mutual authentication
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
	"log"
	"net"
	"net/http"
	"path"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/wostzone/hubapi-go/pkg/certsetup"
)

// Simple TLS Client
type TLSClient struct {
	address    string
	certFolder string
	httpClient *http.Client
}

// GetOutboundInterface Get preferred outbound network interface of this machine
// Credits: https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
// and https://qiita.com/shaching/items/4c2ee8fd2914cce8687c
func GetOutboundInterface(address string) (interfaceName string, macAddress string, ipAddr net.IP) {

	// This dial command doesn't actually create a connection
	conn, err := net.Dial("udp", address)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ipAddr = localAddr.IP

	// find the first interface for this address
	interfaces, _ := net.Interfaces()
	for _, interf := range interfaces {

		if addrs, err := interf.Addrs(); err == nil {
			for index, addr := range addrs {
				logrus.Debug("[", index, "]", interf.Name, ">", addr)

				// only interested in the name with current IP address
				if strings.Contains(addr.String(), ipAddr.String()) {
					logrus.Debug("Use name : ", interf.Name)
					interfaceName = interf.Name
					macAddress = fmt.Sprint(interf.HardwareAddr)
					break
				}
			}
		}
	}
	// netInterface, err = net.InterfaceByName(interfaceName)
	// macAddress = netInterface.HardwareAddr
	fmt.Println("MAC: ", macAddress)
	return
}

// testing
func (cl *TLSClient) Post(path string, msg interface{}) ([]byte, error) {
	url := fmt.Sprintf("https://%s/%s", cl.address, path)

	bodyBytes, _ := json.Marshal(msg)
	body := bytes.NewReader(bodyBytes)
	resp, err := cl.httpClient.Post(url, "", body)
	data, err := ioutil.ReadAll(resp.Body)

	return data, err
}

// invoke a HTTPS method and read response
//  client is the http client to use
//  method: GET, PUT, POST, ...
//  addr the server to connect to
//  path to invoke
//  msg body to include
func (cl *TLSClient) Invoke(method string, path string, msg interface{}) ([]byte, error) {
	var body io.Reader
	var data []byte
	var err error
	var req *http.Request
	// careful, a double // in the path causes a 301 and changes post to get
	url := fmt.Sprintf("https://%s%s", cl.address, path)
	if msg != nil {
		bodyBytes, _ := json.Marshal(msg)
		body = bytes.NewReader(bodyBytes)
	}
	req, err = http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	resp, err := cl.httpClient.Do(req)
	if err != nil {
		logrus.Errorf("invoke: %s %s: %s", method, path, err)
		return nil, err
	}
	if resp.StatusCode >= 400 {
		if resp.Status != "" {
			err = errors.New(resp.Status)
		} else {
			err = errors.New(fmt.Sprintf("%d: %s", resp.StatusCode, resp.Status))
		}
	} else if err == nil {
		data, err = ioutil.ReadAll(resp.Body)
	}
	if err != nil {
		logrus.Errorf("invoke: read error %s %s: %s", method, path, err)
		return nil, err
	}
	return data, err
}

// Start the client.
// Mutual TLS authentication is used when both CA and client certificates are available
func (cl *TLSClient) Start() (err error) {
	var clientCertList []tls.Certificate = []tls.Certificate{}
	var checkServerCert = false

	// Use CA certificate for server authentication if it exists
	caCertPath := path.Join(cl.certFolder, certsetup.CaCertFile)
	caCertPEM, _ := ioutil.ReadFile(caCertPath)
	caCertPool := x509.NewCertPool()
	if caCertPEM != nil {
		logrus.Infof("TLSClient.Start: Using CA certificate in '%s' for server verification", caCertPath)
		caCertPool.AppendCertsFromPEM(caCertPEM)
		checkServerCert = true
	} else {
		logrus.Infof("TLSClient.Start, No CA certificate in '%s' for use by client", caCertPath)
	}

	// Use client certificate for mutual authentication with the server
	clientKeyPath := path.Join(cl.certFolder, certsetup.ClientKeyFile)
	clientCertPath := path.Join(cl.certFolder, certsetup.ClientCertFile)
	clientCertPEM, _ := ioutil.ReadFile(clientCertPath)
	clientKeyPEM, _ := ioutil.ReadFile(clientKeyPath)
	if clientCertPEM != nil && clientKeyPEM != nil {
		logrus.Infof("TLSClient.Start: Using client certificate from %s for mutual auth", clientKeyPath)
		clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
		if err != nil {
			logrus.Error("TLSClient.Start: Invalid client certificate or key: ", err)
			return err
		}
		clientCertList = append(clientCertList, clientCert)
	} else {
		logrus.Infof("TLSClient.Start, no client certificate in '%s'", clientKeyPath)
	}
	tlsConfig := &tls.Config{
		RootCAs:            caCertPool,
		Certificates:       clientCertList,
		InsecureSkipVerify: !checkServerCert,
	}
	// tlsTransport := http.Transport{
	// 	TLSClientConfig: tlsConfig,
	// }
	tlsTransport := http.DefaultTransport
	tlsTransport.(*http.Transport).TLSClientConfig = tlsConfig

	cl.httpClient = &http.Client{
		Transport: tlsTransport,
	}
	return nil
}

// Stop the TLS client
func (cl *TLSClient) Stop() {
	// cs.updateMutex.Lock()
	// defer cs.updateMutex.Unlock()
	logrus.Infof("TLSClient.Stop: Stopping TLS client")

	if cl.httpClient != nil {
		cl.httpClient = nil
	}
}

// Create a new TLS Client instance. Use Start/Stop to run and close connections
//  address address of the server
//  certFolder folder with ca, client certs and key (see cersetup for standard names)
// returns TLS client for submitting requests
func NewTLSClient(address string, certFolder string) *TLSClient {
	// get the certificates ready
	if certFolder == "" {
		certFolder = "./certs"
	}
	cl := &TLSClient{
		address:    address,
		certFolder: certFolder,
	}
	return cl
}
