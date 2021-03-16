// Package wostws with websocket API for WoST Hub connection
package wostws

// NOTE: This client is not ready. The question is whether it has any use as
// the mqtt API is just as easy to use and this is just a wrapper around mqtt.

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/wostzone/hubapi/pkg/certsetup"
)

// DefaultConnectTimeout the default connection timeout is 1 hour
const DefaultConnectTimeout = 3600

// implement the WostAPI interface
type WostWS struct {
	clientID   string
	hostPort   string
	timeoutSec int // connection timeout
	//
	clientCertPEM []byte // Client certificate
	clientKeyPEM  []byte // Client private key
	serverCertPEM []byte // server certificate
	connection    *websocket.Conn
	updateMutex   *sync.Mutex

	// API connections
	// pubTD      *websocket.Conn
	// pubTDProps *websocket.Conn
	// pubTD      *websocket.Conn
}

// Connection headers
const (
	AuthorizationHeader = "Authorization"
	ClientHeader        = "Client"
)

// Connect to the websocket server
//  socketdialer is used to connect and is setup with TLS certificates if applicable
//  url contains the full websocket URL, eg ws://host:port/path or wss://host:port/path
//  clientID is used to identify this client
func Connect(socketDialer *websocket.Dialer, url string, clientID string) (*websocket.Conn, error) {
	reqHeader := http.Header{}
	reqHeader.Add(ClientHeader, clientID)

	connection, resp, err := socketDialer.Dial(url, reqHeader)
	if err != nil {
		msg := fmt.Sprintf("%s: %s", url, err)
		if resp != nil {
			msg = fmt.Sprintf("%s: %s (%d)", err, resp.Status, resp.StatusCode)
		}
		logrus.Error("connect: Failed to connect: ", msg)
		return nil, err
	}
	return connection, err
}

// Listen for data from the connection and determine the command, channel and the message
// This function blocks until the connection is closed
//  conn is an active connection to a websocket server
//  handler is a message callback
func Listen(conn *websocket.Conn,
	handler func(command string, topic string, message []byte)) {
	// setup a receive loop for this connection if a receive handler is provided
	// also listen on publisher connections to detect connection closure
	remoteURL := conn.RemoteAddr()
	// conn := connection
	for {
		msgType, message, err := conn.ReadMessage()
		_ = msgType
		if err != nil {
			// the connect has closed
			// logrus.Warningf("NewChannelConnection: Connection to %s has closed", url)
			logrus.Warningf("ReadMessage, read error from %s: %s", remoteURL, err)
			err = conn.Close()
			if handler != nil {
				handler("", "", nil)
			}
			break
		}
		// message contains command:topic:data
		command := ""
		topic := ""
		data := []byte(nil)
		parts := strings.SplitN(string(message), ":", 3)
		if len(parts) != 3 {
			logrus.Warningf("Ignored invalid message without command or topic from %s", remoteURL)
		} else {
			command = parts[0]
			topic = parts[1]
			data = []byte(parts[2])
			if handler != nil {
				handler(command, topic, data)
			}
		}
	}
}

// Connect to the WoST hub
//  hostname is the name or address of the server to connect to
//  clientID is the ID to identify this client. Must be unique
// Returns error if connection fails
func (wws *WostWS) Start() error {
	var conn *websocket.Conn
	var err error
	// hostName, _ := os.Hostname()

	if wws.clientCertPEM == nil {
		err := fmt.Errorf("Missing client certificate")
		return err
	} else if wws.clientKeyPEM == nil {
		err := fmt.Errorf("Missing client key")
		return err
	} else if wws.serverCertPEM == nil {
		err := fmt.Errorf("Missing server certificate")
		return err
	}

	url := fmt.Sprintf("wss://%s/wost", wws.hostPort)

	// Use client certificate to identify with the server
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(wws.serverCertPEM)

	clientCert, err := tls.X509KeyPair(wws.clientCertPEM, wws.clientKeyPEM)
	if err != nil {
		logrus.Error("Invalid client certificate or key: ", err)
		return err
	}

	socketDialer := &websocket.Dialer{}
	socketDialer.TLSClientConfig = &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{clientCert},
	}

	retryDelaySec := 1
	retryDuration := 0
	for wws.timeoutSec == 0 || retryDuration < wws.timeoutSec {

		connection, err := Connect(socketDialer, url, wws.clientID)
		if err != nil {

			sleepDuration := time.Duration(retryDelaySec)
			retryDuration += int(sleepDuration)
			logrus.Errorf("Failed connecting to the hub: %s. sleep for %d seconds", err, sleepDuration)
			time.Sleep(sleepDuration * time.Second)

			// slowly increment wait time
			if retryDelaySec < 120 {
				retryDelaySec++
			}
		} else {
			logrus.Warningf("Success connecting to hub: %s", wws.hostPort)
			// setup a receive loop for this connection if a receive handler is provided
			go func() {
				Listen(connection, wws.handler)
			}()
		}
	}
	wws.connection = conn
	return err
}

// Disconnect from the WoST hub
func (wws *WostWS) Stop() {
	wws.updateMutex.Lock()
	defer wws.updateMutex.Unlock()

	if wws.connection != nil {
		wws.connection.Close()
		wws.connection = nil
	}
}

// PublishTD publish a Thing description to the WoST hub
func (wws *WostWS) PublishTD(td []byte) {

}

// PublishProperties publish a Thing property values to the WoST hub
func (wws *WostWS) PublishProperties(props []byte) {

}

// PublishEvent publish a Thing event to the WoST hub
func (wws *WostWS) PublishEvent(event []byte) {

}

// NewWostWS creates a new wost hub websocket connection
func NewWostWS(certFolder string, hostPort string, clientID string) (*WostWS, error) {
	var err error
	wws := &WostWS{
		clientID:    clientID,
		hostPort:    hostPort,
		timeoutSec:  DefaultConnectTimeout,
		updateMutex: &sync.Mutex{},
	}
	if wws.clientID == "" {
		wws.clientID = fmt.Sprintf("%s-%d", hostPort, time.Now().Unix())
	}
	if certFolder != "" {
		serverCertPath := path.Join(certFolder, certsetup.ServerCertFile)
		clientCertPath := path.Join(certFolder, certsetup.ClientCertFile)
		clientKeyPath := path.Join(certFolder, certsetup.ClientKeyFile)

		wws.serverCertPEM, err = ioutil.ReadFile(serverCertPath)
		if err != nil {
			return nil, logrus.Errorf("No certificates in %s: %s", certFolder, err)
		}
		wws.clientCertPEM, err = ioutil.ReadFile(clientCertPath)
		if err != nil {
			return nil, logrus.Errorf("No certificates in %s: %s", certFolder, err)
		}
		wws.clientKeyPEM, err = ioutil.ReadFile(clientKeyPath)
		if err != nil {
			return nil, logrus.Errorf("No certificates in %s: %s", certFolder, err)
		}
	}
	return wws, fmt.Errorf("This client is not ready for use")
}
