package tlsclient_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wostzone/wostlib-go/pkg/certsetup"
	"github.com/wostzone/wostlib-go/pkg/hubnet"
	"github.com/wostzone/wostlib-go/pkg/tlsclient"
)

var testAddress string
var testPort uint = 4444

// These are set in TestMain
var homeFolder string
var serverCertFolder string
var caCertPath string
var caKeyPath string
var pluginCertPath string
var pluginKeyPath string
var serverCertPath string
var serverKeyPath string

var serverTLSConf *tls.Config

func startTestServer() (*http.Server, error) {
	var err error
	httpServer := &http.Server{
		Addr: fmt.Sprintf("%s:%d", testAddress, testPort),
		// ReadTimeout:  5 * time.Minute, // 5 min to allow for delays when testing
		// WriteTimeout: 10 * time.Second,
		// Handler:   srv.router,
		TLSConfig: serverTLSConf,
	}
	go func() {
		err = httpServer.ListenAndServeTLS("", "")
		logrus.Errorf("startTestServer: %s", err)
	}()
	// Catch any startup errors
	time.Sleep(100 * time.Millisecond)
	return httpServer, err
}

// TestMain runs a http server
// Used for all test cases in this package
func TestMain(m *testing.M) {
	logrus.Infof("------ TestMain of httpauthhandler ------")
	testAddress = hubnet.GetOutboundIP("").String()
	hostnames := []string{testAddress}

	cwd, _ := os.Getwd()
	homeFolder = path.Join(cwd, "../../test")
	serverCertFolder = path.Join(homeFolder, "certs")

	certsetup.CreateCertificateBundle(hostnames, serverCertFolder)
	caCertPath = path.Join(serverCertFolder, certsetup.CaCertFile)
	caKeyPath = path.Join(serverCertFolder, certsetup.CaKeyFile)
	serverCertPath = path.Join(serverCertFolder, certsetup.HubCertFile)
	serverKeyPath = path.Join(serverCertFolder, certsetup.HubKeyFile)
	pluginCertPath = path.Join(serverCertFolder, certsetup.PluginCertFile)
	pluginKeyPath = path.Join(serverCertFolder, certsetup.PluginKeyFile)

	caCertPEM, err := ioutil.ReadFile(caCertPath)
	serverCertPEM, err2 := ioutil.ReadFile(serverCertPath)
	serverKeyPEM, err3 := ioutil.ReadFile(serverKeyPath)
	serverCert, err4 := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil || err2 != nil || err3 != nil || err4 != nil {
		panic("TestMain failed to setup test certs")
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertPEM)

	serverTLSConf = &tls.Config{
		Certificates:       []tls.Certificate{serverCert},
		ClientAuth:         tls.VerifyClientCertIfGiven,
		ClientCAs:          caCertPool,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,

		// VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// 	logrus.Infof("***TLS server VerifyPeerCertificate called")
		// 	return nil
		// },
	}

	res := m.Run()

	time.Sleep(time.Second)
	os.Exit(res)
}

func TestNoCA(t *testing.T) {
	path1 := "/hello"
	path1Hit := 0

	// setup server and client environment
	srv, err := startTestServer()
	http.HandleFunc(path1, func(http.ResponseWriter, *http.Request) {
		logrus.Infof("TestAuthCert: path1 hit")
		path1Hit++
	})
	assert.NoError(t, err)
	//
	cl, err := tlsclient.NewTLSClient(testAddress, testPort, "")
	require.NoError(t, err)
	err = cl.ConnectWithClientCert(pluginCertPath, pluginKeyPath)
	assert.NoError(t, err)

	_, err = cl.Get(path1)
	assert.NoError(t, err)
	assert.Equal(t, 1, path1Hit)
	cl.Close()

	err = cl.ConnectWithLoginID("", "", tlsclient.AuthMethodNone)
	assert.NoError(t, err)

	_, err = cl.Get(path1)
	assert.NoError(t, err)
	assert.Equal(t, 2, path1Hit)

	cl.Close()
	srv.Close()
}

// Test certificate based authentication
func TestAuthClientCert(t *testing.T) {
	path1 := "/test1"
	path1Hit := 0

	// setup server and client environment
	srv, err := startTestServer()
	assert.NoError(t, err)
	//
	http.HandleFunc(path1, func(http.ResponseWriter, *http.Request) {
		logrus.Infof("TestAuthClientCert: path1 hit")
		path1Hit++
	})
	//
	cl, err := tlsclient.NewTLSClient(testAddress, testPort, caCertPath)
	require.NoError(t, err)
	err = cl.ConnectWithClientCert(pluginCertPath, pluginKeyPath)
	assert.NoError(t, err)

	clientCert := cl.Certificate()
	assert.NotNil(t, clientCert)

	//
	_, err = cl.Get(path1)
	assert.NoError(t, err)
	_, err = cl.Post(path1, "")
	assert.NoError(t, err)
	_, err = cl.Put(path1, "")
	assert.NoError(t, err)
	assert.Equal(t, 3, path1Hit)

	cl.Close()
	srv.Close()
}

func TestMissingCA(t *testing.T) {
	// setup server and client environm
	//
	cl, err := tlsclient.NewTLSClient(testAddress, testPort, "missingca")
	assert.Error(t, err)
	assert.Nil(t, cl)
}

func TestNotStarted(t *testing.T) {
	cl, err := tlsclient.NewTLSClient(testAddress, testPort, caCertPath)
	assert.NoError(t, err)
	_, err = cl.Get("/notstarted")
	assert.Error(t, err)
	cl.Close()
}
func TestNoClientCert(t *testing.T) {
	cl, err := tlsclient.NewTLSClient(testAddress, testPort, caCertPath)
	assert.NoError(t, err)
	err = cl.ConnectWithClientCert("", "")
	assert.NoError(t, err)
	cl.Close()
}

func TestBadClientCert(t *testing.T) {
	cl, err := tlsclient.NewTLSClient(testAddress, testPort, caCertPath)
	assert.NoError(t, err)
	// user key as cert should create error
	err = cl.ConnectWithClientCert(pluginKeyPath, pluginKeyPath)
	assert.Error(t, err)
	cl.Close()
}

func TestBadClientKey(t *testing.T) {
	cl, err := tlsclient.NewTLSClient(testAddress, testPort, caCertPath)
	assert.NoError(t, err)
	// user cert for key should create error
	err = cl.ConnectWithClientCert(pluginCertPath, pluginCertPath)
	assert.Error(t, err)
	cl.Close()
}

func TestNoServer(t *testing.T) {
	// setup server and client environm
	//
	cl, err := tlsclient.NewTLSClient(testAddress, testPort, caCertPath)
	require.NoError(t, err)
	err = cl.ConnectWithClientCert(pluginCertPath, pluginKeyPath)
	assert.NoError(t, err)
	_, err = cl.Get("/noserver")
	assert.Error(t, err)
	cl.Close()
}
func TestCert404(t *testing.T) {
	srv, err := startTestServer()
	assert.NoError(t, err)

	cl, err := tlsclient.NewTLSClient(testAddress, testPort, caCertPath)
	assert.NoError(t, err)

	err = cl.ConnectWithClientCert(pluginCertPath, pluginKeyPath)
	assert.NoError(t, err)

	_, err = cl.Get("/pathnotfound")
	assert.Error(t, err)

	cl.Close()
	srv.Close()
}

func TestAuthBasic(t *testing.T) {
	path2 := "/test2"
	path2Hit := 0
	user1 := "user1"
	password1 := "password1"

	// setup server and client environment
	srv, err := startTestServer()
	assert.NoError(t, err)
	//
	http.HandleFunc(path2, func(resp http.ResponseWriter, req *http.Request) {
		logrus.Infof("TestAuthBasic: path1 hit")
		username, password, ok := req.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, user1, username)
		assert.Equal(t, password1, password)
		path2Hit++
	})
	//
	cl, _ := tlsclient.NewTLSClient(testAddress, testPort, caCertPath)
	err = cl.ConnectWithLoginID(user1, password1, tlsclient.AuthMethodBasic)
	assert.NoError(t, err)

	//
	_, err = cl.Get(path2)
	assert.NoError(t, err)
	assert.Equal(t, 1, path2Hit)

	cl.Close()
	srv.Close()
}

func TestAuthJWT(t *testing.T) {
	pathLogin1 := "/login"
	pathLogin2 := "/login2"
	path3 := "/test3"
	path3Hit := 0
	user1 := "user1"
	password1 := "password1"

	// setup server and client environment
	srv, err := startTestServer()
	assert.NoError(t, err)
	//
	http.HandleFunc(pathLogin1, func(resp http.ResponseWriter, req *http.Request) {
		var authMsg tlsclient.JwtAuthMessage
		logrus.Infof("TestAuthJWT: login")
		body, err := ioutil.ReadAll(req.Body)
		assert.NoError(t, err)
		err = json.Unmarshal(body, &authMsg)
		assert.NoError(t, err)
		assert.Equal(t, user1, authMsg.LoginID)
		assert.Equal(t, password1, authMsg.Secret)
		if authMsg.LoginID == user1 {
			resp.Write([]byte("fake auth token 123"))
		} else {
			// write nothing
		}
		path3Hit++
	})
	// a second loging function that returns nothing
	http.HandleFunc(pathLogin2, func(resp http.ResponseWriter, req *http.Request) {
	})

	http.HandleFunc(path3, func(http.ResponseWriter, *http.Request) {
		logrus.Infof("TestAuthClientCert: path1 hit")
		path3Hit++
	})
	//
	cl, _ := tlsclient.NewTLSClient(testAddress, testPort, caCertPath)
	err = cl.ConnectWithLoginID(user1, password1, tlsclient.AuthMethodJwt)
	assert.NoError(t, err)

	_, err = cl.Get(path3)
	assert.NoError(t, err)
	assert.Equal(t, 2, path3Hit)

	// test if no auth is returned
	cl.Close()
	cl.LoginPath = pathLogin2
	err = cl.ConnectWithLoginID(user1, password1, tlsclient.AuthMethodJwt)
	assert.Error(t, err)
	//

	cl.Close()
	srv.Close()
}

// Test BASIC authentication
// func TestBasicAuth(t *testing.T) {
// 	path1 := "/test1"
// 	path1Hit := false
// 	loginID1 := "user1"
// 	password1 := "user1pass"

// 	// setup authentication of user1
// 	srv, err := startTestServer()

// 	pwstore := unpwstore.NewPasswordFileStore(unpwFilePath, "client1")
// 	authenticator := httpauth.NewHttpAuthenticator(pwstore)
// 	err := authenticator.Start()
// 	require.NoError(t, err)
// 	authenticator.SetPassword(loginID1, password1)

// 	// setup server and client environment
// 	srv := tlsserver.NewTLSServer(
// 		srvAddress, srvPort, serverCertPath, serverKeyPath, caCertPath, authenticator.Authenticate)
// 	err = srv.Start()
// 	assert.NoError(t, err)
// 	//
// 	srv.AddHandler(path1, func(http.ResponseWriter, *http.Request) {
// 		logrus.Infof("TestBasicAuth: path1 hit")
// 		path1Hit = true
// 	})
// 	//
// 	cl := tlsclient.NewTLSClient(srvAddress, srvPort, caCertPath)
// 	err = cl.ConnectWithLoginID(loginID1, password1)
// 	assert.NoError(t, err)

// 	// test the auth with a GET request
// 	_, err = cl.Get(path1)
// 	assert.NoError(t, err)

// 	assert.True(t, path1Hit)

// 	cl.Close()
// 	authenticator.Stop()
// 	srv.Stop()
// }

// Test JWT authentication
// func TestJWTAuth(t *testing.T) {
// 	path1 := "/test1"
// 	path1Hit := false
// 	loginID1 := "user1"
// 	password1 := "user1pass"

// 	// setup authentication of user1
// 	pwstore := unpwstore.NewPasswordFileStore(unpwFilePath, "client1")
// 	authenticator := httpauth.NewHttpAuthenticator(pwstore)
// 	err := authenticator.Start()
// 	require.NoError(t, err)
// 	authenticator.SetPassword(loginID1, password1)

// 	// setup server and client environment
// 	srv := tlsserver.NewTLSServer(
// 		srvAddress, srvPort, serverCertPath, serverKeyPath, caCertPath, authenticator.Authenticate)
// 	err = srv.Start()
// 	assert.NoError(t, err)
// 	srv.AddJWTLogin("/auth", authenticator.HandleJWTLogin)
// 	//
// 	srv.AddHandler(path1, func(http.ResponseWriter, *http.Request) {
// 		logrus.Infof("TestJWTAuth: path1 hit")
// 		path1Hit = true
// 	})
// 	//
// 	cl := tlsclient.NewTLSClient(srvAddress, srvPort, caCertPath)
// 	err = cl.ConnectWithLoginID("", "")
// 	// err = cl.ConnectWithLoginID(loginID1, password1)
// 	assert.NoError(t, err)

// 	// get token
// 	loginCred := httpauth.LoginCredentials{Username: loginID1, Password: password1}
// 	token, err := cl.Post("/auth", loginCred)
// 	assert.NoError(t, err)
// 	assert.NotEmpty(t, token)

// 	// test the auth with a GET request
// 	_, err = cl.Get(path1)
// 	assert.NoError(t, err)

// 	assert.True(t, path1Hit)

// 	cl.Close()
// 	authenticator.Stop()
// 	srv.Stop()
// }
