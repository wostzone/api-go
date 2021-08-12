package tlsserver_test

import (
	"fmt"
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
	"github.com/wostzone/wostlib-go/pkg/tlsserver"
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

	res := m.Run()

	time.Sleep(time.Second)
	os.Exit(res)
}

func TestStartStop(t *testing.T) {
	srv := tlsserver.NewTLSServer(testAddress, testPort,
		serverCertPath, serverKeyPath, caCertPath, nil)
	err := srv.Start()
	assert.NoError(t, err)
	srv.Stop()
}

func TestNoCA(t *testing.T) {
	srv := tlsserver.NewTLSServer(testAddress, testPort,
		serverCertPath, serverKeyPath, "", nil)
	err := srv.Start()
	assert.Error(t, err)
}
func TestBadCert(t *testing.T) {
	srv := tlsserver.NewTLSServer(testAddress, testPort,
		serverCertPath, serverCertPath, caCertPath, nil)
	err := srv.Start()
	assert.Error(t, err)
}

func TestHandler(t *testing.T) {
	path1 := "/hello"
	path1Hit := 0
	srv := tlsserver.NewTLSServer(testAddress, testPort,
		serverCertPath, serverKeyPath, caCertPath, nil)

	// handler can be added any time
	srv.AddHandler(path1, func(http.ResponseWriter, *http.Request) {
		logrus.Infof("TestAuthCert: path1 hit")
		path1Hit++
	})
	err := srv.Start()
	assert.NoError(t, err)

	cl, err := tlsclient.NewTLSClient(testAddress, testPort, "")
	require.NoError(t, err)
	cl.ConnectWithClientCert(pluginCertPath, pluginKeyPath)
	_, err = cl.Get(path1)
	assert.NoError(t, err)
	assert.Equal(t, 1, path1Hit)

	cl.Close()
	srv.Stop()
}

func TestJWTLogin(t *testing.T) {
	user1 := "user1"
	user1Pass := "pass1"
	path1 := "/login"
	path1Hit := 0
	path2 := "/hello"
	path2Hit := 0
	srv := tlsserver.NewTLSServer(testAddress, testPort,
		serverCertPath, serverKeyPath, caCertPath, func(http.ResponseWriter, *http.Request) error {
			//authenticator
			return nil
		})
	err := srv.Start()
	assert.NoError(t, err)
	srv.AddJWTLogin(path1, func(resp http.ResponseWriter, req *http.Request) {
		// return the jwt token
		path1Hit++
		resp.Write([]byte("faketoken"))
	})
	srv.AddHandler(path2, func(resp http.ResponseWriter, req *http.Request) {
		path2Hit++
	})

	cl, err := tlsclient.NewTLSClient(testAddress, testPort, caCertPath)
	require.NoError(t, err)
	err = cl.ConnectWithLoginID(user1, user1Pass, tlsclient.AuthMethodJwt)
	assert.NoError(t, err)

	_, err = cl.Get(path2)
	assert.NoError(t, err)
	assert.Equal(t, 1, path2Hit)

	cl.Close()
	srv.Stop()
}

func TestQuery(t *testing.T) {
	path2 := "/hello"
	path2Hit := 0
	srv := tlsserver.NewTLSServer(testAddress, testPort,
		serverCertPath, serverKeyPath, caCertPath, nil)
	err := srv.Start()
	assert.NoError(t, err)
	srv.AddHandler(path2, func(resp http.ResponseWriter, req *http.Request) {
		// query string
		q1 := srv.GetQueryString(req, "query1", "")
		assert.Equal(t, "bob", q1)
		// fail not a number
		_, err := srv.GetQueryInt(req, "query1", 0) // not a number
		assert.Error(t, err)
		// query of number
		q2, _ := srv.GetQueryInt(req, "query2", 0)
		assert.Equal(t, 3, q2)
		// default should work
		q3 := srv.GetQueryString(req, "query3", "default")
		assert.Equal(t, "default", q3)
		// multiple parameters fail
		_, err = srv.GetQueryInt(req, "multi", 0)
		assert.Error(t, err)
		path2Hit++
	})

	cl, err := tlsclient.NewTLSClient(testAddress, testPort, caCertPath)
	require.NoError(t, err)
	err = cl.ConnectWithClientCert(pluginCertPath, pluginKeyPath)
	assert.NoError(t, err)

	_, err = cl.Get(fmt.Sprintf("%s?query1=bob&query2=3&multi=a&multi=b", path2))
	assert.NoError(t, err)
	assert.Equal(t, 1, path2Hit)

	cl.Close()
	srv.Stop()
}

func TestWriteResponse(t *testing.T) {
	path2 := "/hello"
	path2Hit := 0
	srv := tlsserver.NewTLSServer(testAddress, testPort,
		serverCertPath, serverKeyPath, caCertPath, nil)
	err := srv.Start()
	assert.NoError(t, err)
	srv.AddHandler(path2, func(resp http.ResponseWriter, req *http.Request) {
		srv.WriteBadRequest(resp, "bad request")
		srv.WriteInternalError(resp, "internal error")
		srv.WriteNotFound(resp, "not found")
		srv.WriteNotImplemented(resp, "not implemented")
		srv.WriteUnauthorized(resp, "unauthorized")
		path2Hit++
	})

	cl, err := tlsclient.NewTLSClient(testAddress, testPort, caCertPath)
	require.NoError(t, err)
	err = cl.ConnectWithClientCert(pluginCertPath, pluginKeyPath)
	assert.NoError(t, err)

	_, err = cl.Get(path2)
	assert.Error(t, err)
	assert.Equal(t, 1, path2Hit)

	cl.Close()
	srv.Stop()
}

func TestBadPort(t *testing.T) {
	srv := tlsserver.NewTLSServer(testAddress, 1, // bad port
		serverCertPath, serverKeyPath, caCertPath, nil)

	err := srv.Start()
	assert.Error(t, err)
}

func TestAuthenticator(t *testing.T) {
	path1 := "/path1"
	loginID1 := "loginID1"
	password1 := "password1"
	srv := tlsserver.NewTLSServer(testAddress, testPort, // bad port
		serverCertPath, serverKeyPath, caCertPath, func(resp http.ResponseWriter, req *http.Request) error {
			return fmt.Errorf("not auth")
		})
	srv.AddHandler(path1, func(rw http.ResponseWriter, r *http.Request) {})

	err := srv.Start()
	assert.NoError(t, err)

	cl, err := tlsclient.NewTLSClient(testAddress, testPort, caCertPath)
	require.NoError(t, err)
	err = cl.ConnectWithLoginID(loginID1, password1, tlsclient.AuthMethodBasic)
	assert.NoError(t, err)

	_, err = cl.Get(path1)
	assert.Error(t, err)

	cl.Close()
	srv.Stop()
}
