package hubclient_test

import (
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wostzone/wostlib-go/pkg/certsetup"
	"github.com/wostzone/wostlib-go/pkg/hubclient"
	"github.com/wostzone/wostlib-go/pkg/hubconfig"
	"github.com/wostzone/wostlib-go/pkg/testenv"
)

// Use test/mosquitto-test.conf and a client cert port
const mqttCertAuthAddress = "localhost:33100"
const mqttUnpwAuthAddress = "localhost:33101"

var mqttTestCaCertFile string
var mqttTestCaKeyFile string
var mqttTestClientCertFile string
var mqttTestClientKeyFile string
var mqttTestCertFolder string

const TEST_TOPIC = "test"

// For running mosquitto in test
const mosquittoConfigFile = "mosquitto-test.conf"
const testPluginID = "test-user"

// easy cleanup for existing  certificate
// func removeCerts(folder string) {
// 	_, _ = exec.Command("sh", "-c", "rm -f "+path.Join(folder, "*.pem")).Output()
// }

// TestMain - launch mosquitto
func TestMain(m *testing.M) {
	hostnames := []string{"localhost"}
	cwd, _ := os.Getwd()
	home := path.Join(cwd, "../../test")
	os.Chdir(home)
	mqttTestCertFolder = path.Join(home, "certs")
	hubconfig.SetLogging("info", "")

	mqttTestCaCertFile = path.Join(mqttTestCertFolder, certsetup.CaCertFile)
	mqttTestCaKeyFile = path.Join(mqttTestCertFolder, certsetup.CaKeyFile)
	mqttTestClientCertFile = path.Join(mqttTestCertFolder, certsetup.PluginCertFile)
	mqttTestClientKeyFile = path.Join(mqttTestCertFolder, certsetup.PluginKeyFile)

	configFolder := path.Join(home, "config")
	// clean start
	// removeCerts(certsFolder)
	certsetup.CreateCertificateBundle(hostnames, mqttTestCertFolder)
	// MQTT port hardcoded to 33100
	mosqConfigPath := path.Join(configFolder, mosquittoConfigFile)

	mosquittoCmd, err := testenv.Launch(mosqConfigPath)
	if err != nil {
		logrus.Fatalf("Unable to setup mosquitto: %s", err)
	}

	result := m.Run()
	mosquittoCmd.Process.Kill()

	os.Exit(result)
}

func TestMqttConnectWithCert(t *testing.T) {
	logrus.Infof("--- TestMqttConnectWithCert ---")

	client := hubclient.NewMqttClient(mqttCertAuthAddress, mqttTestCaCertFile, hubclient.DefaultTimeoutSec)
	err := client.ConnectWithClientCert(testPluginID, mqttTestClientCertFile, mqttTestClientKeyFile)
	assert.NoError(t, err)
	// reconnect
	err = client.ConnectWithClientCert(testPluginID, mqttTestClientCertFile, mqttTestClientKeyFile)
	assert.NoError(t, err)
	client.Close()
}

func TestMqttConnectWithUnpw(t *testing.T) {
	logrus.Infof("--- TestMqttConnectWithUnpw ---")
	username := "user1"
	password := "user1"

	client := hubclient.NewMqttClient(mqttUnpwAuthAddress, mqttTestCaCertFile, hubclient.DefaultTimeoutSec)
	err := client.ConnectWithPassword(username, password)
	assert.NoError(t, err)
	client.Close()
}

func TestMqttConnectWrongAddress(t *testing.T) {
	logrus.Infof("--- TestMqttConnectWrongAddress ---")

	invalidHost := "nohost:1111"
	client := hubclient.NewMqttClient(invalidHost, mqttTestCaCertFile, hubclient.DefaultTimeoutSec)
	require.NotNil(t, client)
	err := client.ConnectWithClientCert(testPluginID, mqttTestClientCertFile, mqttTestClientKeyFile)
	assert.Error(t, err)
	client.Close()
}

func TestMQTTPubSub(t *testing.T) {
	logrus.Infof("--- TestMQTTPubSub ---")

	var rx string
	rxMutex := sync.Mutex{}
	var msg1 = "Hello world"

	client := hubclient.NewMqttClient(mqttCertAuthAddress, mqttTestCaCertFile, hubclient.DefaultTimeoutSec)
	err := client.ConnectWithClientCert(testPluginID, mqttTestClientCertFile, mqttTestClientKeyFile)
	require.NoError(t, err)

	client.Subscribe(TEST_TOPIC, func(channel string, msg []byte) {
		rxMutex.Lock()
		defer rxMutex.Unlock()
		rx = string(msg)
		logrus.Infof("Received message: %s", msg)
	})
	require.NoErrorf(t, err, "Failed subscribing to channel %s", TEST_TOPIC)

	err = client.Publish(TEST_TOPIC, []byte(msg1))
	require.NoErrorf(t, err, "Failed publishing message")

	// allow time to receive
	time.Sleep(1000 * time.Millisecond)
	rxMutex.Lock()
	defer rxMutex.Unlock()
	require.Equalf(t, msg1, rx, "Did not receive the message")

	client.Close()
}

func TestMQTTMultipleSubscriptions(t *testing.T) {
	logrus.Infof("--- TestMQTTMultipleSubscriptions ---")

	client := hubclient.NewMqttClient(mqttCertAuthAddress, mqttTestCaCertFile, hubclient.DefaultTimeoutSec)
	var rx1 string
	var rx2 string
	rxMutex := sync.Mutex{}
	var msg1 = "Hello world 1"
	var msg2 = "Hello world 2"
	// clientID := "test"

	// mqttMessenger := NewMqttMessenger(clientID, mqttCertFolder)
	err := client.ConnectWithClientCert(testPluginID, mqttTestClientCertFile, mqttTestClientKeyFile)
	require.NoError(t, err)
	handler1 := func(channel string, msg []byte) {
		rxMutex.Lock()
		defer rxMutex.Unlock()
		rx1 = string(msg)
		logrus.Infof("Received message on handler 1: %s", msg)
	}
	handler2 := func(channel string, msg []byte) {
		rxMutex.Lock()
		defer rxMutex.Unlock()
		rx2 = string(msg)
		logrus.Infof("Received message on handler 2: %s", msg)
	}
	_ = handler2
	client.Subscribe(TEST_TOPIC, handler1)
	client.Subscribe(TEST_TOPIC, handler2)
	err = client.Publish(TEST_TOPIC, []byte(msg1))
	assert.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	rxMutex.Lock()
	// tbd
	assert.Equalf(t, "", rx1, "Did not expect a message on handler 1")
	assert.Equalf(t, msg1, rx2, "Did not receive the message on handler 2")
	// after unsubscribe no message should be received by handler 1
	rx1 = ""
	rx2 = ""
	rxMutex.Unlock()
	client.Unsubscribe(TEST_TOPIC)
	err = client.Publish(TEST_TOPIC, []byte(msg2))
	assert.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	rxMutex.Lock()
	assert.Equalf(t, "", rx1, "Received a message on handler 1 after unsubscribe")
	assert.Equalf(t, "", rx2, "Received a message on handler 2 after unsubscribe")
	rx1 = ""
	rx2 = ""
	rxMutex.Unlock()

	client.Subscribe(TEST_TOPIC, handler1)
	err = client.Publish(TEST_TOPIC, []byte(msg2))
	assert.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	rxMutex.Lock()
	assert.Equalf(t, msg2, rx1, "Did not receive a message on handler 1 after subscribe")
	assert.Equalf(t, "", rx2, "Receive the message on handler 2")
	rxMutex.Unlock()

	// when unsubscribing without handler, all handlers should be unsubscribed
	rx1 = ""
	rx2 = ""
	client.Subscribe(TEST_TOPIC, handler1)
	client.Subscribe(TEST_TOPIC, handler2)
	client.Unsubscribe(TEST_TOPIC)
	err = client.Publish(TEST_TOPIC, []byte(msg2))
	assert.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	rxMutex.Lock()
	assert.Equalf(t, "", rx1, "Received a message on handler 1 after unsubscribe")
	assert.Equalf(t, "", rx2, "Did not receive the message on handler 2")
	rxMutex.Unlock()

	client.Close()
}

func TestMQTTBadUnsubscribe(t *testing.T) {
	logrus.Infof("--- TestMQTTBadUnsubscribe ---")

	client := hubclient.NewMqttClient(mqttCertAuthAddress, mqttTestCaCertFile, hubclient.DefaultTimeoutSec)
	err := client.ConnectWithClientCert(testPluginID, mqttTestClientCertFile, mqttTestClientKeyFile)
	require.NoError(t, err)

	client.Unsubscribe(TEST_TOPIC)
	client.Close()
}

func TestMQTTPubNoConnect(t *testing.T) {
	logrus.Infof("--- TestMQTTPubNoConnect ---")

	invalidHost := "localhost:1111"
	client := hubclient.NewMqttClient(invalidHost, mqttTestCaCertFile, hubclient.DefaultTimeoutSec)
	var msg1 = "Hello world 1"

	err := client.Publish(TEST_TOPIC, []byte(msg1))
	require.Error(t, err)

	client.Close()
}

func TestMQTTSubBeforeConnect(t *testing.T) {
	logrus.Infof("--- TestMQTTSubBeforeConnect ---")

	client := hubclient.NewMqttClient(mqttCertAuthAddress, mqttTestCaCertFile, hubclient.DefaultTimeoutSec)
	const msg = "hello 1"
	var rx string
	rxMutex := sync.Mutex{}
	// mqttMessenger := NewMqttMessenger(clientID, mqttCertFolder)

	handler1 := func(channel string, msg []byte) {
		logrus.Infof("Received message on handler 1: %s", msg)
		rxMutex.Lock()
		defer rxMutex.Unlock()
		rx = string(msg)
	}
	client.Subscribe(TEST_TOPIC, handler1)

	err := client.ConnectWithClientCert(testPluginID, mqttTestClientCertFile, mqttTestClientKeyFile)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	err = client.Publish(TEST_TOPIC, []byte(msg))
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	rxMutex.Lock()
	assert.Equal(t, msg, rx)
	rxMutex.Unlock()

	client.Close()
}

func TestSubscribeWildcard(t *testing.T) {
	logrus.Infof("--- TestSubscribeWildcard ---")
	const testTopic1 = "test/1/5"
	const wildcardTopic = "test/+/#"

	client := hubclient.NewMqttClient(mqttCertAuthAddress, mqttTestCaCertFile, hubclient.DefaultTimeoutSec)
	const msg = "hello 1"
	var rx string
	rxMutex := sync.Mutex{}
	// mqttMessenger := NewMqttMessenger(clientID, mqttCertFolder)

	handler1 := func(channel string, msg []byte) {
		logrus.Infof("Received message on handler 1: %s", msg)
		rxMutex.Lock()
		defer rxMutex.Unlock()
		rx = string(msg)
	}
	client.Subscribe(wildcardTopic, handler1)

	// connect after subscribe uses resubscribe
	err := client.ConnectWithClientCert(testPluginID, mqttTestClientCertFile, mqttTestClientKeyFile)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	err = client.Publish(testTopic1, []byte(msg))
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	rxMutex.Lock()
	assert.Equal(t, msg, rx)
	rxMutex.Unlock()

	client.Close()
}
