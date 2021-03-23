package mqttclient_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/wostzone/hubapi/internal/mqttclient"
	"github.com/wostzone/hubapi/pkg/td"
)

// !!! THIS REQUIRES A RUNNING MQTT SERVER ON LOCALHOST WITH CERTS !!!

func TestPublishAction(t *testing.T) {
	logrus.Infof("--- TestPublishAction ---")

	credentials := ""
	thingID := "thing1"
	var rx map[string]interface{}

	action1 := map[string]interface{}{"actionName": "actionValue"}
	consumerClient := mqttclient.NewMqttHubClient(mqttTestServerHostPort, mqttTestCaCertFile, "", credentials)
	thingClient := mqttclient.NewMqttHubClient(mqttTestServerHostPort, mqttTestCaCertFile, "", credentials)
	thingClient.SubscribeToActions(thingID, func(thingID string, action map[string]interface{}, sender string) {
		logrus.Infof("TestPublishAction: Received action of Thing %s from client %s", thingID, sender)
		rx = action
	})

	err := consumerClient.Start(false)
	err = thingClient.Start(false)
	assert.NoError(t, err)

	time.Sleep(time.Millisecond)

	err = consumerClient.PublishAction(thingID, action1)
	assert.NoError(t, err)

	// TODO, check if it was received by the Thing
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, action1["actionName"], rx["actionName"])

	thingClient.Stop()
	consumerClient.Stop()
	// make sure it doest reconnect
	time.Sleep(1 * time.Second)
}

func TestPublishConfig(t *testing.T) {
	logrus.Infof("--- TestPublishConfig ---")

	credentials := ""
	thingID := "thing1"
	var rx map[string]interface{}
	var rxID string

	config1 := map[string]interface{}{"prop1": "value1"}
	consumerClient := mqttclient.NewMqttHubClient(mqttTestServerHostPort, mqttTestCaCertFile, "", credentials)
	thingClient := mqttclient.NewMqttHubClient(mqttTestServerHostPort, mqttTestCaCertFile, "", credentials)
	thingClient.SubscribeToConfig(thingID, func(thingID string, config map[string]interface{}, sender string) {
		logrus.Infof("TestPublishConfig: Received config of Thing %s from client %s", thingID, sender)
		rx = config
		rxID = thingID
	})

	err := consumerClient.Start(false)
	err = thingClient.Start(false)
	assert.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	err = consumerClient.PublishConfig(thingID, config1)
	assert.NoError(t, err)

	// TODO, check if it was received by the Thing
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, config1["prop1"], rx["prop1"])
	assert.Equal(t, thingID, rxID)
	thingClient.Stop()
	consumerClient.Stop()
}

func TestPublishEvent(t *testing.T) {
	logrus.Infof("--- TestPublishEvent ---")

	credentials := ""
	thingID := "thing1"
	event1 := map[string]interface{}{"eventName": "eventValue"}
	var rx map[string]interface{}

	consumerClient := mqttclient.NewMqttHubClient(mqttTestServerHostPort, mqttTestCaCertFile, "", credentials)
	thingClient := mqttclient.NewMqttHubClient(mqttTestServerHostPort, mqttTestCaCertFile, "", credentials)

	err := thingClient.Start(false)
	assert.NoError(t, err)
	err = consumerClient.Start(false)
	assert.NoError(t, err)
	consumerClient.SubscribeToEvents(thingID, func(thingID string, event map[string]interface{}, sender string) {
		logrus.Infof("TestPublishEvent: Received event of Thing %s from client %s", thingID, sender)
		rx = event
	})

	time.Sleep(time.Millisecond)
	err = thingClient.PublishEvent(thingID, event1)
	assert.NoError(t, err)

	// TODO, check if it was received by a consumer

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, event1["eventName"], rx["eventName"])

	thingClient.Stop()
	consumerClient.Stop()
}

func TestPublishPropertyValues(t *testing.T) {
	logrus.Infof("--- TestPublishPropertyValues ---")
	credentials := ""
	thingID := "thing1"
	propValues := map[string]interface{}{"propname": "value"}
	var rx map[string]interface{}

	thingClient := mqttclient.NewMqttHubClient(mqttTestServerHostPort, mqttTestCaCertFile, "", credentials)
	err := thingClient.Start(false)
	assert.NoError(t, err)
	consumerClient := mqttclient.NewMqttHubClient(mqttTestServerHostPort, mqttTestCaCertFile, "", credentials)
	err = consumerClient.Start(false)
	assert.NoError(t, err)
	consumerClient.SubscribeToPropertyValues(thingID, func(thingID string, values map[string]interface{}, sender string) {
		logrus.Infof("TestPublishPropertyValues: Received values of Thing %s from client %s", thingID, sender)
		rx = values
	})

	time.Sleep(time.Millisecond)
	err = thingClient.PublishPropertyValues(thingID, propValues)
	assert.NoError(t, err)

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, propValues["propname"], rx["propname"])

	thingClient.Stop()
	consumerClient.Stop()
}
func TestPublishTD(t *testing.T) {
	logrus.Infof("--- TestPublishTD ---")
	credentials := ""
	thingID := "thing1"
	td1 := td.CreateTD(thingID)
	var rxTd map[string]interface{}

	thingClient := mqttclient.NewMqttHubClient(mqttTestServerHostPort, mqttTestCaCertFile, "", credentials)
	err := thingClient.Start(false)
	assert.NoError(t, err)
	consumerClient := mqttclient.NewMqttHubClient(mqttTestServerHostPort, mqttTestCaCertFile, "", credentials)
	err = consumerClient.Start(false)
	assert.NoError(t, err)
	consumerClient.SubscribeToTD(thingID, func(thingID string, thing map[string]interface{}, sender string) {
		logrus.Infof("TestPublishTD: Received TD of Thing %s from client %s", thingID, sender)
		rxTd = thing
	})
	time.Sleep(time.Millisecond * 100)

	err = thingClient.PublishTD(thingID, td1)
	assert.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, td1["id"], rxTd["id"])

	// TODO, check if it was received by a consumer using a consumer client
	thingClient.Stop()
	consumerClient.Stop()
}

// subscribe to all things
func TestSubscribeAll(t *testing.T) {
	logrus.Infof("--- TestSubscribeAll ---")
	credentials := ""
	thingID := "thing1"
	td1 := td.CreateTD(thingID)
	txTd, _ := json.Marshal(td1)
	var rxTd []byte
	var rxThing string

	pluginClient := mqttclient.NewMqttHubClient(mqttTestServerHostPort, mqttTestCaCertFile, "", credentials)
	err := pluginClient.Start(false)
	assert.NoError(t, err)
	thingClient := mqttclient.NewMqttHubClient(mqttTestServerHostPort, mqttTestCaCertFile, "", credentials)
	err = thingClient.Start(false)
	assert.NoError(t, err)
	pluginClient.Subscribe("", func(thingID string, msgType string, raw []byte, sender string) {
		logrus.Infof("TestSubscribe: Received msg %s of Thing %s from client %s", msgType, thingID, sender)
		rxTd = raw
		rxThing = thingID
	})
	time.Sleep(time.Millisecond * 100)

	err = thingClient.PublishTD(thingID, td1)
	assert.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, string(txTd), string(rxTd))
	assert.Equal(t, thingID, rxThing)

	// after unsubscribe there should be no more messages
	pluginClient.Unsubscribe("")
	time.Sleep(100 * time.Millisecond)
	err = thingClient.PublishTD(thingID, td1)
	rxTd = nil
	time.Sleep(100 * time.Millisecond)
	assert.NotEqual(t, td1, rxTd)

	// TODO, check if it was received by a consumer using a consumer client
	thingClient.Stop()
	pluginClient.Stop()
}
