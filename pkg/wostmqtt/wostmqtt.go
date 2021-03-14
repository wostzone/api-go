package wostmqtt

import (
	"strings"
)

/* Client library with the MQTT API to the Hub using (tbd):
A: paho-mqtt
B: https://github.com/emqx/emqx
*/

// TopicRoot is the base of the topic
const TopicRoot = "things"

// TopicThingTD topic for thing publishing its TD
const TopicThingTD = TopicRoot + "/{id}"

// TopicThingProperties topic for thing publishing its property values
const TopicThingProperties = TopicRoot + "/{id}/properties"

// TopicThingEvent topic for thing publishing its property values
const TopicThingEvent = TopicRoot + "/{id}/event"

// TopicSetProperty topic request to set property values
const TopicSetProperty = TopicRoot + "/{id}/set"

// TopicAction topic request to start action
const TopicAction = TopicRoot + "/{id}/action"

type WostMqttClient struct {
	mqttClient *MqttClient
	certFolder string
	timeoutSec int
}

// Start the client connection
func (wmc *WostMqttClient) Start(hostname string, clientID string) error {
	wmc.mqttClient = NewMqttClient(wmc.certFolder, hostname)
	err := wmc.mqttClient.Connect(clientID, wmc.timeoutSec)

	return err
}

// End the client connection
func (wmc *WostMqttClient) Stop() {
	wmc.mqttClient.Disconnect()
}

// PublishTD publish a Thing description to the WoST hub
func (wmc *WostMqttClient) PublishTD(thingID string, td []byte) error {
	topic := strings.ReplaceAll(TopicThingTD, "{id}", thingID)
	err := wmc.mqttClient.Publish(topic, td)
	return err
}

// PublishProperties publish a Thing property values to the WoST hub
func (wmc *WostMqttClient) PublishProperties(thingID string, props []byte) error {
	topic := strings.ReplaceAll(TopicThingProperties, "{id}", thingID)
	err := wmc.mqttClient.Publish(topic, props)
	return err
}

// PublishEvent publish a Thing event to the WoST hub
func (wmc *WostMqttClient) PublishEvent(thingID string, event []byte) error {
	topic := strings.ReplaceAll(TopicThingEvent, "{id}", thingID)
	err := wmc.mqttClient.Publish(topic, event)
	return err
}

// Create a new instance of the WoST MQTT client
// This implements the WostAPI interface
func NewWostMqtt(certFolder string) *WostMqttClient {
	wm := &WostMqttClient{
		certFolder: certFolder,
		timeoutSec: 3,
	}
	return wm
}
