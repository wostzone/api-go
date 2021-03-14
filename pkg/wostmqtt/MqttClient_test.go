package wostmqtt_test

import (
	"testing"

	"github.com/wostzone/api/pkg/wostmqtt"
)

const mqttServerHostPort = "localhost:8883"
const mqttCertFolder = "/etc/mosquitto/certs"

// These tests require an MQTT TLS server on localhost with TLS support

func TestMqttConnect(t *testing.T) {
	client := wostmqtt.NewMqttClient(mqttCertFolder, mqttServerHostPort)
	TMessengerConnect(t, client)
}

func TestMqttNoConnect(t *testing.T) {
	invalidHost := "localhost:1111"
	client := wostmqtt.NewMqttClient(mqttCertFolder, invalidHost)
	TMessengerNoConnect(t, client)
}

func TestMQTTPubSub(t *testing.T) {
	client := wostmqtt.NewMqttClient(mqttCertFolder, mqttServerHostPort)
	TMessengerPubSub(t, client)
}

func TestMQTTMultipleSubscriptions(t *testing.T) {
	client := wostmqtt.NewMqttClient(mqttCertFolder, mqttServerHostPort)
	TMessengerMultipleSubscriptions(t, client)
}

func TestMQTTBadUnsubscribe(t *testing.T) {
	client := wostmqtt.NewMqttClient(mqttCertFolder, mqttServerHostPort)
	TMessengerBadUnsubscribe(t, client)
}

func TestMQTTPubNoConnect(t *testing.T) {
	invalidHost := "localhost:1111"
	client := wostmqtt.NewMqttClient(mqttCertFolder, invalidHost)
	TMessengerPubNoConnect(t, client)
}

func TestMQTTSubBeforeConnect(t *testing.T) {
	client := wostmqtt.NewMqttClient(mqttCertFolder, mqttServerHostPort)
	TMessengerSubBeforeConnect(t, client)
}
