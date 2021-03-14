package wostapi

// WostAPI defines the common interface for all protocol bindings
type WostAPI interface {
	// Start the client connection
	Start(hostname string, clientID string) error

	// End the client connection
	Stop()

	// PublishTD publish a Thing description to the WoST hub
	PublishTD(td []byte)

	// PublishProperties publish a Thing property values to the WoST hub
	PublishProperties(props []byte)

	// PublishEvent publish a Thing event to the WoST hub
	PublishEvent(event []byte)
}
