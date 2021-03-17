# WoST Web Of Things API

This repository defines the API's to use to connect to the WoST Hub and exchange information between Things and consumers. It contains the type definitions and client libraries to exchange messages via the hub as well as constructing a *Thing Description* document. This API aims to adhere to the [WoT Specfications](https://www.w3.org/WoT/).

## Project Status

Status: In development, not ready for use

## Audience

This project is aimed at WoST Thing and Hub Plugin developers that share concerns about the security and privacy risk of running a server on every WoT Thing. WoST developers choose to not run servers on Things and instead use a hub and spokes model.


## Summary

This library provides API's to exchange messages with the WoST Hub in a WoT compatible manner. IoT developers can use it to provision their IoT device, publish their Thing Description, send events and receive actions. Plugin developers can use it to receive Thing Descriptions, events and property values, and to request Thing actions.

A Python and Javascript version is planned for the future.

## Dependencies

This requires the use of a WoST compatible Hub or Gateway.

Supported hubs and gateways:
- [WoST Hub](https://github.com/wostzone/hub)


## Usage

This module is intended to be used as a library by Things and Hub Plugin developers. It features support for building WoT compliant Thing Description documents, reading Hub and plugin configuration files, client connections to the Hub over HTTP/TLS and MQTT/TLS.

### hubconfig

The hubconfig package contains the library to read the Hub and plugin configuration files and setup logging. It is intended for plugin developers that need Hub configuration. 

### wosthttp

The wosthttp package contains the client code to connect to the Hub using the HTTP/TLS protocol binding. It is intended for Thing developers although it can also be used by consumers. This package is for convenience. It wraps the HTTP/TLS library and handles the TLS and certificate boilerplate. 

See the [HTTP API documentation](docs/http-api.md) for details. This client does not yet use [the Form method](https://www.w3.org/TR/2020/WD-wot-thing-description11-20201124/#protocol-bindings). This will be added in the near future.

Note that the above WoT specification talks about interaction between consumer and Thing. In the case of WoST this interaction takes place via the Hub.

The api/IThingClient.go package contains the interface on using this library.

For example:
```go
  package myiotdevice
  import (
    "github.com/wostzone/api-go/pkg/td
    "github.com/wostzone/api-go/pkg/wosthttp
  )
  certificateFolder := "./certs"
  deviceID := "mydevice1"
  myTD := td.CreateTD(id)
  client := wosthttp.NewWostHTTP(certificateFolder, )
  client.Start("", myDeviceID)
  client.PublishTD(myTD)
  client.Stop()
```

### wostmqtt

The wostmqtt package contains the client code to connect to the Hub over MQTT. It is intended for Thing and plugin developers. This package is for convenience. It wraps the Paho mqtt client and adds automatic reconnect and resubscribes in case connections get lost. 

See the [MQTT API documentation](docs/mqtt-api.md) for details. This client does not yet use [the Form method](https://www.w3.org/TR/2020/WD-wot-thing-description11-20201124/#protocol-bindings).  This will be added in the near future.

Note that the above WoT specification talks about interaction between consumer and Thing. In the case of WoST this interaction takes place via the Hub's message bus.

The api/IThingClient.go package contains the interface on using this library.

### certsetup

The certsetup package provides functions for creating self signed certificates include a self signed Certificate Authority (CA). These can be used for verifying authenticity of server and clients of the message bus.

### signing

The signing package provides functions to JWS sign and JWE encrypt messages. This is used to verify the authenticity of the sender of the message.

Signing support is built into the HTTP and MQTT protocol binding client and server. 
Well, soon anyways... 

Signing and sender verification is key to guarantee that the information has not been tampered with and originated from the sender. The WoT spec does not (?) have a place for this, so it might become a WoST extension.


> ### Under consideration
>  The protocol for signing messages is under consideration
> 
> The Thing public key and certificate is included in the Thing TD. The consumer uses the public key to verify the signature of the message which guarantees that the message has not been tampered with. The certificate that is included in the TD is provided by the Hub on provisioning and can be used to verify that the TD's authenticity. 
>
> In reverse, messages from consumers can also be signed and encrypted. Since consumers do not have a TD, a different method of discovering the consumer certificate is needed.
> 
> TBD, Options
> - Consumers receive a certificate from the Hub after signup/login/verification.
> - Certificate/Signature can be verified against Hub certificate
> - Consumers must be approved by admin before they are allowed to send action/config messages (the main role of the Hub is to coordinate auths)


### td

The td package provides methods to construct a WoT compliant Thing Description. 


# Contributing

Contributions to WoST projects are always welcome. There are many areas where help is needed, especially with documentation and building plugins for IoT and other devices. See [CONTRIBUTING](https://github.com/wostzone/hub/docs/CONTRIBUTING.md) for guidelines.


# Credits

This project builds on the Web of Things (WoT) standardization by the W3C.org standards organization. For more information https://www.w3.org/WoT/
