# WoST Hub API

This repository defines the APIs to use the WoST Hub. It contains the type definitions and client libraries to exchange messages with the hub as well as constructing a Thing Definition document for use by WoST Things.

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



### config

### wosthttp

### wosthttp

The http client library can be used to get and post messages over HTTPS.

For example:
```go
  package myiotdevice
  import (
    "github.com/wostzone/api-go/pkg/td
    "github.com/wostzone/api-go/pkg/wosthttp
  )
  myTD := td.CreateTD(id)
  connection := wosthttp.CreateConnection(hostname, "myiotdevice")
  connection.PublishTD(myTD)
```
### wostapi


# Contributing

Contributions to WoST projects are always welcome. There are many areas where help is needed, especially with documentation and building plugins for IoT and other devices. See [CONTRIBUTING](https://github.com/wostzone/hub/docs/CONTRIBUTING.md) for guidelines.


# Credits

This project builds on the Web of Things (WoT) standardization by the W3C.org standards organization. For more information https://www.w3.org/WoT/
