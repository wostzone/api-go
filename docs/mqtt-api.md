
# WoST Hub MQTT API

This document describes the MQTT API used to connect to the WoST Hub. The server side is provided by the Hub MQTT protocol binding.

It is based on the Dec 2020 draft specification of [WEB Thing API](https://webthings.io/api/) with some changes to make it WoST compatible.

Note that this is an abbreviated description of the full API. The full API will be defined in Swagger in the future.

## Security Schemes

Where applicable, the Hub supports the API's with [security schemes](https://www.w3.org/TR/wot-thing-description/): 
* BasicSecurityScheme
* DigestSecurityScheme
* APIKeySecurityScheme
* BearerSecurityScheme
* PSKSecurityScheme 
* OAuth2SecurityScheme

Clients can connect to the API using one of these schemes.


## HUB MQTT API

The MQTT API is intended for live communication between Things, Services and Consumers. 

* Things publishes updates to their TD 
* Things publishes updates to their property values 
* Things publishes events
* Consumer publishes a configuration update requests
* Consumer publishes an action request

### Provisioning

> ### TBD


### Thing Publishes a Thing Description Document

Thing publish a Thing Description Document to subscribers

> Topic: things/{id}/td
> Content: 
> ```json
> {
>   Full TD
> }
>```

Consumers can subscribe to this topic or the 'things/+/td' topic to receive TDs as they are published.

### Thing Publishes Update To Their Property Values 

Notify consumers that one or more Thing property values are updated. 

* Note1: that the Mozilla API uses the things/{id}/properties address.
* Note2: the final topic is still tbd, should this use 'properties' or 'values'?

> Topic: things/{id}/values
> Content: 
> ```json
> {
>    "{property1}": {value1}
>    ...
> }
>```

Consumers can subscribe to a this topic or the 'things/+/values' wildcard topic to receive updates to property values as they are published.

### Thing Publishes Events

Notify consumers of one or more events that have happened on a Thing.

> Topic: things/{id}/events
> ```json
> Content:
> {
>   "event1": {
>     "data": {value},
>     "timestamp": {iso8601 timestamp},
>   },
>    ...
> }
> ```

### Consumer Publishes Update To Thing Configuration Values

Consumer request that a Thing updates its configuration property value(s). Note that actuator values are updated through actions.

Things subscribe to this address to receive the update request. If successful this results in a publication of a configuration property values update message by the Thing.

> Topic: things/{id}/config
> Content: 
> ```json
> {
>    "{property1}": {value1}
>    ...
> }
>```

### Consumer Publishes Request That A Thing Performs An Action

Consumer requests an action on a Thing. 

Things subscribe to this address to receive the action requests. If successful this results in a publication of an actuator property value update message by the Thing.

> Topic: things/{id}/action
> ```json
> Content:
> {
>   "event1": {
>     "data": {value},
>     "timestamp": {iso8601 timestamp},
>   },
>    ...
> }
> ```


