
# WoST Hub HTTP API

This document describes the HTTP API used to connect to the WoST Hub. The server side is implemented by the Hub HTTP protocol binding.

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


## HUB HTTP API 

This HUB HTTP API is an interface that lets Things send updates and events and answers to request for Thing information.

* Things can publish updates to their TD to the Hub
* Things can publish updates to their property values 
* Things can publish events
* Things can retrieve configuration update requests made in the last 24 hours (future)
* Things can retrieve action requests made in the last 24 hours (future)
* Consumers can publish action requests
* Consumers can publish thing property update requests

This interface has the following limitations:
* This API is not a Directory Service. See the directory service for more information on its API to query for Things. (once it is defined)
* This API does not support requests for historical values. See the history service for more information (well, once it is defined)

### Provisioning

A WoST compatible device must be provisioned using one of the client API's. When a device is provisioned by the Hub, they exchange credentials for secured connectivity and message exchange. The credentials are defined by the security schemes. A device manage multiple Things.

> ### This section is still to be defined

### Get a Thing Description
=== FUTURE ===
This returns the most receive Thing Description from the shadow registry

> ### Request 
> ```http
> HTTP Get https://{hub}/things/{id}
> Accept: application/json
> ```

> ### Response
> 200 OK
> ```json
> {
>    Full TD
> }
> ```

> ### Response
> 404 NOT FOUND
> ```

### Update a Thing Description Document

This updates a Thing Description Document in the shadow registry.

> ### Request 
> ```http
> HTTP PUT https://{hub}/things/{id}
> Accept: application/json
> {
>    Full TD
> }
> ```
> ### Response
> ```http
> 200 OK
> ```

Where
* {hub} is the DNS name or IP address of the Hub
* {id} is the ID of the thing


### Get All Thing Property Values

==Future==

This returns the property values of a Thing from the shadow registry.

> #### request
> ```http
> HTTP GET https://{hub}/things/{id}/properties
> Accept: application/json
> ```
> ### Response
> ```json
> {
>   "property1": "value 1",
>   ...
> }
> ```

### Get A Single Thing Property Value

==Future==

This returns the property value of a Thing from the shadow registry.

> #### request
> ```http
> HTTP GET https://{hub}/things/{id}/properties/{name}
> Accept: application/json
> ```
> ### Response
> ```json
> {
>   "{name}": "value",
> }
> ```

### Update Of A Thing's Property Values

This updates Thing property values in the shadow registry. Only the properties that are updated need to be included. 

> ### Request
> ```http
> HTTP PUT https://{hub}/things/{id}/properties
> Accept: application/json
> {
>    "{property1}": {value1},
>    ...
> }
> ```
> ### Response
> ```http
> 200 OK
> {
>    "{name}": {value},
>    ...
> }
### Set Thing Property Values

==Future==

This requests that a Thing updates its property value

> ### Request
> ```http
> HTTP PUT https://{hub}/things/{id}/set
> Accept: application/json
> {
>    "{property1}": {value1},
>    ...
> }
> ```
> ### Response
> ```http
> 200 OK
> {
>    "{name}": {value},
>    ...
> }

### Publish Thing Events

This notifies subscribers of an event that happened on a Thing.

> ### Request
> ```http
> PUT /things/{id}/events
> Accept: application/json
> Content:
> {
>   "event1": {
>     "data": {value},
>     "timestamp": {iso8601 timestamp},
>   },
>    ...
> }
> ### Response
> ```http
> 200 OK
> {
>    {event}
> }


### Request Queued Actions 

==Future==

This returns the queued actions of a Thing from the shadow registry.

This is intended for Things to request the actions that have been queued since their last request. After the result is returned the queue is emptied. It is intended for Things that cannot use the WebSocket or MQTT API.
This call is not idempotent.

> ### Request
> ```http
> Get /things/{id}/actions
> Accept: application/json
> 
> ### Response
> ```http
> 200 OK
> Content:
> {
>   "{action1}": {
>     "input": {
>       "{param1}": {value},
>       "{param2}": {value},
>     },
>   },
>    ...
> }



## API comparison

The HTTP API is intended to conform to the WoT API standard. As this is not yet defined this is a best guess.

