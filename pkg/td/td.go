package td

import "github.com/sirupsen/logrus"

// tbd json-ld parsers:
// Most popular; https://github.com/xeipuuv/gojsonschema
// Other:  https://github.com/piprate/json-gold

// AddTDAction adds or replaces an action in the TD
//  td is a TD created with 'CreateTD'
//  name of action to add
//  action created with 'CreateAction'
func AddTDAction(td map[string]interface{}, name string, action interface{}) {
	actions := td["actions"].(map[string]interface{})
	if action == nil {
		logrus.Errorf("Add action '%s' to TD. Action is nil", name)
	} else {
		actions[name] = action
	}
}

// AddTDEvent adds or replaces an event in the TD
//  td is a TD created with 'CreateTD'
//  name of action to add
//  event created with 'CreateEvent'
func AddTDEvent(td map[string]interface{}, name string, event interface{}) {
	events := td["events"].(map[string]interface{})
	if event == nil {
		logrus.Errorf("Add event '%s' to TD. Event is nil.", name)
	} else {
		events[name] = event
	}
}

// AddTDProperty adds or replaces a property in the TD
//  td is a TD created with 'CreateTD'
//  name of property to add
//  property created with 'CreateProperty'
func AddTDProperty(td map[string]interface{}, name string, property interface{}) {
	props := td["properties"].(map[string]interface{})
	if property == nil {
		logrus.Errorf("Add property '%s' to TD. Propery is nil.", name)
	} else {
		props[name] = property
	}
}

// SetThingVersion adds or replace Thing version info in the TD
//  td is a TD created with 'CreateTD'
//  version with map of 'name: version'
func SetThingVersion(td map[string]interface{}, version map[string]string) {
	td["version"] = version
}

// SetThingErrorStatus sets the error status of a Thing
// This is set under the 'status' property, 'error' subproperty
//  td is a TD created with 'CreateTD'
//  status is a status tring
func SetThingErrorStatus(td map[string]interface{}, errorStatus string) {
	// FIXME:is this a property
	status := td["status"]
	if status == nil {
		status = make(map[string]interface{})
		td["status"] = status
	}
	status.(map[string]interface{})["error"] = errorStatus
}

// SetTDForm sets the top level forms section of the TD
// NOTE: In WoST actions are always routed via the Hub using the Hub's protocol binding.
// Under normal circumstances forms are therefore not needed.
//  td to add form to
//  forms with list of forms to add. See also CreateForm to create a single form
func SetTDForms(td map[string]interface{}, formList []map[string]interface{}) {
	td["forms"] = formList
}

// CreateTD creates a new Thing Description document with properties, events and actions
func CreateTD(id string) map[string]interface{} {
	td := make(map[string]interface{}, 0)
	td["@context"] = "http://www.w3.org/ns/td"
	td["id"] = id
	td["properties"] = make(map[string]interface{})
	td["events"] = make(map[string]interface{})
	td["actions"] = make(map[string]interface{})
	return td
}
