package td

// Thing property creation

// ThingPropType with types of property that are defined
type ThingPropType string

const (
	// Property is an actuator (readonly, use Actions)
	PropertyTypeActuator ThingPropType = "actuator"
	// Property is a readonly internal Thing attribute
	PropertyTypeAttr ThingPropType = "attr"
	// Property is a writable configuration
	PropertyTypeConfig ThingPropType = "configuration"
	// Property is a readonly sensor
	PropertyTypeSensor ThingPropType = "sensor"
	// Property is a readonly internal state
	PropertyTypeState ThingPropType = "state"
	// Property is an input (use in Actions)
	PropertyTypeInput ThingPropType = "input"
	// Property is an output (when different from sensor)
	PropertyTypeOutput ThingPropType = "output"
)

// CreateTDProperty creates a new property instance
//  title propery title for presentation
//  description optional extra description of what the property does
//  propType provides @type value for a property
//  writable property is a configuration value and is writable
func CreateTDProperty(title string, description string, propType ThingPropType) map[string]interface{} {

	var writable = (propType == PropertyTypeConfig)
	prop := make(map[string]interface{}, 0)
	prop["type"] = "null"
	prop["@type"] = propType
	prop["title"] = title
	prop["description"] = description
	prop["writable"] = writable
	// see https://www.w3.org/TR/2020/WD-wot-thing-description11-20201124/#example-29
	prop["readOnly"] = !writable
	prop["writeOnly"] = writable

	return prop
}

func SetTDPropertyEnum(prop map[string]interface{}, enumValues ...interface{}) {
	prop["enum"] = enumValues
}

func SetTDPropertyUnit(prop map[string]interface{}, unit string) {
	prop["unit"] = unit
}

// SetTDPropertyDataTypeArray sets the property data type as an array (of ?)
// If maxItems is 0, both minItems and maxItems are ignored
//  minItems is the minimum nr of items required
//  maxItems sets the maximum nr of items required
func SetTDPropertyDataTypeArray(prop map[string]interface{}, minItems uint, maxItems uint) {
	prop["type"] = "array"
	if maxItems > 0 {
		prop["minItems"] = minItems
		prop["maxItems"] = maxItems
	}
}

// SetPropertyTypeNumber sets the property data type as an integer
// If min and max are both 0, they are ignored
//  min is the minimum value
//  max sets the maximum value
func SetTDPropertyDataTypeInteger(prop map[string]interface{}, min int, max int) {
	prop["type"] = "integer"
	if !(min == 0 && max == 0) {
		prop["minimum"] = min
		prop["maximum"] = max
	}
}

// SetTDPropertyDataTypeNumber sets the property data type as floating point number
// If min and max are both 0, they are ignored
//  min is the minimum value
//  max sets the maximum value
func SetTDPropertyDataTypeNumber(prop map[string]interface{}, min float64, max float64) {
	prop["type"] = "number"
	if !(min == 0 && max == 0) {
		prop["minimum"] = min
		prop["maximum"] = max
	}
}

// SetTDPropertyDataTypeObject sets the property data type as an object
func SetTDPropertyDataTypeObject(prop map[string]interface{}, object interface{}) {
	prop["type"] = "object"
	prop["object"] = object
}

// SetTDPropertyDataTypeString sets the property data type as string
// If minLength and maxLength are both 0, they are ignored
//  minLength is the minimum value
//  maxLength sets the maximum value
func SetTDPropertyDataTypeString(prop map[string]interface{}, minLength int, maxLength int) {
	prop["type"] = "string"
	if !(minLength == 0 && maxLength == 0) {
		prop["minLength"] = minLength
		prop["maxLength"] = maxLength
	}
}
