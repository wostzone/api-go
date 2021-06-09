// Package api with group based authorization definition
// Group based authorization is managed centrally by the Hub and implemented by protocol bindings
// These definitions are intended for use by protocol bindings that implement authorization for their protocol
package api

// Client roles for authorization. The client's role is stored in the certificate OU field.
// A client can have multiple roles.
// See also certsetup.CreateClientCert(clientId, role, ...)
const (
	// RoleNone indicates that the client has no particular role. It can not do anything until
	// the role is upgraded to viewer or better.
	RoleNone = "none"

	// RoleAdmin lets a user approve thing provisioning (postOOB), add and remove users
	// administrators are not users and do not control Things.
	RoleAdmin = "admin"

	// RoleManager lets a client subscribe to Thing TD, events, publish actions and update configuration
	RoleManager = "manager"

	// RolePlugin marks a client as a plugin. Plugins have full permission to all topics
	RolePlugin = "plugin"

	// RoleThing indicates the client is a IoT provider that can publish and subscribe
	// to Thing topics. A Thing Client can publish multiple Things.
	// Things should only publish events for Things it published the TD for.
	RoleThing = "thing"

	// RoleUser lets a client subscribe to Thing TD, events and publish actions
	RoleUser = "user"

	// RoleViewer lets a client subscribe to Thing TD and events
	RoleViewer = "viewer"
)

// AuthGroup defines a group with Thing and Users
// The permission is determined by taking the thing permission and user permission and
// return the lowest of the two.
// Eg an admin role can do anything only if the thing allows it
//
// This allows for Things to be shared with other groups with viewing rights only, even though
// there are user or admins in that group.
type AuthGroup struct {
	// The name of the group
	GroupName string
	// The members (thingIDs and userIDs) and their role: [memberid]role
	MemberRoles map[string]string
}
