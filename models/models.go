package models

/*
JldapData represents the full LDAP data export, including base DN, administrative user, all users, and all groups.
*/
type JldapData struct {
	BaseDN       string       `json:"baseDN"`
	AdminUsersCN string       `json:"adminUsersCN"`
	Users        []JldapUser  `json:"users"`
	Groups       []JldapGroup `json:"groups"`
}

/*
JldapUser models an LDAP user entry. It includes identity attributes, authentication information, and optional POSIX account properties.
*/
type JldapUser struct {
	CN           string   `json:"cn"`
	SN           string   `json:"sn"`
	GivenName    string   `json:"givenName"`
	UID          string   `json:"uid"`
	Mail         string   `json:"mail"`
	UserPassword string   `json:"userPassword"`
	UIDNumber    string   `json:"uidNumber,omitempty"`
	GIDNumber    string   `json:"gidNumber,omitempty"`
	HomeDir      string   `json:"homeDirectory,omitempty"`
	LoginShell   string   `json:"loginShell,omitempty"`
	ObjectClass  []string `json:"objectClass,omitempty"`
}

/*
JldapGroup models an LDAP group entry. It includes group identifiers, member references, and object class definitions.
*/
type JldapGroup struct {
	CN          string   `json:"cn"`
	GIDNumber   string   `json:"gidNumber,omitempty"`
	Member      []string `json:"member,omitempty"`
	MemberUID   []string `json:"memberUid,omitempty"`
	ObjectClass []string `json:"objectClass,omitempty"`
}
