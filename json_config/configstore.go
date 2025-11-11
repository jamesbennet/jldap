package json_config

import (
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"jldap/models"
)

/*
The ConfigStore struct represents the in-memory representation of the configuration.
*/
type ConfigStore struct {
	// Read/write mutex protecting concurrent access to the config data.
	Mu sync.RWMutex
	// Filesystem path where the config is stored.
	Path string
	// The actual configuration data (users, groups, base DN, etc.).
	Data models.JldapData
	// When the config was last reloaded from disk.
	lastReload time.Time
	// Last modification time of the file on disk when read.
	lastFileMTime time.Time
}

/*
The AddUser function takes a JldapUser as input and returns an error.
*/
func (c *ConfigStore) AddUser(u models.JldapUser) error {
	// Trims whitespace around u.UID and checks if it’s empty. If empty, logs an error message and returns an error – UID is mandatory.
	if strings.TrimSpace(u.UID) == "" {
		log.Printf("uid is required")
		return errors.New("uid is required")
	}
	// Remove any unwanted whitespace
	u.CN = strings.TrimSpace(u.CN)
	u.SN = strings.TrimSpace(u.SN)
	u.GivenName = strings.TrimSpace(u.GivenName)
	u.UID = strings.TrimSpace(u.UID)
	u.Mail = strings.TrimSpace(u.Mail)
	u.UserPassword = strings.TrimSpace(u.UserPassword)
	u.UIDNumber = strings.TrimSpace(u.UIDNumber)
	u.GIDNumber = strings.TrimSpace(u.GIDNumber)
	u.HomeDir = strings.TrimSpace(u.HomeDir)
	u.LoginShell = strings.TrimSpace(u.LoginShell)
	cleanObjectclass := make([]string, len(u.ObjectClass))
	for i, s := range u.ObjectClass {
		cleanObjectclass[i] = strings.TrimSpace(s)
	}
	u.ObjectClass = cleanObjectclass

	// Acquires the write lock (exclusive lock) because this method modifies data.
	c.Mu.Lock()
	// defer c.Mu.Unlock() ensures the mutex is unlocked when the function returns, regardless of where it exits.
	defer c.Mu.Unlock()
	// Ensures the config has a BaseDN defined. If not, logs and returns an error because you can’t properly construct DNs without it.
	if strings.TrimSpace(c.Data.BaseDN) == "" {
		log.Printf("config has no BaseDN")
		return errors.New("config has no BaseDN")
	}
	// Loops over the Users slice by index.
	for i := range c.Data.Users {
		// strings.EqualFold compares UIDs case-insensitively.
		// If a user with the same UID already exists, you’re in “update existing user” mode.
		if strings.EqualFold(c.Data.Users[i].UID, u.UID) {
			// Takes a pointer to the existing user in the slice so you can modify it in-place.
			ex := &c.Data.Users[i]
			// For each field: if the incoming user’s field is non-empty (or slice non-empty), overwrite the existing user’s field.
			// This pattern lets you do partial updates: only explicitly-set fields in u overwrite existing values.
			if u.CN != "" {
				ex.CN = u.CN
			}
			if u.SN != "" {
				ex.SN = u.SN
			}
			if u.GivenName != "" {
				ex.GivenName = u.GivenName
			}
			if u.Mail != "" {
				ex.Mail = u.Mail
			}
			if u.UserPassword != "" {
				ex.UserPassword = u.UserPassword
			}
			if u.UIDNumber != "" {
				ex.UIDNumber = u.UIDNumber
			}
			if u.GIDNumber != "" {
				ex.GIDNumber = u.GIDNumber
			}
			if u.HomeDir != "" {
				ex.HomeDir = u.HomeDir
			}
			if u.LoginShell != "" {
				ex.LoginShell = u.LoginShell
			}
			if len(u.ObjectClass) > 0 {
				ex.ObjectClass = u.ObjectClass
			}
			// After updating the existing user, call saveToDiskLocked() to write c.Data to disk, and return immediately since work is done.
			return c.saveToDiskLocked()
		}
	}
	// If loop ends with no match, no existing user had that UID, so append the new user to the users slice.
	c.Data.Users = append(c.Data.Users, u)
	// Save the updated config to disk and return any error from that.
	return c.saveToDiskLocked()
}

/*
The DeleteUser function removes a user by UID.
*/
func (c *ConfigStore) DeleteUser(uid string) error {
	// Trim the UID and ensure it’s not empty; log and return error if it is.
	uid = strings.TrimSpace(uid)
	if uid == "" {
		log.Printf("uid required")
		return errors.New("uid required")
	}
	c.Mu.Lock()
	defer c.Mu.Unlock()
	// found tracks whether the user to delete is found.
	found := false
	// users := c.Data.Users[:0] reuses the underlying array of c.Data.Users but sets the logical length to 0. This is a common Go trick to build a filtered slice without extra allocations.
	users := c.Data.Users[:0]
	// Iterate over existing users.
	// If the UID matches (case-insensitive), set found = true and skip appending (effectively deleting it). All other users are appended to the new users slice.
	for _, ex := range c.Data.Users {
		if strings.EqualFold(ex.UID, uid) {
			found = true
			continue
		}
		users = append(users, ex)
	}
	// If no user with that UID was found, log and return an error.
	if !found {
		log.Printf("user not found")
		return errors.New("user not found")
	}
	// Replace the original users slice with the filtered one (without the deleted user).
	c.Data.Users = users
	userDN := "uid=" + uid + ",ou=users," + strings.TrimSpace(c.Data.BaseDN)
	// Construct the user’s full DN string based on UID and BaseDN.
	for i := range c.Data.Groups {
		// Loop through each group, and for MemberUID slice, rebuild it excluding the deleted user’s UID using the same [:0] reuse trick.
		mu := c.Data.Groups[i].MemberUID[:0]
		for _, v := range c.Data.Groups[i].MemberUID {
			if !strings.EqualFold(v, uid) {
				mu = append(mu, v)
			}
		}
		// Assign filtered slice back to MemberUID.
		c.Data.Groups[i].MemberUID = mu
		// Similarly filter the Member slice (which contains full DNs), removing the user’s DN, and assign the filtered slice back.
		mem := c.Data.Groups[i].Member[:0]
		for _, m := range c.Data.Groups[i].Member {
			if !strings.EqualFold(m, userDN) {
				mem = append(mem, m)
			}
		}
		c.Data.Groups[i].Member = mem
	}
	// Save updated config (without the user and without their group memberships) to disk.
	return c.saveToDiskLocked()
}

/*
The AddGroup function adds or updates a group.
*/
func (c *ConfigStore) AddGroup(g models.JldapGroup) error {
	// Remove any unwanted whitespace
	g.CN = strings.TrimSpace(g.CN)
	g.GIDNumber = strings.TrimSpace(g.GIDNumber)
	cleanMember := make([]string, len(g.Member))
	for i, s := range g.Member {
		cleanMember[i] = strings.TrimSpace(s)
	}
	g.Member = cleanMember
	cleanMemberUID := make([]string, len(g.MemberUID))
	for i, s := range g.MemberUID {
		cleanMemberUID[i] = strings.TrimSpace(s)
	}
	g.MemberUID = cleanMemberUID
	cleanObjectclass := make([]string, len(g.ObjectClass))
	for i, s := range g.ObjectClass {
		cleanObjectclass[i] = strings.TrimSpace(s)
	}
	g.ObjectClass = cleanObjectclass

	// Require non-empty CN (group name).
	if strings.TrimSpace(g.CN) == "" {
		log.Printf("cn is required")
		return errors.New("cn is required")
	}
	// Lock for writing.
	c.Mu.Lock()
	defer c.Mu.Unlock()
	// Iterate groups by index.
	for i := range c.Data.Groups {
		// If an existing group has the same CN (case-insensitive), you’ll update that group.
		if strings.EqualFold(c.Data.Groups[i].CN, g.CN) {
			// ex is a pointer to the existing group in the slice.
			ex := &c.Data.Groups[i]
			// Similar update pattern: only overwrite fields if non-empty/non-zero in the new group struct.
			if g.GIDNumber != "" {
				ex.GIDNumber = g.GIDNumber
			}
			if len(g.Member) > 0 {
				ex.Member = g.Member
			}
			if len(g.MemberUID) > 0 {
				ex.MemberUID = g.MemberUID
			}
			if len(g.ObjectClass) > 0 {
				ex.ObjectClass = g.ObjectClass
			}
			// If updated existing group, save to disk and return.
			return c.saveToDiskLocked()
		}
	}
	// If no existing group with that CN, append a new group and save.
	c.Data.Groups = append(c.Data.Groups, g)
	return c.saveToDiskLocked()
}

/*
The DeleteGroup function allows to delete a group by CN.
*/
func (c *ConfigStore) DeleteGroup(cn string) error {
	cn = strings.TrimSpace(cn)
	// Validate CN is not empty.
	if cn == "" {
		log.Printf("cn required")
		return errors.New("cn required")
	}
	// Lock for writing.
	c.Mu.Lock()
	defer c.Mu.Unlock()
	// Use the same filter pattern: rebuild grps without the group whose CN matches.
	found := false
	grps := c.Data.Groups[:0]
	for _, ex := range c.Data.Groups {
		if strings.EqualFold(ex.CN, cn) {
			found = true
			continue
		}
		grps = append(grps, ex)
	}
	// If no such group, log and return error.
	if !found {
		log.Printf("group not found")
		return errors.New("group not found")
	}
	// Update groups slice, then save to disk.
	c.Data.Groups = grps
	return c.saveToDiskLocked()
}

/*
The ListUsers function returns a copy of the list of users.
*/
func (c *ConfigStore) ListUsers() []models.JldapUser {
	// Uses RLock (read lock) because it only reads data.
	c.Mu.RLock()
	defer c.Mu.RUnlock()
	// allocates a new slice of the same length.
	out := make([]models.JldapUser, len(c.Data.Users))
	// copies all users, so callers don’t accidentally mutate internal state.
	copy(out, c.Data.Users)
	// Returns the copied slice.
	return out
}

/*
The GetUser function looks up a user by UID.
*/
func (c *ConfigStore) GetUser(uid string) (models.JldapUser, bool) {
	// Trim the UID.
	uid = strings.TrimSpace(uid)
	// Use read lock.
	c.Mu.RLock()
	defer c.Mu.RUnlock()
	// Loop through users; if case-insensitive match found, return that user and true.
	for _, u := range c.Data.Users {
		if strings.EqualFold(u.UID, uid) {
			return u, true
		}
	}
	// If not found, return zero-value JldapUser and false.
	return models.JldapUser{}, false
}

/*
The ListGroups function follows the pattern as ListUsers but for groups: read lock, copy slice, return copy.
*/
func (c *ConfigStore) ListGroups() []models.JldapGroup {
	c.Mu.RLock()
	defer c.Mu.RUnlock()
	out := make([]models.JldapGroup, len(c.Data.Groups))
	copy(out, c.Data.Groups)
	return out
}

/*
The GetGroup function follows the same pattern as GetUser but for groups: trim, read lock, search by CN, return group and true if found, otherwise zero-value and false.
*/
func (c *ConfigStore) GetGroup(cn string) (models.JldapGroup, bool) {
	cn = strings.TrimSpace(cn)
	c.Mu.RLock()
	defer c.Mu.RUnlock()
	for _, g := range c.Data.Groups {
		if strings.EqualFold(g.CN, cn) {
			return g, true
		}
	}
	return models.JldapGroup{}, false
}

/*
The Info function returns some metadata: the config file path, last reload time, and last file modification time.
*/
func (c *ConfigStore) Info() (path string, lastReload, lastMtime time.Time) {
	// Use read lock to safely read these fields.
	c.Mu.RLock()
	defer c.Mu.RUnlock()
	return c.Path, c.lastReload, c.lastFileMTime
}

// AddUserToAdmin is a convenience method: add user to the admin group. Internally calls modifyAdminMembership with add = true.
func (c *ConfigStore) AddUserToAdmin(uid string) error {
	return c.modifyAdminMembership(uid, true)
}

// RemoveUserFromAdmin is a convenience method: remove user from admin group. Calls modifyAdminMembership with add = false.
func (c *ConfigStore) RemoveUserFromAdmin(uid string) error {
	return c.modifyAdminMembership(uid, false)
}

// modifyAdminMembership is an internal helper to add/remove a user from the admin group, depending on add.
func (c *ConfigStore) modifyAdminMembership(uid string, add bool) error {
	// Trim UID and ensure it’s not empty.
	uid = strings.TrimSpace(uid)
	if uid == "" {
		log.Printf("uid required")
		return errors.New("uid required")
	}
	// Lock for writing because membership will be modified.
	c.Mu.Lock()
	defer c.Mu.Unlock()
	// Get admin group CN from config (AdminUsersCN).
	adminCN := strings.TrimSpace(c.Data.AdminUsersCN)
	if adminCN == "" {
		// If not configured, log and return error.
		log.Printf("adminUsersCN not configured")
		return errors.New("adminUsersCN not configured")
	}
	var g *models.JldapGroup
	// Search for the admin group in c.Data.Groups by CN (case-insensitive).
	// If found, g will point to that group.
	for i := range c.Data.Groups {
		if strings.EqualFold(c.Data.Groups[i].CN, adminCN) {
			g = &c.Data.Groups[i]
			break
		}
	}
	// If g is still nil, the admin group doesn’t exist:
	// Create a new JldapGroup with CN set to adminCN, and append it to the groups slice. Then, update g to point to the newly added group in the slice.
	if g == nil {
		g = &models.JldapGroup{
			CN:        adminCN,
			GIDNumber: "",
		}
		c.Data.Groups = append(c.Data.Groups, *g)
		g = &c.Data.Groups[len(c.Data.Groups)-1]
	}
	// Grab BaseDN, trim it.
	baseDN := strings.TrimSpace(c.Data.BaseDN)
	// Build user’s DN for admin group’s Member field.
	userDN := "uid=" + uid + ",ou=users," + baseDN
	// If add is true, we’re adding user membership:
	if add {
		found := false
		// Check if UID is already in MemberUID. If not, append it.
		for _, u := range g.MemberUID {
			if strings.EqualFold(u, uid) {
				found = true
				break
			}
		}
		if !found {
			g.MemberUID = append(g.MemberUID, uid)
		}
		found = false
		for _, dn := range g.Member {
			if strings.EqualFold(dn, userDN) {
				found = true
				break
			}
		}
		// Check if user DN is already in Member. If not, append it.
		if !found {
			g.Member = append(g.Member, userDN)
		}
	} else {
		// Else branch: add == false, so we’re removing the user from the admin group
		// Filter MemberUID, keeping all UIDs except the one we’re removing.
		mu := g.MemberUID[:0]
		for _, u := range g.MemberUID {
			if !strings.EqualFold(u, uid) {
				mu = append(mu, u)
			}
		}
		g.MemberUID = mu
		// Filter Member, keeping all DNs except this user’s DN.
		mem := g.Member[:0]
		for _, dn := range g.Member {
			if !strings.EqualFold(dn, userDN) {
				mem = append(mem, dn)
			}
		}
		g.Member = mem
	}
	// After updating the admin group, save the config to disk and return any error.
	return c.saveToDiskLocked()
}
