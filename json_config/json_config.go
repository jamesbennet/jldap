package json_config

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"jldap/directory"
	"jldap/models"
)

/*
The LoadFromDisk function loads the JSON config file at c.Path into memory (into c.Data), and returns an error if anything goes wrong.
*/
func (c *ConfigStore) LoadFromDisk() error {
	// If Path is empty, we don’t know which file to read. Immediately return an error "no config Path".
	if c.Path == "" {
		return errors.New("no config Path")
	}
	// os.ReadFile(c.Path) reads the entire file contents into memory as []byte.
	b, err := os.ReadFile(c.Path)
	if err != nil {
		// If there’s an error (file missing, permission denied, etc.), log, and return the error to the caller.
		log.Printf("%+v", err)
		return err
	}
	var jd models.JldapData
	// Parse the JSON bytes into the jd struct.
	if err := json.Unmarshal(b, &jd); err != nil {
		// If the JSON is invalid or doesn’t match the struct, log the error and return it.
		log.Printf("%+v", err)
		return err
	}
	// os.Stat retrieves file info (size, mod time, etc.).
	fi, err := os.Stat(c.Path)
	if err != nil {
		// If there’s an error, log. No need to return, it fails, fi will be nil, and we handle that later.
		log.Printf("%+v", err)
	}
	// Acquire the write lock on the ConfigStore’s mutex (Mu is a sync.RWMutex).
	c.Mu.Lock()
	// Replace c.Data with the newly loaded jd.
	c.Data = jd
	// Set c.lastReload to the current time.
	c.lastReload = time.Now()
	// If file info was successfully obtained (fi != nil), store the file’s modification time in c.lastFileMTime.
	// This lets us later detect whether the file has changed on disk.
	if fi != nil {
		c.lastFileMTime = fi.ModTime()
	}
	// Release the lock and return nil (success)
	c.Mu.Unlock()
	return nil
}

/*
The saveToDiskLocked function Writes c.Data out to JSON on disk.
It assumes the caller already holds c.Mu.Lock(). That’s why it’s named *Locked — it doesn’t lock/unlock itself.
*/
func (c *ConfigStore) saveToDiskLocked() error {
	// json.MarshalIndent converts c.Data into pretty-printed JSON (" " indentation, no prefix).
	buf, err := json.MarshalIndent(c.Data, "", "  ")
	// On error (e.g. a type that can’t be marshaled), log and return the error.
	if err != nil {
		log.Printf("%+v", err)
		return err
	}
	// dir is the directory part of c.Path. filepath.Base(c.Path) is the filename part.
	dir := filepath.Dir(c.Path)
	// tmp is a temporary path in the same directory, like ./.config.json.tmp:
	// The . prefix makes it hidden-ish on Unix.
	tmp := filepath.Join(dir, "."+filepath.Base(c.Path)+".tmp")
	// Write the JSON bytes buf into the temp file tmp. File permissions: 0o600 (owner read/write only).
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		// If writing fails, log and return the error.
		log.Printf("%+v", err)
		return err
	}
	// Atomically replace the final file with the temp file via os.Rename.
	// On most OSes in the same filesystem, this is atomic — prevents partial writes and corruption.
	if err := os.Rename(tmp, c.Path); err != nil {
		// Log and return error if rename fails.
		log.Printf("%+v", err)
		return err
	}
	// Because os.Rename will NOT preserve the permissions of an existing file on all platforms, force correct perms after rename.
	err = os.Chmod(c.Path, 0o600)
	if err != nil {
		// If it fails, log error
		log.Printf("%+v", err)
	}
	// After successful write, set lastFileMTime to “now” (approximate; not the actual filesystem mtime, but close).
	c.lastFileMTime = time.Now()
	// Return success.
	return nil
}

/*
The LoadDirectoryFromJSON function reads a JSON file, parses it into models.JldapData, converts that into an in-memory LDAP-like Directory (users + groups), and returns a *directory.Directory.
It takes a filesystem path, returns either a pointer to Directory or an error.
*/
func LoadDirectoryFromJSON(path string) (*directory.Directory, error) {
	// Read the whole file into data.
	data, err := os.ReadFile(path)
	if err != nil {
		// If it fails, log error and return (nil, err).
		log.Printf("%+v", err)
		return nil, err
	}
	var jd models.JldapData
	// Parse JSON into jd.
	if err := json.Unmarshal(data, &jd); err != nil {
		// On failure, log and return (nil, err).
		log.Printf("%+v", err)
		return nil, err
	}
	// If AdminUsersCN in the JSON is empty/whitespace, default it to "homelab_admins". This is a convenience default for the “admin users” group CN.
	if strings.TrimSpace(jd.AdminUsersCN) == "" {
		jd.AdminUsersCN = "homelab_admins"
	}
	// Normalize the base DN by trimming whitespace. If empty, that’s a fatal config error: log a message and return an error.
	// The base DN (“dc=example,dc=com”, etc.) is required to build DNs.
	base := strings.TrimSpace(jd.BaseDN)
	if base == "" {
		log.Printf("json: BaseDN is required")
		return nil, errors.New("json: BaseDN is required")
	}
	// Create a new in-memory directory, rooted at base. It sets up internal maps like ByDN, ByUID, etc.
	d := directory.NewDirectory(base)
	// Add users to the directory.
	// Iterate over all users in the JSON data (jd.Users).
	for _, u := range jd.Users {
		// Each user must have a UID. If not, log and return an error. This aborts the whole load if a single user is malformed.
		if strings.TrimSpace(u.UID) == "" {
			log.Printf("json: user missing uid")
			return nil, errors.New("json: user missing uid")
		}
		// Construct the user’s DN
		dn := "uid=" + u.UID + ",ou=users," + base
		// oc is the user’s objectClass list from JSON. If it’s empty, default it to a typical set of LDAP classes.
		oc := u.ObjectClass
		if len(oc) == 0 {
			oc = []string{"top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount"}
		}
		// Build the LDAP attribute map for this entry. Key = attribute name (lowercase here). Value = slice of strings (LDAP attributes can be multivalued).
		// objectclass is set to oc. cn, sn, givenname, displayname, uid, mail, userpassword come from the JSON user.
		a := map[string][]string{
			"objectclass":  oc,
			"cn":           {u.CN},
			"sn":           {u.SN},
			"givenname":    {u.GivenName},
			"displayname":  {u.CN},
			"uid":          {u.UID},
			"mail":         {u.Mail},
			"userpassword": {u.UserPassword},
		}
		// Only add these attributes if they’re non-empty in the JSON: uidnumber, gidnumber, homedirectory, loginshell.
		// That way, optional fields don’t appear as empty attributes.
		if u.UIDNumber != "" {
			a["uidnumber"] = []string{u.UIDNumber}
		}
		if u.GIDNumber != "" {
			a["gidnumber"] = []string{u.GIDNumber}
		}
		if u.HomeDir != "" {
			a["homedirectory"] = []string{u.HomeDir}
		}
		if u.LoginShell != "" {
			a["loginshell"] = []string{u.LoginShell}
		}
		// Create a directory.Entry for this user. Inserts the entry into the directory (and likely into indices like ByDN, ByUID, etc.).
		d.Add(&directory.Entry{
			// Full DN.
			DN: dn,
			// Attributes map created above.
			Attrs: a,
			// The parent DN (ou=users,<base>).
			Parent: "ou=users," + base,
		})
	} // End of user loop.
	// Add groups to the directory - Iterate over all groups in the JSON (jd.Groups).
	for _, g := range jd.Groups {
		// Group must have a CN. If missing, log and fail.
		if strings.TrimSpace(g.CN) == "" {
			log.Printf("json: group missing cn")
			return nil, errors.New("json: group missing cn")
		}
		// Construct group DN, e.g., cn=admins,ou=groups,dc=example,dc=com.
		dn := "cn=" + g.CN + ",ou=groups," + base
		// Use g.ObjectClass if provided; otherwise default to top, posixGroup, groupOfNames.
		oc := g.ObjectClass
		if len(oc) == 0 {
			oc = []string{"top", "posixGroup", "groupOfNames"}
		}
		// Start building the attribute map for the group: objectclass and cn are required.
		a := map[string][]string{
			"objectclass": oc,
			"cn":          {g.CN},
		}
		// If the group has a GIDNumber, add it.
		if g.GIDNumber != "" {
			a["gidnumber"] = []string{g.GIDNumber}
		}
		// If g.MemberUID is non-empty, loop over each member UID.
		if len(g.MemberUID) > 0 {
			for _, mu := range g.MemberUID {
				// Trim whitespace from each mu. Trim whitespace from each mu. This is a POSIX-style group membership (usernames/UIDs, not full DNs).
				if mu = strings.TrimSpace(mu); mu != "" {
					a["memberuid"] = append(a["memberuid"], mu)
				}
			}
		}
		// Now loop over g.Member, another membership list that may contain Full DNs, uid=... forms, plain usernames, maybe even cn=... or dn=....
		for _, m := range g.Member {
			// Trim each one; skip empty.
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			// l is lowercased version of m, used for case-insensitive checks.
			l := strings.ToLower(m)
			// Case 1: member looks like a DN starting with uid=... and contains a comma (e.g. uid=alice,ou=users,dc=example,dc=com). Treat it as a full DN and append it directly to the member attribute.
			if strings.HasPrefix(l, "uid=") && strings.Contains(l, ",") {
				a["member"] = append(a["member"], m)
			} else if isLikelyUID(m) {
				// Case 2: m is “likely” a UID (no commas and no = char; see isLikelyUID). Then attempt to resolve it via the directory’s ByUID index.
				// We Look up d.ByUID[strings.ToLower(m)]. If found, udn is the user’s DN, then look up the entry e := d.ByDN[udn].
				// If the entry exists, append its DN to the member attribute. If no such UID exists in the directory, log a warning that the member could not be found.
				if udn, ok := d.ByUID[strings.ToLower(m)]; ok {
					e := d.ByDN[udn]
					if e != nil {
						a["member"] = append(a["member"], e.DN)
					}
				} else {
					log.Printf("json: warning: group %q member %q not found by uid", g.CN, m)
				}
			} else if strings.HasPrefix(l, "cn=") || strings.HasPrefix(l, "dn=") || strings.Contains(m, "=") {
				// Case 3: m looks like some kind of DN or name reference: Starts with cn=... or dn=..., or just contains an = (typical DN format).
				// In that case, treat it as a DN-like string and append it directly to member.
				a["member"] = append(a["member"], m)
			} else {
				// Case 4 (fallback): Everything else (doesn’t look like uid=..., not “likely UID” by the earlier rule, not obviously DN-like).
				// Still try to resolve it as a UID via d.ByUID. If resolution fails, log a warning: unrecognized member format/value.
				if udn, ok := d.ByUID[strings.ToLower(m)]; ok {
					e := d.ByDN[udn]
					if e != nil {
						a["member"] = append(a["member"], e.DN)
					}
				} else {
					log.Printf("json: warning: group %q unrecognized member %q", g.CN, m)
				}
			}
		} // End of loop over g.Member.
		// Finally, create a directory.Entry for this group, and aAd it to the directory.
		d.Add(&directory.Entry{
			// cn=...,ou=groups,...
			DN: dn,
			// The attributes built above, including memberuid and member.
			Attrs:  a,
			Parent: "ou=groups," + base,
		})
	} // End of group loop.
	// Everything succeeded, return the populated directory and nil error.
	return d, nil
}

/*
The isLikelyUID function is a helper, returns true if s does not contain a comma or an equals sign.
The idea is that DNs typically contain commas and/or = signs. So if the string has neither, it’s probably just a bare username/UID like "alice".
Used to decide whether to treat a group member string as a UID that should be resolved to a DN.
*/
func isLikelyUID(s string) bool {
	return !strings.Contains(s, ",") && !strings.Contains(s, "=")
}
