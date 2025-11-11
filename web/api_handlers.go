package web

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"jldap/directory"
	"jldap/json_config"
	"jldap/models"
)

// apiUsersHandler returns an http.HandlerFunc that handles /api/users requests (list users, create users).
func apiUsersHandler(store *directory.DirStore, cfg *json_config.ConfigStore) http.HandlerFunc {
	// Return an anonymous function that matches http.HandlerFunc signature.
	return func(w http.ResponseWriter, r *http.Request) {
		// Enforce LDAP Basic Auth; if authentication fails, the helper writes the response and ok == false.
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			// Stop handling the request if authentication failed.
			return
		}

		// Branch on the HTTP method (POST for create, GET for list).
		switch r.Method {

		case http.MethodPost:
			// Handle user creation via POST /api/users.

			// Declare a variable to hold the JSON body as a JldapUser.
			var u models.JldapUser

			// Decode the JSON request body into the user struct.
			if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
				// Log the JSON decoding error.
				log.Printf("bad json: %+v", err)
				// Return HTTP 400 Bad Request with error details.
				http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Add the user to the JSON config store.
			if err := cfg.AddUser(u); err != nil {
				// Log the error from adding the user.
				log.Printf("%+v", err)
				// Convert the error to an HTTP status and send it back.
				http.Error(w, err.Error(), httpStatusFromErr(err))
				return
			}

			// Reload the in-memory directory from JSON so LDAP data reflects the new user.
			if d, err := json_config.LoadDirectoryFromJSON(cfg.Path); err != nil {
				// Log the error if reload fails.
				log.Printf("%+v", err)
			} else {
				// Update the shared directory store with the fresh directory.
				store.Set(d)
			}

			// Indicate that the resource was successfully created.
			w.WriteHeader(http.StatusCreated)

		case http.MethodGet:
			// Handle listing users via GET /api/users.

			// Retrieve the list of users from config.
			list := cfg.ListUsers()
			// Scrub passwords before returning the list over the API.
			safeList := scrubUsersPasswords(list)
			// Set the response content type to JSON.
			w.Header().Set("Content-Type", "application/json")
			// Encode the user list as JSON into the response body.
			err := json.NewEncoder(w).Encode(safeList)
			if err != nil {
				// Log any JSON encoding error.
				log.Printf("%+v", err)
			}

		default:
			// For any method other than GET or POST, return 405 Method Not Allowed.
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// apiUsersWithPathHandler handles routes like /api/users/{uid} and /api/users/{uid}/groups.
func apiUsersWithPathHandler(store *directory.DirStore, cfg *json_config.ConfigStore) http.HandlerFunc {
	// Return the handler function.
	return func(w http.ResponseWriter, r *http.Request) {
		// Enforce LDAP Basic Auth; abort if authentication fails.
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			return
		}

		// Strip the "/api/users/" prefix from the request path.
		rest := strings.TrimPrefix(r.URL.Path, "/api/users/")
		// Trim leading and trailing slashes from the remaining path.
		rest = strings.Trim(rest, "/")

		// If nothing remains, we don't have a UID, so return an error.
		if rest == "" {
			log.Printf("uid required")
			http.Error(w, "uid required", http.StatusBadRequest)
			return
		}

		// Check if this is the groups subresource: /api/users/{uid}/groups.
		if strings.HasSuffix(rest, "/groups") {
			// Only GET is allowed for this endpoint.
			if r.Method != http.MethodGet {
				log.Printf("method not allowed")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			// Remove the trailing "/groups" to get the UID portion.
			uid := strings.TrimSuffix(rest, "/groups")
			// Trim any remaining slashes around the UID.
			uid = strings.Trim(uid, "/")

			// If the UID is empty after trimming, return error.
			if uid == "" {
				log.Printf("uid required")
				http.Error(w, "uid required", http.StatusBadRequest)
				return
			}

			// Look up the user from the config by UID.
			u, ok := cfg.GetUser(uid)
			if !ok {
				// User not found; return 404.
				log.Printf("user not found")
				http.Error(w, "user not found", http.StatusNotFound)
				return
			}

			// Get the current in-memory directory.
			d := store.Get()
			// Construct the user's DN based on UID and directory base DN.
			userDN := "uid=" + u.UID + ",ou=users," + d.BaseDN
			// Find which groups this DN is a member of.
			memberOf := d.MemberOf(userDN)

			// Define an anonymous struct that will be JSON-encoded.
			resp := struct {
				// The user object
				User models.JldapUser `json:"user"`
				// The list of groups the user belongs to.
				MemberOf []string `json:"memberOf"`
			}{
				// Set the user field to the found user.
				User: scrubUserPassword(u),
				// Set the group membership list.
				MemberOf: memberOf,
			}

			// Set content type to JSON.
			w.Header().Set("Content-Type", "application/json")
			// Encode the response struct as JSON.
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				// Log any encoding error.
				log.Printf("%+v", err)
			}
			// Return because we fully handled the request.
			return
		}

		// For all other paths under /api/users/, treat the remainder as the UID.
		uid := rest

		// Branch on HTTP method for /api/users/{uid}.
		switch r.Method {

		case http.MethodDelete:
			// Handle deleting a user.

			// Attempt to delete the user from config by UID.
			if err := cfg.DeleteUser(uid); err != nil {
				// Log the error.
				log.Printf("%+v", err)
				// Map the error to an HTTP status and send it.
				http.Error(w, err.Error(), httpStatusFromErr(err))
				return
			}

			// Reload the directory from JSON to reflect the deletion.
			if d, err := json_config.LoadDirectoryFromJSON(cfg.Path); err != nil {
				log.Printf("%+v", err)
			} else {
				store.Set(d)
			}

			// Indicate successful deletion with 204 No Content.
			w.WriteHeader(http.StatusNoContent)

		case http.MethodGet:
			// Handle fetching a single user by UID.

			// Retrieve the user from the config.
			u, ok := cfg.GetUser(uid)
			if !ok {
				// If not found, return 404.
				log.Printf("user not found")
				http.Error(w, "user not found", http.StatusNotFound)
				return
			}

			// Scrub the password before returning the user over the API.
			safeUser := scrubUserPassword(u)

			// Set response type to JSON.
			w.Header().Set("Content-Type", "application/json")
			// Encode the user as JSON.
			err := json.NewEncoder(w).Encode(safeUser)
			if err != nil {
				// Log encoding errors.
				log.Printf("%+v", err)
			}

		default:
			// For any unsupported method on /api/users/{uid}, return 405.
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// apiGroupsHandler returns a handler for /api/groups (list groups, create groups).
func apiGroupsHandler(store *directory.DirStore, cfg *json_config.ConfigStore) http.HandlerFunc {
	// Return the handler function.
	return func(w http.ResponseWriter, r *http.Request) {
		// Enforce LDAP Basic Auth; abort if authentication fails.
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			return
		}

		// Switch on HTTP method (POST for create, GET for list).
		switch r.Method {

		case http.MethodPost:
			// Handle creating a group with POST /api/groups.

			// Declare a variable to hold the decoded group.
			var g models.JldapGroup

			// Decode JSON body into the group struct.
			if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
				// Log JSON decoding error.
				log.Printf("bad json: %+v", err)
				// Return HTTP 400 Bad Request.
				http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Add the group to the config store.
			if err := cfg.AddGroup(g); err != nil {
				// Log error when adding group fails.
				log.Printf("%+v", err)
				// Map the error to an HTTP status code.
				http.Error(w, err.Error(), httpStatusFromErr(err))
				return
			}

			// Reload the directory from JSON to include the new group.
			if d, err := json_config.LoadDirectoryFromJSON(cfg.Path); err != nil {
				log.Printf("%+v", err)
			} else {
				store.Set(d)
			}

			// Return 201 Created since group has been created.
			w.WriteHeader(http.StatusCreated)

		case http.MethodGet:
			// Handle listing all groups via GET /api/groups.

			// Get list of all groups from config.
			list := cfg.ListGroups()
			// Set the response content type to JSON.
			w.Header().Set("Content-Type", "application/json")
			// Encode and send the list as JSON.
			err := json.NewEncoder(w).Encode(list)
			if err != nil {
				// Log any encoding errors.
				log.Printf("%+v", err)
			}

		default:
			// For unsupported methods, return 405 Method Not Allowed.
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// apiGroupsWithPathHandler handles /api/groups/{cn} and /api/groups/{cn}/members.
func apiGroupsWithPathHandler(store *directory.DirStore, cfg *json_config.ConfigStore) http.HandlerFunc {
	// Return the handler function.
	return func(w http.ResponseWriter, r *http.Request) {
		// Enforce LDAP Basic Auth; abort if authentication fails.
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			return
		}

		// Remove the "/api/groups/" prefix from the request path.
		rest := strings.TrimPrefix(r.URL.Path, "/api/groups/")
		// Trim leading and trailing slashes from the remaining path.
		rest = strings.Trim(rest, "/")

		// If nothing is left, then CN is missing; return an error.
		if rest == "" {
			log.Printf("cn required")
			http.Error(w, "cn required", http.StatusBadRequest)
			return
		}

		// Check for group members subresource: /api/groups/{cn}/members.
		if strings.HasSuffix(rest, "/members") {
			// Only GET is allowed for this endpoint.
			if r.Method != http.MethodGet {
				log.Printf("method not allowed")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			// Extract the CN by stripping the "/members" suffix.
			cn := strings.TrimSuffix(rest, "/members")
			// Trim any leftover slashes around CN.
			cn = strings.Trim(cn, "/")

			// If CN is empty after trimming, return error.
			if cn == "" {
				log.Printf("cn required")
				http.Error(w, "cn required", http.StatusBadRequest)
				return
			}

			// Fetch group by CN from config.
			g, ok := cfg.GetGroup(cn)
			if !ok {
				// Group not found; return 404.
				log.Printf("group not found")
				http.Error(w, "group not found", http.StatusNotFound)
				return
			}

			// List all users from config to resolve group members.
			users := cfg.ListUsers()

			// Create a map from lowercased UID to user struct for quick lookup.
			userByUID := make(map[string]models.JldapUser, len(users))
			for _, u := range users {
				// Use lowercase UID as the key for case-insensitive lookup.
				userByUID[strings.ToLower(u.UID)] = u
			}

			// Slice to accumulate resolved member user objects.
			var members []models.JldapUser
			// Map to keep track of already added UIDs (avoid duplicates).
			seen := map[string]bool{}

			// First, resolve members listed in g.MemberUID (plain UID list).
			for _, uid := range g.MemberUID {
				// Look up the user by lowercased UID.
				u, ok := userByUID[strings.ToLower(uid)]
				if ok && !seen[strings.ToLower(u.UID)] {
					// Mark this UID as seen to prevent duplicate entries.
					seen[strings.ToLower(u.UID)] = true
					// Append the user to the members slice.
					members = append(members, u)
				}
			}

			// Next, resolve members listed in g.Member (likely DN strings).
			for _, dn := range g.Member {
				// Try to extract UID from DN using helper function uidFromDN.
				if uid, ok := uidFromDN(dn); ok {
					// Look up user by extracted UID.
					u, ok2 := userByUID[strings.ToLower(uid)]
					// If found and not already seen, add to members.
					if ok2 && !seen[strings.ToLower(u.UID)] {
						seen[strings.ToLower(u.UID)] = true
						members = append(members, u)
					}
				}
			}

			// Prepare response struct, bundling group + members + raw member fields.
			resp := struct {
				// The group object.
				Group models.JldapGroup `json:"group"`
				// Resolved member users.
				Members []models.JldapUser `json:"members"`
				// Original memberUid attribute.
				MemberUID []string `json:"memberUid"`
				// Original member DN attribute.
				MemberDN []string `json:"memberDn"`
				// Count of resolved members.
				MemberCount int `json:"memberCount"`
			}{
				// The group that was queried.
				Group: g,
				// Unique resolved members.
				Members: members,
				// Raw UID entries from group.
				MemberUID: g.MemberUID,
				// Raw DN entries from group.
				MemberDN: g.Member,
				// Number of unique members.
				MemberCount: len(members),
			}

			// Set response type to JSON.
			w.Header().Set("Content-Type", "application/json")
			// Encode the response as JSON and send it.
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				// Log any encoding error.
				log.Printf("%+v", err)
			}
			// Done handling this request.
			return
		}

		// If not /members, treat remaining path as CN of the group.
		cn := rest

		// Switch on method for /api/groups/{cn}.
		switch r.Method {

		case http.MethodDelete:
			// Handle deleting a group by CN.

			// Attempt to delete the group from config.
			if err := cfg.DeleteGroup(cn); err != nil {
				// Log the error.
				log.Printf("%+v", err)
				// Map the error to HTTP status and send it back.
				http.Error(w, err.Error(), httpStatusFromErr(err))
				return
			}

			// Reload the directory from JSON to reflect the deletion.
			if d, err := json_config.LoadDirectoryFromJSON(cfg.Path); err != nil {
				log.Printf("%+v", err)
			} else {
				store.Set(d)
			}

			// Respond with 204 No Content to indicate successful deletion.
			w.WriteHeader(http.StatusNoContent)

		case http.MethodGet:
			// Handle fetching a single group by CN.

			// Look up the group in config store.
			g, ok := cfg.GetGroup(cn)
			if !ok {
				// Group not found; return 404.
				log.Printf("group not found")
				http.Error(w, "group not found", http.StatusNotFound)
				return
			}

			// Set response type to JSON.
			w.Header().Set("Content-Type", "application/json")
			// Encode the group as JSON.
			err := json.NewEncoder(w).Encode(g)
			if err != nil {
				// Log encoding error.
				log.Printf("%+v", err)
			}

		default:
			// Any other method is not allowed on /api/groups/{cn}.
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// apiDebugDumpHandler returns configuration/debug info as JSON, primarily for debugging.
func apiDebugDumpHandler(store *directory.DirStore, cfg *json_config.ConfigStore) http.HandlerFunc {
	// Return the handler function.
	return func(w http.ResponseWriter, r *http.Request) {
		// Only allow GET method on this endpoint.
		if r.Method != http.MethodGet {
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Enforce LDAP Basic Auth; abort if authentication fails.
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			return
		}

		// Acquire a read lock on the config mutex to safely read cfg.Data.
		cfg.Mu.RLock()
		// Ensure the lock is released when function returns.
		defer cfg.Mu.RUnlock()

		// Define response struct holding the entire config data.
		resp := struct {
			// Full JSON config data.
			Config models.JldapData `json:"config"`
		}{
			// Copy current config snapshot.
			Config: scrubConfigPasswords(cfg.Data),
		}

		// Set response type to JSON.
		w.Header().Set("Content-Type", "application/json")
		// Encode the response as JSON and write it.
		err := json.NewEncoder(w).Encode(resp)
		if err != nil {
			// Log any encoding error.
			log.Printf("%+v", err)
		}
	}
}

// apiReloadHandler reloads the directory and configuration from disk.
func apiReloadHandler(store *directory.DirStore, cfg *json_config.ConfigStore) http.HandlerFunc {
	// Return the handler function.
	return func(w http.ResponseWriter, r *http.Request) {
		// Only allow POST method for reload.
		if r.Method != http.MethodPost {
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Enforce LDAP Basic Auth; abort if authentication fails.
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			return
		}

		// If no config store is available, we cannot reload.
		if cfg == nil {
			log.Printf("no config Store")
			http.Error(w, "no config Store", http.StatusServiceUnavailable)
			return
		}

		// Load a fresh directory object from the JSON file on disk.
		newDir, err := json_config.LoadDirectoryFromJSON(cfg.Path)
		if err != nil {
			// Log failure to reload directory.
			log.Printf("reload failed %+v", err)
			// Return 500 Internal Server Error with error details.
			http.Error(w, "reload failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Update the shared directory store with the new directory.
		store.Set(newDir)

		// Reload the config store from disk as well.
		if err := cfg.LoadFromDisk(); err != nil {
			// Log any failure to reload config.
			log.Printf("api reload: config reload failed: %+v", err)
		} else {
			// If config reload was successful, ensure default AdminUsersCN is set if missing.
			// Acquire write lock to modify cfg.Data.
			cfg.Mu.Lock()
			if strings.TrimSpace(cfg.Data.AdminUsersCN) == "" {
				// Set a default AdminUsersCN if it is empty or whitespace.
				cfg.Data.AdminUsersCN = "homelab_admins"
			}
			// Release the write lock.
			cfg.Mu.Unlock()
		}

		// Indicate successful reload with 204 No Content.
		w.WriteHeader(http.StatusNoContent)
	}
}

// scrubUserPassword returns a copy of the user with the UserPassword field cleared.
// This is used to prevent exposing passwords in JSON API responses or debug dumps.
func scrubUserPassword(u models.JldapUser) models.JldapUser {
	u.UserPassword = ""
	return u
}

// scrubUsersPasswords returns a slice of users with all UserPassword fields cleared.
// It allocates a new slice so that the original slice (and its backing array) are not modified.
func scrubUsersPasswords(in []models.JldapUser) []models.JldapUser {
	if len(in) == 0 {
		return nil
	}
	out := make([]models.JldapUser, len(in))
	for i, u := range in {
		out[i] = scrubUserPassword(u)
	}
	return out
}

// scrubConfigPasswords returns a copy of the config data with all users' passwords cleared.
// Only the Users slice is scrubbed; other fields are left as-is.
func scrubConfigPasswords(data models.JldapData) models.JldapData {
	data.Users = scrubUsersPasswords(data.Users)
	return data
}
