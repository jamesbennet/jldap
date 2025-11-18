package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"jldap/directory"
	"jldap/json_config"
	"jldap/models"
)

const (
	csrfCookieName = "XSRF-TOKEN"
	csrfFormField  = "csrf_token"
	csrfTokenBytes = 32 // 256 bits
)

/*
uiViewModel struct holds all the data for the main UI page.
*/
type uiViewModel struct {
	// Now – current time when the page was rendered.
	Now time.Time
	// BaseDN – the LDAP base DN (e.g. dc=example,dc=com).
	BaseDN string
	// AdminCN – CN of the admin group, from config.
	AdminCN string
	// AuthedDN – DN of the currently authenticated user (from Basic Auth).
	AuthedDN string
	// Users – list of users (for display).
	Users []models.JldapUser
	// Groups – list of groups  (for display).
	Groups []models.JldapGroup
	// GIDToCN – map from gidNumber to cn (for quickly resolving primary groups).
	GIDToCN map[string]string
	// Query – the search/filter query from the UI.
	Query string
	// IsAdmin – map of username → true if user is an admin.
	IsAdmin map[string]bool
	// UserMemberOf – map of uid → slice of group DNs they belong to.
	UserMemberOf map[string][]string
	// ConfigPath – path to the JSON config file on disk.
	ConfigPath string
	// LastReload – when the config/directory was last reloaded.
	LastReload time.Time
	// LastFileMTime – file’s last modification time.
	LastFileMTime time.Time
	// CsrfToken – token value to embed in forms on the main page (if any).
	CsrfToken string
}

/*
uiUserFormVM struct is the view model for the user create/edit form.
*/
type uiUserFormVM struct {
	// IsNew – true for “new user” form, false for edit form
	IsNew bool
	// U – the user being edited (or empty user for new).
	U models.JldapUser
	// Groups – all groups (to show selectable options).
	Groups []models.JldapGroup
	// MemberOf – which groups this user is in (for the edit case).
	MemberOf []string
	// IsAdmin – whether the user is in the admin group.
	IsAdmin bool
	// BaseDN – directory base DN (for building DNs in templates).
	BaseDN string
	// CsrfToken – token value to embed in the user form.
	CsrfToken string
}

/*
uiGroupFormVM struct is the view model for group create/edit form.
*/
type uiGroupFormVM struct {
	// IsNew – true for new group.
	IsNew bool
	// G – the group being edited.
	G models.JldapGroup
	// Users – all users (for picking members).
	Users []models.JldapUser
	// BaseDN – directory base DN.
	BaseDN string
	// MemberUidJoined – MemberUID slice joined into a textarea-friendly string.
	MemberUidJoined string
	// MemberJoined – Member (DNs) joined likewise.
	MemberJoined string
	// CsrfToken – token value to embed in the group form.
	CsrfToken string
}

/*
splitList helper function. Take users input from a textarea (where they might separate items by newlines and/or commas) and turn it into a clean []string.
*/
func splitList(s string) []string {
	// Normalize line endings
	// Replace Windows \r\n with \n.
	s = strings.ReplaceAll(s, "\r\n", "\n")
	// Replace lone \r with \n.
	s = strings.ReplaceAll(s, "\r", "\n")
	// Initialize out as an empty slice of strings.
	var out []string
	// Split by newline into segs.
	for _, seg := range strings.Split(s, "\n") {
		// For each seg, also split by comma (so both \n and , act as separators).
		for _, p := range strings.Split(seg, ",") {
			// Trim whitespace from each piece p.
			p = strings.TrimSpace(p)
			if p != "" {
				// If p isn’t empty, append to out.
				out = append(out, p)
			}
		}
	}
	// Return the resulting slice.
	return out
}

// joinList is the reverse of splitList (without commas): takes a slice and joins items with newline characters – handy to pre-fill textareas.
func joinList(xs []string) string {
	return strings.Join(xs, "\n")
}

// dedup removes duplicates and empties. Used when merging existing members with newly selected ones.
func dedup(ss []string) []string {
	// seen map tracks which strings are already in the output.
	seen := make(map[string]bool, len(ss))
	// out will hold unique, non-empty values.
	out := make([]string, 0, len(ss))
	// Iterate over input slice
	for _, s := range ss {
		// Skip empty strings.
		if s == "" {
			continue
		}
		if !seen[s] {
			seen[s] = true
			// If s not in seen, mark it and append to out.
			out = append(out, s)
		}
	}
	return out
}

/*
*
uiHandlerFunc is the Main UI handler. This function builds an http.HandlerFunc closure bound to the directory store, config store, and UI template. The returned function will handle requests to the main UI page.
*/
func uiHandlerFunc(store *directory.DirStore, cfg *json_config.ConfigStore, uiTmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Calls requireBasicAuthLDAP to enforce HTTP Basic Auth against LDAP. dn is the authenticated user’s DN.
		dn, ok := requireBasicAuthLDAP(w, r, store, cfg)
		if !ok {
			// If authentication fails, it already wrote the response and returns false, so we exit early.
			return
		}
		// Reads the q query parameter (search term) from URL, and trims whitespace.
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		// Reads the admin group CN from config. Uses an RW mutex RLock/RUnlock around cfg.Data for thread-safe access.
		cfg.Mu.RLock()
		adminCN := cfg.Data.AdminUsersCN
		cfg.Mu.RUnlock()
		// gets the current in-memory directory snapshot.
		d := store.Get()
		// users – slice of all users from config.
		users := cfg.ListUsers()
		// groups – slice of all groups from config.
		groups := cfg.ListGroups()
		// Builds gidMap mapping gidNumber → cn for groups that have a non-empty gidNumber. Helps resolve a user’s primary GID to a group name in templates.
		gidMap := map[string]string{}
		for _, g := range groups {
			if strings.TrimSpace(g.GIDNumber) != "" {
				gidMap[g.GIDNumber] = g.CN
			}
		}
		// isAdmin – will store whether each uid is admin.
		isAdmin := map[string]bool{}
		// userMemberOf – will store group DNs for each uid.
		userMemberOf := map[string][]string{}
		// Constructs the DN of the admin group.
		adminGroupDN := "cn=" + adminCN + ",ou=groups," + d.BaseDN
		// Looks up that group entry in the directory.
		adminGroup := d.Get(adminGroupDN)
		// If the admin group exists:
		if adminGroup != nil {
			// Iterate memberuid attribute: a list of user IDs – mark each as admin (case-insensitive).
			for _, mu := range adminGroup.Attrs["memberuid"] {
				isAdmin[strings.ToLower(mu)] = true
			}
			// Iterate member attribute: a list of full DNs – uses uidFromDN helper to extract uid from DN; if extraction works, mark that uid as admin as well.
			for _, m := range adminGroup.Attrs["member"] {
				if uid, ok := uidFromDN(m); ok {
					isAdmin[strings.ToLower(uid)] = true
				}
			}
		}
		// For each user, build the user’s DN, and ask the directory what groups that DN is a member of (MemberOf). If there are any, store them under userMemberOf[uid].
		for _, u := range users {
			userDN := "uid=" + u.UID + ",ou=users," + d.BaseDN
			mo := d.MemberOf(userDN)
			if len(mo) > 0 {
				userMemberOf[u.UID] = mo
			}
		}
		// If there’s a search query
		if q != "" {
			// Lowercase the query (lq).
			lq := strings.ToLower(q)
			// Reuse the backing array of users by slicing users[:0] to get an empty slice with same capacity.
			uFiltered := users[:0]
			// For each user, if the query is contained in the lowercased UID, CN, or mail, we keep that user.
			for _, u := range users {
				if strings.Contains(strings.ToLower(u.UID), lq) ||
					strings.Contains(strings.ToLower(u.CN), lq) ||
					strings.Contains(strings.ToLower(u.Mail), lq) {
					uFiltered = append(uFiltered, u)
				}
			}
			// Replace users with uFiltered (the filtered version).
			users = uFiltered
			// Similarly filters groups by CN containing the query.
			gFiltered := groups[:0]
			for _, g := range groups {
				if strings.Contains(strings.ToLower(g.CN), lq) {
					gFiltered = append(gFiltered, g)
				}
			}
			groups = gFiltered
		}
		// Calls Info() on config to get: configPath – file path, lastReload – when config was last reloaded, lastMtime – last modification time of the JSON file.
		configPath, lastReload, lastMtime := cfg.Info()
		// Constructs the view model with all the computed information.
		token := ensureCSRFCookie(w, r)
		vm := uiViewModel{
			Now:           time.Now(),
			BaseDN:        d.BaseDN,
			AdminCN:       adminCN,
			AuthedDN:      dn,
			Users:         users,
			Groups:        groups,
			GIDToCN:       gidMap,
			Query:         q,
			IsAdmin:       isAdmin,
			UserMemberOf:  userMemberOf,
			ConfigPath:    configPath,
			LastReload:    lastReload,
			LastFileMTime: lastMtime,
			CsrfToken:     token,
		}
		// Sets the content type to HTML.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Executes the main UI template with vm, writing directly to w.
		if err := uiTmpl.Execute(w, vm); err != nil {
			// If template execution fails, logs error and returns 500.
			log.Printf("template errror: %+v", err)
			http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

/*
rootHandler takes an “inner” UI handler function and wraps it in a handler suitable for the root (/) path.
Only responds to exact /. Any other path yields 404.
Only allows GET; all other methods get 405.
Delegates to the provided uiHandler if checks pass.
*/
func rootHandler(uiHandler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		uiHandler(w, r)
	}
}

/*
uiPathHandler wrapper does not check the path, only enforces GET method. Useful for routes like /ui or others pointing to the same UI logic.
*/
func uiPathHandler(uiHandler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		uiHandler(w, r)
	}
}

/*
uiUsersNewHandler is the user form handler.
*/
func uiUsersNewHandler(store *directory.DirStore, cfg *json_config.ConfigStore, userFormTmpl *template.Template) http.HandlerFunc {
	// Returns a handler for the “new user” form.
	return func(w http.ResponseWriter, r *http.Request) {
		// Only GET allowed.
		if r.Method != http.MethodGet {
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Require authenticated LDAP user. Ignore the DN (we just need auth).
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			return
		}
		// Get directory snapshot.
		d := store.Get()
		// Build uiUserFormVM:
		token := ensureCSRFCookie(w, r)
		vm := uiUserFormVM{
			// IsNew set to true.
			IsNew: true,
			// Empty JldapUser (this is a blank form).
			U: models.JldapUser{},
			// Groups populated for selection.
			Groups: cfg.ListGroups(),
			// MemberOf and IsAdmin left blank/false.
			MemberOf: nil,
			IsAdmin:  false,
			// BaseDN from directory.
			BaseDN:    d.BaseDN,
			CsrfToken: token,
		}
		// Render the user form template with VM; log any error.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		err := userFormTmpl.Execute(w, vm)
		if err != nil {
			log.Printf("%+v", err)
		}
	}
}

/*
uiUsersEditHandler - Handler for editing an existing user
*/
func uiUsersEditHandler(store *directory.DirStore, cfg *json_config.ConfigStore, userFormTmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// GET only.
		if r.Method != http.MethodGet {
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Requires auth.
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			return
		}
		// Get uid from query string. If missing/empty, log and return 400.
		uid := strings.TrimSpace(r.URL.Query().Get("uid"))
		if uid == "" {
			log.Printf("missing uid")
			http.Error(w, "missing uid", http.StatusBadRequest)
			return
		}
		// Look up user in config/snapshot. If not found, 404.
		u, ok := cfg.GetUser(uid)
		if !ok {
			log.Printf("user not found")
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		// Build DN for the user based on UID and BaseDN.
		// Ask directory for groups they’re member of.
		d := store.Get()
		userDN := "uid=" + u.UID + ",ou=users," + d.BaseDN
		memberOf := d.MemberOf(userDN)
		// Fetch admin group CN (thread-safe).
		cfg.Mu.RLock()
		adminCN := cfg.Data.AdminUsersCN
		cfg.Mu.RUnlock()
		// Build admin group DN.
		adminGroupDN := "cn=" + adminCN + ",ou=groups," + d.BaseDN
		isAdmin := false
		// See if any of the user’s memberOf DNs matches it (case-insensitive); if so, isAdmin = true.
		for _, gdn := range memberOf {
			if strings.EqualFold(gdn, adminGroupDN) {
				isAdmin = true
				break
			}
		}
		// Build VM for edit screen.
		token := ensureCSRFCookie(w, r)
		vm := uiUserFormVM{
			IsNew:     false,
			U:         u,
			Groups:    cfg.ListGroups(),
			MemberOf:  memberOf,
			IsAdmin:   isAdmin,
			BaseDN:    d.BaseDN,
			CsrfToken: token,
		}
		// Render form; log errors.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		err := userFormTmpl.Execute(w, vm)
		if err != nil {
			log.Printf("%+v", err)
		}
	}
}

/*
uiUsersSaveHandler - Handler for POSTing user create/update form.
*/
func uiUsersSaveHandler(store *directory.DirStore, cfg *json_config.ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// POST only.
		if r.Method != http.MethodPost {
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Require auth.
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			return
		}
		// Same-origin check for UI POSTs.
		if !isSafeUIOrigin(r) {
			log.Printf("forbidden origin for uiUsersSaveHandler")
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		// Parse form data into r.Form/r.PostForm. If bad, 400.
		if err := r.ParseForm(); err != nil {
			log.Printf("bad form: %+v", err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if !verifyCSRFFromBrowser(w, r) {
			log.Printf("CSRF Token error")
			return
		}
		// Builds a JldapUser from the form fields, trimming whitespace to avoid stray spaces.
		u := models.JldapUser{
			UID:        strings.TrimSpace(r.Form.Get("uid")),
			CN:         strings.TrimSpace(r.Form.Get("cn")),
			SN:         strings.TrimSpace(r.Form.Get("sn")),
			GivenName:  strings.TrimSpace(r.Form.Get("givenName")),
			Mail:       strings.TrimSpace(r.Form.Get("mail")),
			UIDNumber:  strings.TrimSpace(r.Form.Get("uidNumber")),
			GIDNumber:  strings.TrimSpace(r.Form.Get("gidNumber")),
			HomeDir:    strings.TrimSpace(r.Form.Get("homeDirectory")),
			LoginShell: strings.TrimSpace(r.Form.Get("loginShell")),
		}
		// Gets password field. Only sets UserPassword if non-empty; this way, leaving it blank doesn’t overwrite existing password.
		pwd := strings.TrimSpace(r.Form.Get("password"))
		if pwd != "" {
			u.UserPassword = pwd
		}
		// Saves/updates user in configuration. If it fails, logs and responds with status translated from the error.
		if err := cfg.AddUser(u); err != nil {
			log.Printf("save user error %+v", err)
			http.Error(w, "save user: "+err.Error(), httpStatusFromErr(err))
			return
		}
		// Reloads the in-memory directory from the JSON config file (so LDAP view matches changes).
		// If load succeeds (err == nil), then store.Set(d) to replace directory, else log the error.
		if d, err := json_config.LoadDirectoryFromJSON(cfg.Path); err != nil {
			log.Printf("%+v", err)
		} else {
			store.Set(d)
		}
		// Redirects back to main UI.
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

/*
uiUsersDeleteHandler - Handler to delete a user.
*/
func uiUsersDeleteHandler(store *directory.DirStore, cfg *json_config.ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// POST only + authentication.
		if r.Method != http.MethodPost {
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			return
		}
		// Same-origin check for UI POSTs.
		if !isSafeUIOrigin(r) {
			log.Printf("forbidden origin for uiUsersDeleteHandler")
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		// Parse form.
		if err := r.ParseForm(); err != nil {
			log.Printf("bad form: %+v", err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if !verifyCSRFFromBrowser(w, r) {
			log.Printf("CSRF Token error")
			return
		}
		// Grab UID from form; if missing, 400.
		uid := strings.TrimSpace(r.Form.Get("uid"))
		if uid == "" {
			log.Printf("missing uid")
			http.Error(w, "missing uid", http.StatusBadRequest)
			return
		}
		// Ask config to delete user; on error, log & return appropriate status.
		if err := cfg.DeleteUser(uid); err != nil {
			log.Printf("delete user error: %+v", err)
			http.Error(w, "delete user: "+err.Error(), httpStatusFromErr(err))
			return
		}
		// Reload directory from JSON (same pattern).
		if d, err := json_config.LoadDirectoryFromJSON(cfg.Path); err != nil {
			log.Printf("%+v", err)
		} else {
			store.Set(d)
		}
		// Redirect back to main UI.
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

/*
uiUsersMakeAdminHandler - Handler to add a user to the admin group.
*/
func uiUsersMakeAdminHandler(store *directory.DirStore, cfg *json_config.ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// POST-only, requires auth, parses form.
		if r.Method != http.MethodPost {
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			return
		}
		// Same-origin check for UI POSTs.
		if !isSafeUIOrigin(r) {
			log.Printf("forbidden origin for uiUsersMakeAdminHandler")
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			log.Printf("bad form: %+v", err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if !verifyCSRFFromBrowser(w, r) {
			log.Printf("CSRF Token error")
			return
		}
		// Get UID from form; require it.
		uid := strings.TrimSpace(r.Form.Get("uid"))
		if uid == "" {
			log.Printf("missing uid")
			http.Error(w, "missing uid", http.StatusBadRequest)
			return
		}
		if err := cfg.AddUserToAdmin(uid); err != nil {
			log.Printf("make admin error %+v", err)
			http.Error(w, "make admin: "+err.Error(), httpStatusFromErr(err))
			return
		}
		// Adds the user to the admin group in config; error → logged and returned.
		if d, err := json_config.LoadDirectoryFromJSON(cfg.Path); err != nil {
			log.Printf("%+v", err)
		} else {
			store.Set(d)
		}
		// Reload directory and redirect.
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

/*
uiUsersRemoveAdminHandler - Handler to remove user from admin group.
*/
func uiUsersRemoveAdminHandler(store *directory.DirStore, cfg *json_config.ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Same checks as make-admin handler.
		if r.Method != http.MethodPost {
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			return
		}
		// Same-origin check for UI POSTs.
		if !isSafeUIOrigin(r) {
			log.Printf("forbidden origin for uiUsersRemoveAdminHandler")
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			log.Printf("bad form: %+v", err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if !verifyCSRFFromBrowser(w, r) {
			log.Printf("CSRF Token error")
			return
		}
		// Require UID.
		uid := strings.TrimSpace(r.Form.Get("uid"))
		if uid == "" {
			log.Printf("missing uid")
			http.Error(w, "missing uid", http.StatusBadRequest)
			return
		}
		// Remove user from admin group; error handling.
		if err := cfg.RemoveUserFromAdmin(uid); err != nil {
			log.Printf("remove admin error: %+v", err)
			http.Error(w, "remove admin: "+err.Error(), httpStatusFromErr(err))
			return
		}
		if d, err := json_config.LoadDirectoryFromJSON(cfg.Path); err != nil {
			log.Printf("%+v", err)
		} else {
			store.Set(d)
		}
		// Reload directory and redirect.
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

/*
uiGroupsNewHandler - Handler to render “new group” form.
*/
func uiGroupsNewHandler(store *directory.DirStore, cfg *json_config.ConfigStore, groupFormTmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// GET only & authenticated.
		if r.Method != http.MethodGet {
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			return
		}
		// Directory snapshot.
		d := store.Get()
		/*
			Build VM with:
				IsNew = true.
				Empty group.
				Users list and BaseDN filled.
		*/
		token := ensureCSRFCookie(w, r)
		vm := uiGroupFormVM{IsNew: true, G: models.JldapGroup{}, Users: cfg.ListUsers(), BaseDN: d.BaseDN, CsrfToken: token}
		// Render the group form.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		err := groupFormTmpl.Execute(w, vm)
		if err != nil {
			log.Printf("%+v", err)
		}
	}
}

/*
uiGroupsEditHandler - Handler for editing an existing group.
*/
func uiGroupsEditHandler(store *directory.DirStore, cfg *json_config.ConfigStore, groupFormTmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// GET only & auth.
		if r.Method != http.MethodGet {
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			return
		}
		// Get cn from query; require it.
		cn := strings.TrimSpace(r.URL.Query().Get("cn"))
		if cn == "" {
			log.Printf("missing cn")
			http.Error(w, "missing cn", http.StatusBadRequest)
			return
		}
		// Lookup group; 404 if not found.
		g, ok := cfg.GetGroup(cn)
		if !ok {
			log.Printf("group not found")
			http.Error(w, "group not found", http.StatusNotFound)
			return
		}
		// Build VM for the edit form:
		d := store.Get()
		token := ensureCSRFCookie(w, r)
		vm := uiGroupFormVM{
			// IsNew = false.
			IsNew: false,
			// G – the group.
			G: g,
			// Users – for selection.
			Users:  cfg.ListUsers(),
			BaseDN: d.BaseDN,
			// MemberUidJoined / MemberJoined – text versions for textarea form fields.
			MemberUidJoined: joinList(g.MemberUID),
			MemberJoined:    joinList(g.Member),
			CsrfToken:       token,
		}
		// Render template.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		err := groupFormTmpl.Execute(w, vm)
		if err != nil {
			log.Printf("%+v", err)
		}
	}
}

/*
uiGroupsSaveHandler - Handler to create/update a group.
*/
func uiGroupsSaveHandler(store *directory.DirStore, cfg *json_config.ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// POST only, auth, parse form.
		if r.Method != http.MethodPost {
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			return
		}
		// Same-origin check for UI POSTs.
		if !isSafeUIOrigin(r) {
			log.Printf("forbidden origin for uiGroupsSaveHandler")
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			log.Printf("bad form: %+v", err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if !verifyCSRFFromBrowser(w, r) {
			log.Printf("CSRF Token error")
			return
		}
		// Reads multi-value form fields memberUidSel and memberSel (probably checkboxes/multi-select UI for adding members by UID and by DN).
		memberUidSel := r.Form["memberUidSel"]
		memberSel := r.Form["memberSel"]
		// Build group model:
		g := models.JldapGroup{
			// CN, GIDNumber from form fields.
			CN:        strings.TrimSpace(r.Form.Get("cn")),
			GIDNumber: strings.TrimSpace(r.Form.Get("gidNumber")),
			/*
				MemberUID:
					Take textarea input memberUid, split into list (splitList).
					Append memberUidSel values from checkboxes.
					Deduplicate with dedup.
			*/
			MemberUID: dedup(append(splitList(r.Form.Get("memberUid")), memberUidSel...)),
			// Same pattern for DN-based members.
			Member: dedup(append(splitList(r.Form.Get("member")), memberSel...)),
		}
		// Save/update group in config; handle errors.
		if err := cfg.AddGroup(g); err != nil {
			log.Printf("save group error %+v", err)
			http.Error(w, "save group: "+err.Error(), httpStatusFromErr(err))
			return
		}
		// Reload directory and redirect.
		if d, err := json_config.LoadDirectoryFromJSON(cfg.Path); err != nil {
			log.Printf("%+v", err)
		} else {
			store.Set(d)
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

/*
uiGroupsDeleteHandler - Handler to delete a group.
*/
func uiGroupsDeleteHandler(store *directory.DirStore, cfg *json_config.ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// POST only, auth, parse form.
		if r.Method != http.MethodPost {
			log.Printf("method not allowed")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, ok := requireBasicAuthLDAP(w, r, store, cfg); !ok {
			return
		}
		// Same-origin check for UI POSTs.
		if !isSafeUIOrigin(r) {
			log.Printf("forbidden origin for uiGroupsDeleteHandler")
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			log.Printf("bad form error %+v", err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if !verifyCSRFFromBrowser(w, r) {
			log.Printf("CSRF Token error")
			return
		}
		// Require cn from form.
		cn := strings.TrimSpace(r.Form.Get("cn"))
		if cn == "" {
			log.Printf("missing cn")
			http.Error(w, "missing cn", http.StatusBadRequest)
			return
		}
		// Delete the group in config; handle errors.
		if err := cfg.DeleteGroup(cn); err != nil {
			log.Printf("delete group error: %+v", err)
			http.Error(w, "delete group: "+err.Error(), httpStatusFromErr(err))
			return
		}
		// Reload directory and redirect to main UI.
		if d, err := json_config.LoadDirectoryFromJSON(cfg.Path); err != nil {
			log.Printf("%+v", err)
		} else {
			store.Set(d)
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// isSafeUIOrigin enforces a simple same-origin policy for UI POSTs.
// It allows the request if:
//   - Origin is empty and Referer is empty or same-host, OR
//   - Origin is present and its host matches r.Host (case-insensitive).
//
// Any parse errors or mismatched hosts are treated as unsafe.
func isSafeUIOrigin(r *http.Request) bool {
	host := strings.ToLower(strings.TrimSpace(r.Host))
	if host == "" {
		// Be permissive if Host is somehow empty; this should not happen in normal TLS use.
		return true
	}

	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		u, err := url.Parse(origin)
		if err != nil {
			log.Printf("bad Origin header %q: %+v", origin, err)
			return false
		}
		if !strings.EqualFold(u.Host, host) {
			log.Printf("forbidden origin: Origin host %q != request host %q", u.Host, host)
			return false
		}
		return true
	}

	// Fall back to Referer if Origin is not set (older clients / some redirects).
	ref := strings.TrimSpace(r.Header.Get("Referer"))
	if ref == "" {
		// No Origin/Referer: allow. This keeps tests and non-browser clients working.
		return true
	}
	u, err := url.Parse(ref)
	if err != nil {
		log.Printf("bad Referer header %q: %+v", ref, err)
		return false
	}
	if !strings.EqualFold(u.Host, host) {
		log.Printf("forbidden origin: Referer host %q != request host %q", u.Host, host)
		return false
	}
	return true
}

// generateCSRFToken returns a new random hex string.
func generateCSRFToken() (string, error) {
	b := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ensureCSRFCookie makes sure the response has a CSRF token cookie, and returns the token value (either existing or newly generated).
func ensureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	token, err := generateCSRFToken()
	if err != nil {
		// In the unlikely event of failure, fall back to a fixed error path:
		log.Printf("csrf: failed to generate token: %+v", err)
		// No token is strictly worse than a weak one here, but we still don't want to accidentally allow any request through; just issue an empty one so UI renders but POST will fail.
		token = ""
	}

	cookie := &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true, // JS doesn't need it; browser still sends it.
		SameSite: http.SameSiteLaxMode,
		Secure:   true, // We are always on HTTPS.
	}
	http.SetCookie(w, cookie)
	return token
}

// verifyCSRFFromBrowser enforces CSRF for browser POSTs. It assumes r.ParseForm() has already been called.
func verifyCSRFFromBrowser(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	referer := r.Header.Get("Referer")

	// If neither Origin nor Referer is present, assume non-browser client (tests, curl, etc.) and skip token enforcement.
	// NOTE: I already have Origin / Referer host checks in place (isSafeUIOrigin). This function only cares about the token itself.
	if origin == "" && referer == "" {
		return true
	}

	c, err := r.Cookie(csrfCookieName)
	if err != nil || c.Value == "" {
		log.Printf("csrf: missing cookie")
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}

	token := strings.TrimSpace(r.Form.Get(csrfFormField))
	if token == "" {
		log.Printf("csrf: missing form token")
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}

	if subtle.ConstantTimeCompare([]byte(c.Value), []byte(token)) != 1 {
		log.Printf("csrf: token mismatch")
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}

	return true
}
