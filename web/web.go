package web

import (
	"crypto/tls"
	"encoding/base64"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"

	"jldap/directory"
	"jldap/json_config"
)

/*
isAdminDN checks whether a given DN (distinguished name) belongs to an admin user.
*/
func isAdminDN(dn string, store *directory.DirStore, cfg *json_config.ConfigStore) bool {
	// Locks the config store for reading.
	cfg.Mu.RLock()
	// Reads AdminUsersCN – the CN (name) of the admin group.
	adminCN := cfg.Data.AdminUsersCN
	// Unlocks afterwards.
	cfg.Mu.RUnlock()
	// If the admin group CN is empty/whitespace, treat it as “no admin group configured” ⇒ no one is admin.
	if strings.TrimSpace(adminCN) == "" {
		return false
	}
	// Fetches the current in-memory *directory.Directory snapshot from the store.
	d := store.Get()
	// Builds the DN for the admin group (cn=<AdminUsersCN>,ou=groups,<BaseDN>), and looks it up in the directory.
	adminGroupDN := "cn=" + adminCN + ",ou=groups," + d.BaseDN
	g := d.Get(adminGroupDN)
	// If the group doesn’t exist, then no admin membership to check ⇒ not admin.
	if g == nil {
		return false
	}
	// First, check member attribute on the group: member is a list of full DN values  -If any member DN equals the provided dn (case-insensitive), this DN is a member of the admin group ⇒ return true.
	for _, m := range g.Attrs["member"] {
		if strings.EqualFold(m, dn) {
			return true
		}
	}
	// Try to fetch the entry for this dn from the directory. If it doesn’t exist, we can’t check UID-style membership, skip to final false.
	if e := d.Get(dn); e != nil {
		// If the entry has a uid attribute: Take the first UID, lowercase it.
		if uids, ok := e.Attrs["uid"]; ok && len(uids) > 0 {
			uid := strings.ToLower(uids[0])
			// Scan the group’s memberuid list (POSIX-style membership by username).
			for _, mu := range g.Attrs["memberuid"] {
				// If any memberuid matches that UID (case-insensitive) ⇒ user is admin ⇒ true.
				if strings.EqualFold(mu, uid) {
					return true
				}
			}
		}
	}
	// If none of the checks match, this DN is not an admin DN.
	return false
}

/*
uidFromDN Extracts a uid value from an LDAP DN if it’s in the first RDN. Returns (uid, true) if found, otherwise ("", false).
*/
func uidFromDN(dn string) (string, bool) {
	dn = strings.TrimSpace(dn)
	// Empty DN ⇒ no UID.
	if dn == "" {
		return "", false
	}
	first := dn
	// Grab the first RDN (the part before the first comma). If there’s no comma, the whole DN is considered.
	if i := strings.Index(dn, ","); i >= 0 {
		first = dn[:i]
	}
	// Split that first segment into attribute=value. If there isn’t exactly one =, it’s not a normal RDN ⇒ fail.
	parts := strings.SplitN(first, "=", 2)
	if len(parts) != 2 {
		return "", false
	}
	// If the attribute name (left side) is uid (case-insensitive), return the trimmed value and true. Otherwise it’s some other attribute (like cn) ⇒ no UID ⇒ false.
	if strings.EqualFold(strings.TrimSpace(parts[0]), "uid") {
		return strings.TrimSpace(parts[1]), true
	}
	return "", false
}

/*
groupFormFuncs - template functions for group form - a map of template function names which defines a contains function to be used in Go templates.
contains "alice" .MemberUID will return true if "alice" is in the slice. Used to pre-check checkboxes/select options for group membership.
*/
var groupFormFuncs = template.FuncMap{
	"contains": func(val string, list []string) bool {
		for _, v := range list {
			if v == val {
				return true
			}
		}
		return false
	},
}

// httpStatusFromErr Maps error messages to HTTP status codes based on substrings. Helper so handlers can do httpStatusFromErr(err) and not repeat these rules.
func httpStatusFromErr(err error) int {
	msg := strings.ToLower(err.Error())
	switch {
	// If the error text (lowercased) contains "not found" ⇒ 404.
	case strings.Contains(msg, "not found"):
		return http.StatusNotFound
	// If it contains "already exists" ⇒ 409 Conflict.
	case strings.Contains(msg, "already exists"):
		return http.StatusConflict
	// If it contains "required" or anything else ⇒ 400 Bad Request.
	case strings.Contains(msg, "required"):
		return http.StatusBadRequest
	default:
		return http.StatusBadRequest
	}
}

// isHTTPSRequest reports whether the incoming HTTP request was delivered over HTTPS.
//
// It treats a request as HTTPS if either:
//   - r.TLS is non-nil (direct HTTPS termination), or
//   - a trusted reverse proxy has set X-Forwarded-Proto or X-Forwarded-Scheme to "https".
func isHTTPSRequest(r *http.Request) bool {
	// Direct HTTPS (server terminated HTTPS itself): Go populates r.TLS for TLS connections.
	if r.TLS != nil {
		return true
	}

	// Common reverse-proxy headers:
	if proto := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
		return true
	}
	if scheme := r.Header.Get("X-Forwarded-Scheme"); strings.EqualFold(scheme, "https") {
		return true
	}

	return false
}

/*
setSecurityHeaders applies standard security headers for both the UI and API:

  - X-Frame-Options: DENY
    Protects against clickjacking by disallowing framing.

  - Content-Security-Policy:
    A default-src 'self' CSP with:

  - frame-ancestors 'none' to block embedding in iframes.

  - object-src 'none' to block plugins.

  - base-uri 'self' to constrain <base>.

  - script-src/style-src 'self' 'unsafe-inline' to keep the current
    inline JS/CSS and event handlers working with the existing templates.

  - Strict-Transport-Security:
    Sent only when the request is effectively HTTPS (either directly, or
    behind a proxy that sets X-Forwarded-Proto/X-Forwarded-Scheme). This
    instructs browsers to always use HTTPS for this origin for one day,
    including subdomains.
*/
func setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	// Clickjacking protection: disallow framing entirely.
	w.Header().Set("X-Frame-Options", "DENY")

	// CSP: reasonably strict, but compatible with current templates which use inline styles and inline JS/event handlers.
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; "+
			"frame-ancestors 'none'; "+
			"object-src 'none'; "+
			"base-uri 'self'; "+
			"script-src 'self' 'unsafe-inline'; "+
			"style-src 'self' 'unsafe-inline'")

	// HSTS: only meaningful over HTTPS; respect both direct TLS and  proxy-terminated TLS signalled via X-Forwarded-* headers.
	if isHTTPSRequest(r) {
		w.Header().Set("Strict-Transport-Security", "max-age=86400; includeSubDomains")
	}
}

/*
authenticateBasicLDAP Implements HTTP Basic Auth against our LDAP directory.
Returns (dn, true) on successful authentication, or ("", false) on failure.
*/
func authenticateBasicLDAP(r *http.Request, store *directory.DirStore) (string, bool) {
	const prefix = "Basic "
	// Reads the Authorization header. Checks it starts with Basic (the Basic auth scheme). If not present / incorrect scheme ⇒ fail.
	ah := r.Header.Get("Authorization")
	if !strings.HasPrefix(ah, prefix) {
		return "", false
	}
	// Strip Basic prefix, trim whitespace, and base64-decode the rest. On decode error, log and fail.
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ah[len(prefix):]))
	if err != nil {
		log.Printf("%+v", err)
		return "", false
	}
	// Decoded form should be "user:password". Split into username and password at the first colon.
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", false
	}
	user, pass := parts[0], parts[1]
	// Require a non-empty user; empty user ⇒ fail.
	if user == "" {
		return "", false
	}
	// Get the current directory snapshot.
	d := store.Get()
	// Declare dn which will be resolved to a full distinguished name.
	var dn string
	// If user looks like a DN (contains = and ,), treat it as a DN directly.
	if strings.Contains(user, "=") && strings.Contains(user, ",") {
		dn = user
	} else {
		// Otherwise, treat it as a login/UID: Look up d.ByUID with strings.ToLower(user) to find the DN (in lowercase). Then fetch the directory entry by that lowercased DN, and store its original DN string.
		if uDNLower, ok := d.ByUID[strings.ToLower(user)]; ok {
			if e := d.ByDN[uDNLower]; e != nil {
				dn = e.DN
			}
		}
	}
	// If neither path gives a DN, this user is unknown. So, if we couldn’t resolve any DN, fail.
	if dn == "" {
		return "", false
	}
	// Use d.Get (case-insensitive) to retrieve the entry for the DN; no entry ⇒ fail.
	e := d.Get(dn)
	if e == nil {
		return "", false
	}
	// Iterate over all userpassword values for this entry (LDAP allows multiple).
	// If any literal value equals the supplied pass, authentication succeeds: If none match, authentication fails..
	for _, v := range e.Attrs["userpassword"] {
		if v == pass {
			return dn, true
		}
	}
	return "", false
}

/*
requireBasicAuthLDAP is a wrapper to enforce Basic auth and admin status on HTTP handlers.
*/
func requireBasicAuthLDAP(w http.ResponseWriter, r *http.Request, store *directory.DirStore, cfg *json_config.ConfigStore) (string, bool) {
	// Enforce HTTPS (or trusted HTTPS-terminating proxy) for all admin/API/UI endpoints.
	if !isHTTPSRequest(r) {
		log.Printf("rejecting non-HTTPS admin/API request from %s %s%s", r.RemoteAddr, r.Method, r.URL.Path)
		http.Error(w, "HTTPS required", http.StatusForbidden)
		return "", false
	}

	// Calls authenticateBasicLDAP.
	dn, ok := authenticateBasicLDAP(r, store)
	// If it fails:
	if !ok {
		// Set WWW-Authenticate header to prompt the client/browser for credentials. Return HTTP 401 with message “authentication required”.
		w.Header().Set("WWW-Authenticate", `Basic realm="JLDAP API"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return "", false
	}
	// If the authenticated DN is not an admin (isAdminDN returns false):
	if !isAdminDN(dn, store, cfg) {
		// Respond with HTTP 403 “forbidden: not an admin user”.
		log.Printf("forbidden: not an admin user")
		http.Error(w, "forbidden: not an admin user", http.StatusForbidden)
		return "", false
	}
	// If both authentication and admin check pass, return the user’s DN and true to the handler.
	return dn, true
}

/*
StartHTTPAPI - main entry point to start our HTTPS API + UI bindings.
Parameters:

	addr – address to listen on, e.g. ":8443" or "0.0.0.0:8443".
	dataPath – path to JSON config file.
	store – shared directory store used by handlers.
	tlsConf – TLS configuration; if nil, HTTPS serving is disabled.

Returns a *ConfigStore, so the caller can access config state.
*/
func StartHTTPAPI(addr string, dataPath string, store *directory.DirStore, tlsConf *tls.Config) *json_config.ConfigStore {
	// Create a new ConfigStore pointing at dataPath.
	cfg := &json_config.ConfigStore{Path: dataPath}
	// Load config data from disk into cfg.Data. Error is ignored (but logged inside LoadFromDisk).
	err := cfg.LoadFromDisk()
	if err != nil {
		log.Printf("%+v", err)
	}
	// Acquire write lock on config.
	cfg.Mu.Lock()
	// If AdminUsersCN isn’t set in the config, default it to "homelab_admins".
	if strings.TrimSpace(cfg.Data.AdminUsersCN) == "" {
		cfg.Data.AdminUsersCN = "homelab_admins"
	}
	// Unlock
	cfg.Mu.Unlock()

	// Create a new HTTP request multiplexer (router).
	mux := http.NewServeMux()

	// Wire API endpoints to their handler functions - they are closure factories (they return http.HandlerFunc bound to store/cfg)
	// /api/users – list/create users.
	mux.HandleFunc("/api/users", apiUsersHandler(store, cfg))
	// /api/users/ – operations on specific user paths.
	mux.HandleFunc("/api/users/", apiUsersWithPathHandler(store, cfg))
	// /api/groups, /api/groups/ – analogous for groups.
	mux.HandleFunc("/api/groups", apiGroupsHandler(store, cfg))
	mux.HandleFunc("/api/groups/", apiGroupsWithPathHandler(store, cfg))
	// /api/debug/dump – some debug info dump.
	mux.HandleFunc("/api/debug/dump", apiDebugDumpHandler(store, cfg))
	// /api/reload – reload config/directory from disk.
	mux.HandleFunc("/api/reload", apiReloadHandler(store, cfg))

	// Template helper functions used in the UI HTML:
	// uidFromDN function accessible in templates, which extracts a UID from a DN safely and returns an empty string if not possible.
	uiFuncs := template.FuncMap{
		"uidFromDN": func(dn string) string {
			if u, ok := uidFromDN(dn); ok {
				return u
			}
			return ""
		},
	}

	// Create a new template named "ui.html". Attach uiFuncs so templates can use uidFromDN. Parse the embedded template file "web/templates/ui.html" from uiTemplatesFS. template.Must will panic if parsing fails (fail fast on bad templates).
	uiTmpl := template.Must(template.New("ui.html").Funcs(uiFuncs).ParseFS(uiTemplatesFS, "templates/ui.html"))
	// Template for the user form (new/edit), also loaded from the embedded FS.
	userFormTmpl := template.Must(template.New("userForm.html").ParseFS(uiTemplatesFS, "templates/userForm.html"))
	// Template for the group form, with groupFormFuncs attached so it can use the "contains" helper, also loaded from the embedded FS.
	groupFormTmpl := template.Must(template.New("groupForm.html").Funcs(groupFormFuncs).ParseFS(uiTemplatesFS, "templates/groupForm.html"))

	// Build the main UI handler closure bound to the directory store, the config store, the main UI template.
	uiHandler := uiHandlerFunc(store, cfg, uiTmpl)

	// / – uses rootHandler to ensure only GET on exact root path goes to uiHandler.
	mux.HandleFunc("/", rootHandler(uiHandler))
	// /ui – any GET on /ui goes to the same UI handler (without path check).
	mux.HandleFunc("/ui", uiPathHandler(uiHandler))
	// Bind all user-related UI routes:
	// /ui/users/new – show new user form.
	mux.HandleFunc("/ui/users/new", uiUsersNewHandler(store, cfg, userFormTmpl))
	// /ui/users/edit – show edit form.
	mux.HandleFunc("/ui/users/edit", uiUsersEditHandler(store, cfg, userFormTmpl))
	// /ui/users/save – POST for create/update.
	mux.HandleFunc("/ui/users/save", uiUsersSaveHandler(store, cfg))
	// /ui/users/delete – POST for delete.
	mux.HandleFunc("/ui/users/delete", uiUsersDeleteHandler(store, cfg))
	// /ui/users/make-admin – POST to grant admin.
	mux.HandleFunc("/ui/users/make-admin", uiUsersMakeAdminHandler(store, cfg))
	// /ui/users/remove-admin – POST to revoke admin.
	mux.HandleFunc("/ui/users/remove-admin", uiUsersRemoveAdminHandler(store, cfg))
	// Group-related UI routes:
	// /ui/groups/new – new group form.
	mux.HandleFunc("/ui/groups/new", uiGroupsNewHandler(store, cfg, groupFormTmpl))
	// /ui/groups/edit – edit group form.
	mux.HandleFunc("/ui/groups/edit", uiGroupsEditHandler(store, cfg, groupFormTmpl))
	// /ui/groups/save – create/update group.
	mux.HandleFunc("/ui/groups/save", uiGroupsSaveHandler(store, cfg))
	// /ui/groups/delete – delete group.
	mux.HandleFunc("/ui/groups/delete", uiGroupsDeleteHandler(store, cfg))

	// Create a sub-FS rooted at "static" so paths line up with /static/ URLs.
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("failed to create static sub filesystem: %v", err)
	}

	// Static assets like CSS
	mux.Handle("/static/",
		http.StripPrefix("/static/",
			http.FileServer(http.FS(staticSub)),
		),
	)

	// Wrap the mux with a handler that applies security headers to every
	// HTTP response served by the API/UI.
	secureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, r)
		mux.ServeHTTP(w, r)
	})

	// Start a goroutine for the HTTPS server so StartHTTPAPI doesn’t block.
	go func() {
		// If tlsConf is nil, Log that HTTPS API is disabled, and exit the goroutine. You still get a configured cfg and mux, but no HTTPS listener.
		if tlsConf == nil {
			log.Printf("https api disabled: no TLS config")
			return
		}
		// Listen on the given TCP address. On error, log.Fatalf will log and exit the process.
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("listen (https api): %+v", err)
		}
		// Wrap the TCP listener in a TLS listener with tlsConf. Log that the HTTPS API is now listening on that address.
		tlsLn := tls.NewListener(ln, tlsConf)
		log.Printf("HTTPS API listening on https://%s", addr)
		// Construct an http.Server with the address, the secureHandler wrapper as handler, the TLS config.
		srv := &http.Server{Addr: addr, Handler: secureHandler, TLSConfig: tlsConf}
		// Call Serve with the TLS listener, which blocks serving HTTPS requests until error.
		if err := srv.Serve(tlsLn); err != nil {
			// If it returns (e.g. because server is shut down), log that the HTTPS API stopped.
			log.Printf("https api stopped: %+v", err)
		}
	}()
	// Return the *ConfigStore so other parts of the program can inspect or manipulate config if needed.
	return cfg
}
