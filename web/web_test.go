package web

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jldap/directory"
	"jldap/json_config"
	"jldap/models"
)

// Use a private baseDN constant for these tests so we don't collide
// with any existing testBaseDN in the package.
const authBaseDN = "dc=example,dc=com"

/*
newDirStore creates a Directory with a known baseDN and returns a DirStore
pointing at it.
*/
func newDirStore(t *testing.T) *directory.DirStore {
	t.Helper()
	d := directory.NewDirectory(authBaseDN)
	var s directory.DirStore
	s.Set(d)
	return &s
}

/*
addUserEntry adds a user entry with the given DN, uid and password to the
directory in the given store.
*/
func addUserEntry(t *testing.T, store *directory.DirStore, dn, uid, password string) {
	t.Helper()
	d := store.Get()
	d.Add(&directory.Entry{
		DN: dn,
		Attrs: map[string][]string{
			"uid":          {uid},
			"userpassword": {password},
		},
		Parent: "ou=users," + d.BaseDN,
	})
	store.Set(d)
}

/*
addAdminGroup creates an admin group entry in the directory with a given CN,
and populates both member (DN-based) and memberuid (uid-based) attributes
with the supplied values.
*/
func addAdminGroup(t *testing.T, store *directory.DirStore, adminCN string, memberDNs []string, memberUIDs []string) {
	t.Helper()
	d := store.Get()
	d.Add(&directory.Entry{
		DN: "cn=" + adminCN + ",ou=groups," + d.BaseDN,
		Attrs: map[string][]string{
			"cn":        {adminCN},
			"member":    memberDNs,
			"memberuid": memberUIDs,
		},
		Parent: "ou=groups," + d.BaseDN,
	})
	store.Set(d)
}

/*
newConfigStore creates a fresh ConfigStore with a given AdminUsersCN.
Other fields are left at their zero values.
*/
func newConfigStore(adminCN string) *json_config.ConfigStore {
	return &json_config.ConfigStore{
		Data: models.JldapData{
			BaseDN:       authBaseDN,
			AdminUsersCN: adminCN,
		},
	}
}

/*
TestIsAdminDN_AdminCNEmpty verifies that isAdminDN immediately returns false
when the config's AdminUsersCN is empty or whitespace.
*/
func TestIsAdminDN_AdminCNEmpty(t *testing.T) {
	store := newDirStore(t)
	cfg := newConfigStore("   ")

	if got := isAdminDN("uid=test,ou=users,"+authBaseDN, store, cfg); got {
		t.Fatalf("expected false when AdminUsersCN is empty, got true")
	}
}

/*
TestIsAdminDN_GroupMissing verifies that isAdminDN returns false when
AdminUsersCN is configured but the corresponding group entry does not exist
in the directory.
*/
func TestIsAdminDN_GroupMissing(t *testing.T) {
	store := newDirStore(t)
	cfg := newConfigStore("admins")

	if got := isAdminDN("uid=test,ou=users,"+authBaseDN, store, cfg); got {
		t.Fatalf("expected false when admin group is missing, got true")
	}
}

/*
TestIsAdminDN_MemberDNMatch verifies that isAdminDN returns true when the
admin group lists the DN directly in its member attribute.
*/
func TestIsAdminDN_MemberDNMatch(t *testing.T) {
	store := newDirStore(t)
	cfg := newConfigStore("admins")

	userDN := "uid=alice,ou=users," + authBaseDN
	// User entry can be mostly empty; only DN matters for memberDN match.
	addUserEntry(t, store, userDN, "alice", "secret")
	addAdminGroup(t, store, "admins", []string{userDN}, nil)

	if !isAdminDN(userDN, store, cfg) {
		t.Fatalf("expected isAdminDN to return true for DN listed in member")
	}
}

/*
TestIsAdminDN_MemberUIDMatch verifies that isAdminDN returns true when the
admin group lists the user only in its memberuid attribute and the user's
entry has the corresponding uid.
*/
func TestIsAdminDN_MemberUIDMatch(t *testing.T) {
	store := newDirStore(t)
	cfg := newConfigStore("admins")

	userDN := "uid=bob,ou=users," + authBaseDN
	addUserEntry(t, store, userDN, "bob", "secret")
	// Only memberuid; member is empty.
	addAdminGroup(t, store, "admins", nil, []string{"bob"})

	if !isAdminDN(userDN, store, cfg) {
		t.Fatalf("expected isAdminDN to return true for uid listed in memberuid")
	}
}

/*
TestIsAdminDN_NotMember verifies that isAdminDN returns false when the user
is neither listed in member nor in memberuid.
*/
func TestIsAdminDN_NotMember(t *testing.T) {
	store := newDirStore(t)
	cfg := newConfigStore("admins")

	userDN := "uid=carol,ou=users," + authBaseDN
	addUserEntry(t, store, userDN, "carol", "secret")
	addAdminGroup(t, store, "admins", []string{"uid=someoneelse,ou=users," + authBaseDN}, []string{"other"})

	if isAdminDN(userDN, store, cfg) {
		t.Fatalf("expected isAdminDN to return false when user is not in admin group")
	}
}

/*
TestUidFromDN_ValidUIDFirstRDN verifies that uidFromDN extracts the uid from
a normal DN where the first RDN is uid=...
*/
func TestUidFromDN_ValidUIDFirstRDN(t *testing.T) {
	dn := "uid=alice,ou=users,dc=example,dc=com"
	uid, ok := uidFromDN(dn)
	if !ok || uid != "alice" {
		t.Fatalf("expected uid=alice,true, got %q,%v", uid, ok)
	}
}

/*
TestUidFromDN_CaseInsensitiveAndSpaces verifies that uidFromDN is robust to
case differences and surrounding spaces in the attribute name and value.
*/
func TestUidFromDN_CaseInsensitiveAndSpaces(t *testing.T) {
	dn := "  UID =  Alice  ,ou=users,dc=example,dc=com"
	uid, ok := uidFromDN(dn)
	if !ok || uid != "Alice" {
		t.Fatalf("expected uid=Alice,true, got %q,%v", uid, ok)
	}
}

/*
TestUidFromDN_NotUIDFirstRDN verifies that uidFromDN returns false when
the first RDN is not a uid attribute (e.g. cn=...).
*/
func TestUidFromDN_NotUIDFirstRDN(t *testing.T) {
	dn := "cn=bob,uid=bob,ou=users,dc=example,dc=com"
	uid, ok := uidFromDN(dn)
	if ok || uid != "" {
		t.Fatalf("expected empty, false for non-uid first RDN, got %q,%v", uid, ok)
	}
}

/*
TestUidFromDN_InvalidFormat verifies that uidFromDN returns false for
empty strings and segments that are missing an '=' sign.
*/
func TestUidFromDN_InvalidFormat(t *testing.T) {
	if uid, ok := uidFromDN(""); ok || uid != "" {
		t.Fatalf("expected empty,false for empty dn, got %q,%v", uid, ok)
	}
	if uid, ok := uidFromDN("uidalice,ou=users,dc=example,dc=com"); ok || uid != "" {
		t.Fatalf("expected empty,false for invalid RDN, got %q,%v", uid, ok)
	}
}

/*
TestGroupFormFuncs_Contains verifies the contains helper used by templates:

  - Returns true when val is present in the list.
  - Returns false when val is absent.
*/
func TestGroupFormFuncs_Contains(t *testing.T) {
	fn, ok := groupFormFuncs["contains"]
	if !ok {
		t.Fatalf("expected contains func in groupFormFuncs")
	}
	contains := fn.(func(string, []string) bool)

	if !contains("alice", []string{"bob", "alice", "carol"}) {
		t.Fatalf("expected contains to return true when value is present")
	}
	if contains("dave", []string{"bob", "alice", "carol"}) {
		t.Fatalf("expected contains to return false when value is absent")
	}
}

/*
TestHTTPStatusFromErr_Mappings verifies that httpStatusFromErr maps common
error message patterns to the expected HTTP status codes.
*/
func TestHTTPStatusFromErr_Mappings(t *testing.T) {
	// not found → 404
	if got := httpStatusFromErr(errors.New("user not found")); got != http.StatusNotFound {
		t.Fatalf("expected 404 for 'not found', got %d", got)
	}
	// already exists → 409
	if got := httpStatusFromErr(errors.New("group already exists")); got != http.StatusConflict {
		t.Fatalf("expected 409 for 'already exists', got %d", got)
	}
	// required → 400
	if got := httpStatusFromErr(errors.New("field required")); got != http.StatusBadRequest {
		t.Fatalf("expected 400 for 'required', got %d", got)
	}
	// default (anything else) → 400
	if got := httpStatusFromErr(errors.New("unexpected error")); got != http.StatusBadRequest {
		t.Fatalf("expected 400 for default case, got %d", got)
	}
}

/*
basicAuthHeader builds a Basic Authorization header value for the given
user and password.
*/
func basicAuthHeader(user, pass string) string {
	raw := user + ":" + pass
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}

/*
TestAuthenticateBasicLDAP_NoAuthHeader verifies that authenticateBasicLDAP
fails (returns "", false) when the Authorization header is missing or does
not use the Basic scheme.
*/
func TestAuthenticateBasicLDAP_NoAuthHeader(t *testing.T) {
	store := newDirStore(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if dn, ok := authenticateBasicLDAP(req, store); ok || dn != "" {
		t.Fatalf("expected auth failure when Authorization header missing, got %q,%v", dn, ok)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Bearer something")
	if dn, ok := authenticateBasicLDAP(req2, store); ok || dn != "" {
		t.Fatalf("expected auth failure for non-Basic scheme, got %q,%v", dn, ok)
	}
}

/*
TestAuthenticateBasicLDAP_BadBase64 verifies that authenticateBasicLDAP
fails when the Basic credentials cannot be base64-decoded.
*/
func TestAuthenticateBasicLDAP_BadBase64(t *testing.T) {
	store := newDirStore(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic !!!not-base64!!!")

	if dn, ok := authenticateBasicLDAP(req, store); ok || dn != "" {
		t.Fatalf("expected auth failure on bad base64, got %q,%v", dn, ok)
	}
}

/*
TestAuthenticateBasicLDAP_MalformedCreds verifies that authenticateBasicLDAP
fails when the decoded credentials are not of the form "user:password",
or when the username part is empty.
*/
func TestAuthenticateBasicLDAP_MalformedCreds(t *testing.T) {
	store := newDirStore(t)

	// No colon
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	raw1 := base64.StdEncoding.EncodeToString([]byte("nousercolon"))
	req1.Header.Set("Authorization", "Basic "+raw1)
	if dn, ok := authenticateBasicLDAP(req1, store); ok || dn != "" {
		t.Fatalf("expected failure for creds without colon, got %q,%v", dn, ok)
	}

	// Empty user
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	raw2 := base64.StdEncoding.EncodeToString([]byte(":password"))
	req2.Header.Set("Authorization", "Basic "+raw2)
	if dn, ok := authenticateBasicLDAP(req2, store); ok || dn != "" {
		t.Fatalf("expected failure for empty user, got %q,%v", dn, ok)
	}
}

/*
TestAuthenticateBasicLDAP_UnknownUser verifies that authenticateBasicLDAP
fails when the supplied username cannot be resolved to a DN either as a UID
or as a DN with an existing entry.
*/
func TestAuthenticateBasicLDAP_UnknownUser(t *testing.T) {
	store := newDirStore(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", basicAuthHeader("unknown", "pass"))

	if dn, ok := authenticateBasicLDAP(req, store); ok || dn != "" {
		t.Fatalf("expected failure for unknown user, got %q,%v", dn, ok)
	}
}

/*
TestAuthenticateBasicLDAP_WrongPassword verifies that authenticateBasicLDAP
fails when the user exists but the password does not match any userpassword
attribute value.
*/
func TestAuthenticateBasicLDAP_WrongPassword(t *testing.T) {
	store := newDirStore(t)
	userDN := "uid=alice,ou=users," + authBaseDN
	addUserEntry(t, store, userDN, "alice", "secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", basicAuthHeader("alice", "wrongpass"))

	if dn, ok := authenticateBasicLDAP(req, store); ok || dn != "" {
		t.Fatalf("expected failure for wrong password, got %q,%v", dn, ok)
	}
}

/*
TestAuthenticateBasicLDAP_SuccessWithUID verifies that authenticateBasicLDAP
succeeds when the credentials specify an existing UID and the password
matches the stored userpassword.
*/
func TestAuthenticateBasicLDAP_SuccessWithUID(t *testing.T) {
	store := newDirStore(t)
	userDN := "uid=alice,ou=users," + authBaseDN
	addUserEntry(t, store, userDN, "alice", "secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", basicAuthHeader("alice", "secret"))

	dn, ok := authenticateBasicLDAP(req, store)
	if !ok || dn != userDN {
		t.Fatalf("expected success with DN %q, got %q,%v", userDN, dn, ok)
	}
}

/*
TestAuthenticateBasicLDAP_SuccessWithDN verifies that authenticateBasicLDAP
succeeds when the username is itself a DN string that resolves to an entry,
and the password matches.
*/
func TestAuthenticateBasicLDAP_SuccessWithDN(t *testing.T) {
	store := newDirStore(t)
	userDN := "uid=bob,ou=users," + authBaseDN
	addUserEntry(t, store, userDN, "bob", "secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", basicAuthHeader(userDN, "secret"))

	dn, ok := authenticateBasicLDAP(req, store)
	if !ok || dn != userDN {
		t.Fatalf("expected success with DN %q, got %q,%v", userDN, dn, ok)
	}
}

/*
TestRequireBasicAuthLDAP_AuthFailure verifies that requireBasicAuthLDAP
returns 401 and sets the WWW-Authenticate header when authentication fails.
*/
func TestRequireBasicAuthLDAP_AuthFailure(t *testing.T) {
	store := newDirStore(t)
	cfg := newConfigStore("admins")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil) // no auth header
	// Simulate HTTPS (or HTTPS-terminating proxy) so we test auth failure, not HTTPS enforcement.
	req.Header.Set("X-Forwarded-Proto", "https")

	dn, ok := requireBasicAuthLDAP(rr, req, store, cfg)
	if ok || dn != "" {
		t.Fatalf("expected requireBasicAuthLDAP to fail, got %q,%v", dn, ok)
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Fatalf(`expected WWW-Authenticate header starting with "Basic ", got %q`, got)
	}
}

/*
TestRequireBasicAuthLDAP_ForbiddenNotAdmin verifies that requireBasicAuthLDAP
returns 403 when the user authenticates successfully but is not a member
of the admin group.
*/
func TestRequireBasicAuthLDAP_ForbiddenNotAdmin(t *testing.T) {
	store := newDirStore(t)
	cfg := newConfigStore("admins")

	userDN := "uid=alice,ou=users," + authBaseDN
	addUserEntry(t, store, userDN, "alice", "secret")
	// No admin group or group not containing the user, so isAdminDN returns false.

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", basicAuthHeader("alice", "secret"))
	// Simulate HTTPS.
	req.Header.Set("X-Forwarded-Proto", "https")

	dn, ok := requireBasicAuthLDAP(rr, req, store, cfg)
	if ok || dn != "" {
		t.Fatalf("expected requireBasicAuthLDAP to fail (not admin), got %q,%v", dn, ok)
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

/*
TestRequireBasicAuthLDAP_Success verifies that requireBasicAuthLDAP returns
the user's DN and does not write an error when the user is both authenticated
and a member of the admin group.
*/
func TestRequireBasicAuthLDAP_Success(t *testing.T) {
	store := newDirStore(t)
	cfg := newConfigStore("admins")

	userDN := "uid=alice,ou=users," + authBaseDN
	addUserEntry(t, store, userDN, "alice", "secret")
	addAdminGroup(t, store, "admins", []string{userDN}, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", basicAuthHeader("alice", "secret"))
	// Simulate HTTPS.
	req.Header.Set("X-Forwarded-Proto", "https")

	dn, ok := requireBasicAuthLDAP(rr, req, store, cfg)
	if !ok || dn != userDN {
		t.Fatalf("expected success with DN %q, got %q,%v", userDN, dn, ok)
	}
	// ResponseRecorder defaults to 200 if no error is written.
	if rr.Code != http.StatusOK {
		t.Fatalf("expected default 200 status when auth succeeds, got %d", rr.Code)
	}
}

/*
TestStartHTTPAPI_MissingConfigFile verifies that StartHTTPAPI:

  - Does not panic when LoadFromDisk returns an error (missing file).
  - Defaults AdminUsersCN to "homelab_admins".
  - Does not start HTTPS serving when tlsConf is nil (goroutine exits early).
*/
func TestStartHTTPAPI_MissingConfigFile(t *testing.T) {
	// writeMinimalTemplates(t)

	// Use a non-existent config path.
	cfgPath := filepath.Join(t.TempDir(), "missing.json")
	store := newDirStore(t)

	cfg := StartHTTPAPI("127.0.0.1:0", cfgPath, store, nil)
	if cfg == nil {
		t.Fatalf("expected non-nil ConfigStore from StartHTTPAPI")
	}

	cfg.Mu.RLock()
	defer cfg.Mu.RUnlock()
	if cfg.Data.AdminUsersCN != "homelab_admins" {
		t.Fatalf("expected AdminUsersCN to default to homelab_admins, got %q", cfg.Data.AdminUsersCN)
	}
}

/*
TestStartHTTPAPI_LoadsConfigAndKeepsAdminCN verifies that StartHTTPAPI:

  - Loads AdminUsersCN from an existing JSON config file.
  - Does not overwrite a non-empty AdminUsersCN with the default.
*/
func TestStartHTTPAPI_LoadsConfigAndKeepsAdminCN(t *testing.T) {
	// writeMinimalTemplates(t)

	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.json")

	// Minimal JSON matching models.JldapData fields we care about.
	json := `{"BaseDN":"` + authBaseDN + `","AdminUsersCN":"custom_admins"}`
	if err := os.WriteFile(cfgPath, []byte(json), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", cfgPath, err)
	}

	store := newDirStore(t)

	cfg := StartHTTPAPI("127.0.0.1:0", cfgPath, store, nil)
	if cfg == nil {
		t.Fatalf("expected non-nil ConfigStore from StartHTTPAPI")
	}

	cfg.Mu.RLock()
	defer cfg.Mu.RUnlock()
	if cfg.Data.AdminUsersCN != "custom_admins" {
		t.Fatalf("expected AdminUsersCN to remain 'custom_admins', got %q", cfg.Data.AdminUsersCN)
	}
}

/*
TestStartHTTPAPI_WithTLSConfig verifies that passing a non-nil TLS config
does not cause StartHTTPAPI to panic. It exercises the goroutine branch
that checks tlsConf != nil, although the actual HTTPS server runs in the
background and is not interacted with by the test.
*/
func TestStartHTTPAPI_WithTLSConfig(t *testing.T) {
	// writeMinimalTemplates(t)

	store := newDirStore(t)
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"BaseDN":"`+authBaseDN+`"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", cfgPath, err)
	}

	tlsConf := &tls.Config{InsecureSkipVerify: true}
	_ = StartHTTPAPI("127.0.0.1:0", cfgPath, store, tlsConf)
	// We don't assert anything further here; if StartHTTPAPI panics or
	// crashes the process, the test will fail.
}

/*
TestUIFuncs_uidFromDN_InTemplate verifies that the uidFromDN helper function
wired into StartHTTPAPI's templates behaves correctly when used from a
template, using the same FuncMap approach.
*/
func TestUIFuncs_uidFromDN_InTemplate(t *testing.T) {
	funcs := template.FuncMap{
		"uidFromDN": func(dn string) string {
			if u, ok := uidFromDN(dn); ok {
				return u
			}
			return ""
		},
	}
	tmpl, err := template.New("test").Funcs(funcs).Parse(`{{uidFromDN .}}`)
	if err != nil {
		t.Fatalf("template parse: %v", err)
	}

	var b strings.Builder
	if err := tmpl.Execute(&b, "uid=alice,ou=users,dc=example,dc=com"); err != nil {
		t.Fatalf("template execute: %v", err)
	}
	if got := strings.TrimSpace(b.String()); got != "alice" {
		t.Fatalf("expected template to render 'alice', got %q", got)
	}
}

/*
TestIsSafeUIOrigin verifies that isSafeUIOrigin correctly allows same-origin
requests, rejects cross-origin requests, and falls back to Referer when
Origin is absent. It also treats requests with no Origin/Referer as
non-browser clients and allows them.
*/
func TestIsSafeUIOrigin(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		origin  string
		referer string
		want    bool
	}{
		{
			name:   "no Origin or Referer headers allowed",
			target: "https://ui.example.test/ui/users/save",
			// origin and referer empty
			want: true,
		},
		{
			name:    "same-origin Origin allowed",
			target:  "https://ui.example.test/ui/users/save",
			origin:  "https://ui.example.test",
			referer: "",
			want:    true,
		},
		{
			name:    "cross-origin Origin rejected",
			target:  "https://ui.example.test/ui/users/save",
			origin:  "https://evil.example.test",
			referer: "",
			want:    false,
		},
		{
			name:    "same-origin Referer allowed when no Origin",
			target:  "https://ui.example.test/ui/users/save",
			origin:  "",
			referer: "https://ui.example.test/some/page",
			want:    true,
		},
		{
			name:    "cross-origin Referer rejected when no Origin",
			target:  "https://ui.example.test/ui/users/save",
			origin:  "",
			referer: "https://evil.example.test/anything",
			want:    false,
		},
		{
			name:    "malformed Origin rejected",
			target:  "https://ui.example.test/ui/users/save",
			origin:  ":// not a url ////",
			referer: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, tt.target, nil)

			// Set headers only if non-empty to reflect realistic requests.
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}

			got := isSafeUIOrigin(req)
			if got != tt.want {
				t.Fatalf("isSafeUIOrigin(%q, Origin=%q, Referer=%q) = %v, want %v",
					tt.target, tt.origin, tt.referer, got, tt.want)
			}
		})
	}
}

// --- isHTTPSRequest / setSecurityHeaders tests ---

/*
TestIsHTTPSRequest_DirectTLS verifies that isHTTPSRequest returns true when
the request has a non-nil TLS field (direct HTTPS termination).
*/
func TestIsHTTPSRequest_DirectTLS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	// Simulate HTTPS by setting a non-nil TLS connection state.
	req.TLS = &tls.ConnectionState{}

	if !isHTTPSRequest(req) {
		t.Fatalf("expected isHTTPSRequest to return true for TLS-enabled request")
	}
}

/*
TestIsHTTPSRequest_XForwardedProto verifies that isHTTPSRequest returns true
when the request comes over HTTP but carries X-Forwarded-Proto: https, as is
common behind TLS-terminating reverse proxies.
*/
func TestIsHTTPSRequest_XForwardedProto(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	if !isHTTPSRequest(req) {
		t.Fatalf("expected isHTTPSRequest to return true when X-Forwarded-Proto=https")
	}
}

/*
TestIsHTTPSRequest_XForwardedScheme verifies that isHTTPSRequest also
understands X-Forwarded-Scheme: https.
*/
func TestIsHTTPSRequest_XForwardedScheme(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-Forwarded-Scheme", "https")

	if !isHTTPSRequest(req) {
		t.Fatalf("expected isHTTPSRequest to return true when X-Forwarded-Scheme=https")
	}
}

/*
TestIsHTTPSRequest_NonHTTPS verifies that isHTTPSRequest returns false when
there is no TLS and no forwarded HTTPS headers.
*/
func TestIsHTTPSRequest_NonHTTPS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	// Explicitly set non-HTTPS forwarded proto to make sure it doesn't mis-detect.
	req.Header.Set("X-Forwarded-Proto", "http")

	if isHTTPSRequest(req) {
		t.Fatalf("expected isHTTPSRequest to return false for plain HTTP request")
	}
}

/*
TestSetSecurityHeaders_HTTPS verifies that setSecurityHeaders sets
clickjacking and CSP headers on every response, and also sets HSTS when the
request is considered HTTPS.
*/
func TestSetSecurityHeaders_HTTPS(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	// Simulate HTTPS (either direct or via proxy; here, direct TLS).
	req.TLS = &tls.ConnectionState{}

	setSecurityHeaders(rr, req)

	h := rr.Header()

	if got := h.Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("expected X-Frame-Options=DENY, got %q", got)
	}

	const wantCSP = "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
	if got := h.Get("Content-Security-Policy"); got != wantCSP {
		t.Fatalf("unexpected Content-Security-Policy header:\n got: %q\nwant: %q", got, wantCSP)
	}

	const wantHSTS = "max-age=86400; includeSubDomains"
	if got := h.Get("Strict-Transport-Security"); got != wantHSTS {
		t.Fatalf("expected Strict-Transport-Security=%q, got %q", wantHSTS, got)
	}
}

/*
TestSetSecurityHeaders_HTTP verifies that setSecurityHeaders always sets
clickjacking and CSP headers, but does NOT set HSTS on non-HTTPS requests.
*/
func TestSetSecurityHeaders_HTTP(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)

	setSecurityHeaders(rr, req)

	h := rr.Header()

	if got := h.Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("expected X-Frame-Options=DENY, got %q", got)
	}

	const wantCSP = "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
	if got := h.Get("Content-Security-Policy"); got != wantCSP {
		t.Fatalf("unexpected Content-Security-Policy header:\n got: %q\nwant: %q", got, wantCSP)
	}

	if got := h.Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("expected no Strict-Transport-Security header for HTTP request, got %q", got)
	}
}
