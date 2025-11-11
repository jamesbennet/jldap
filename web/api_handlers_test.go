package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"jldap/directory"
	"jldap/json_config"
	"jldap/models"
)

// ---------- test helpers ----------

const (
	testBaseDN     = "dc=example,dc=com"
	testAdminUID   = "admin"
	testAdminPass  = "password"
	testAdminCN    = "Admin User"
	testAdminGroup = "homelab_admins"
)

// testEnv bundles the ConfigStore and DirStore we use in tests.
type testEnv struct {
	cfg   *json_config.ConfigStore
	store *directory.DirStore
}

// newTestEnv writes a JSON config file to a temp dir, builds a ConfigStore and Directory
// from that file, and returns both wrapped in testEnv.
// The supplied data is augmented to ensure:
//   - BaseDN is non-empty
//   - AdminUsersCN is non-empty
//   - There is an admin user "admin" with password "password"
//   - There is an admin group with CN AdminUsersCN containing that admin user
func newTestEnv(t *testing.T, data models.JldapData) testEnv {
	t.Helper()

	// Ensure BaseDN
	if strings.TrimSpace(data.BaseDN) == "" {
		data.BaseDN = testBaseDN
	}

	// Ensure AdminUsersCN
	if strings.TrimSpace(data.AdminUsersCN) == "" {
		data.AdminUsersCN = testAdminGroup
	}

	// Ensure admin user exists
	foundAdmin := false
	for _, u := range data.Users {
		if strings.EqualFold(u.UID, testAdminUID) {
			foundAdmin = true
			break
		}
	}
	if !foundAdmin {
		data.Users = append(data.Users, models.JldapUser{
			CN:           testAdminCN,
			SN:           "User",
			GivenName:    "Admin",
			UID:          testAdminUID,
			Mail:         "admin@example.com",
			UserPassword: testAdminPass,
		})
	}

	// Ensure admin group exists with memberUid "admin"
	foundAdminGroup := false
	for i, g := range data.Groups {
		if strings.EqualFold(g.CN, data.AdminUsersCN) {
			foundAdminGroup = true
			hasAdmin := false
			for _, mu := range g.MemberUID {
				if strings.EqualFold(mu, testAdminUID) {
					hasAdmin = true
					break
				}
			}
			if !hasAdmin {
				data.Groups[i].MemberUID = append(data.Groups[i].MemberUID, testAdminUID)
			}
			break
		}
	}
	if !foundAdminGroup {
		data.Groups = append(data.Groups, models.JldapGroup{
			CN:        data.AdminUsersCN,
			MemberUID: []string{testAdminUID},
		})
	}

	// Write JSON config file
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	buf, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal test data: %v", err)
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("failed to write test config file: %v", err)
	}

	// Build Directory from disk
	d, err := json_config.LoadDirectoryFromJSON(path)
	if err != nil {
		t.Fatalf("LoadDirectoryFromJSON failed: %v", err)
	}

	// Build DirStore
	store := &directory.DirStore{}
	store.Set(d)

	// Build ConfigStore with same data in memory
	cfg := &json_config.ConfigStore{
		Path: path,
		Data: data,
		Mu:   sync.RWMutex{},
	}

	return testEnv{
		cfg:   cfg,
		store: store,
	}
}

// setAdminAuth sets basic auth for the admin user used in newTestEnv.
func setAdminAuth(r *http.Request) {
	r.SetBasicAuth(testAdminUID, testAdminPass)
	// Mark the request as HTTPS so requireBasicAuthLDAP does not reject it.
	r.Header.Set("X-Forwarded-Proto", "https")
}

// ---------- apiUsersHandler tests ----------

/*
TestApiUsersHandler_Post_BadJSON verifies that POST /api/users with
invalid JSON body returns HTTP 400 and includes "bad json" in the body.
*/
func TestApiUsersHandler_Post_BadJSON(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader("{bad json"))
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiUsersHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "bad json") {
		t.Fatalf("expected bad json error, got %q", rr.Body.String())
	}
}

/*
TestApiUsersHandler_Post_AddUserError verifies that when cfg.AddUser
fails (simulated by using a ConfigStore with an invalid BaseDN), the
handler does not return 201/200 but instead returns an error status.
*/
func TestApiUsersHandler_Post_AddUserError(t *testing.T) {
	// Build a normal env for directory/admin auth
	env := newTestEnv(t, models.JldapData{})

	// Now build a ConfigStore with no BaseDN to trigger AddUser error,
	// but still with AdminUsersCN set so auth works.
	cfgBad := &json_config.ConfigStore{
		Path: env.cfg.Path,
		Data: models.JldapData{
			BaseDN:       "",                        // cause AddUser to complain
			AdminUsersCN: env.cfg.Data.AdminUsersCN, // needed for isAdminDN
		},
		Mu: sync.RWMutex{},
	}

	u := models.JldapUser{UID: "bob"}
	payload, _ := json.Marshal(u)

	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(payload))
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiUsersHandler(env.store, cfgBad).ServeHTTP(rr, req)

	if rr.Code == http.StatusCreated {
		t.Fatalf("expected error status, got 201 Created")
	}
	if rr.Code == http.StatusOK {
		t.Fatalf("expected error status, got 200 OK")
	}
}

/*
TestApiUsersHandler_Post_Success verifies that a valid POST /api/users
with a new user and a valid config returns HTTP 201 Created.
*/
func TestApiUsersHandler_Post_Success(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	newUser := models.JldapUser{UID: "bob"}
	buf, _ := json.Marshal(newUser)

	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(buf))
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiUsersHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d (body=%q)", rr.Code, rr.Body.String())
	}
}

/*
TestApiUsersHandler_Get_ListUsers ensures that GET /api/users returns
200 OK, JSON content, and that at least the admin user is present in
the returned list.
*/
func TestApiUsersHandler_Get_ListUsers(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiUsersHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("expected JSON content type, got %q", ct)
	}

	var got []models.JldapUser
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("error decoding response: %v", err)
	}
	if len(got) == 0 {
		t.Fatalf("expected at least one user (admin), got 0")
	}
	foundAdmin := false
	for _, u := range got {
		if u.UID == testAdminUID {
			foundAdmin = true
			break
		}
	}
	if !foundAdmin {
		t.Fatalf("expected admin user in list, not found")
	}
	// Ensure no userPassword values are exposed via the list API.
	for _, u := range got {
		if u.UserPassword != "" {
			t.Fatalf("expected UserPassword to be redacted in list response, got %q for uid %q", u.UserPassword, u.UID)
		}
	}
}

/*
TestApiUsersHandler_MethodNotAllowed checks that using an unsupported
HTTP method (PUT) on /api/users returns 405 Method Not Allowed.
*/
func TestApiUsersHandler_MethodNotAllowed(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodPut, "/api/users", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiUsersHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

// ---------- apiUsersWithPathHandler tests ----------

/*
TestApiUsersWithPathHandler_UidRequired confirms that hitting
/api/users/ without a UID returns 400 with a "uid required" message.
*/
func TestApiUsersWithPathHandler_UidRequired(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodGet, "/api/users/", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiUsersWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "uid required") {
		t.Fatalf("expected uid required message, got %q", rr.Body.String())
	}
}

/*
TestApiUsersWithPathHandler_Groups_MethodNotAllowed verifies that
POST /api/users/{uid}/groups is rejected with status 405 because only
GET is allowed for the /groups subresource.
*/
func TestApiUsersWithPathHandler_Groups_MethodNotAllowed(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodPost, "/api/users/alice/groups", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiUsersWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

/*
TestApiUsersWithPathHandler_Groups_UserNotFound ensures that requesting
group memberships for a non-existent user returns HTTP 404.
*/
func TestApiUsersWithPathHandler_Groups_UserNotFound(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodGet, "/api/users/unknown/groups", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiUsersWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

/*
TestApiUsersWithPathHandler_Groups_Success verifies that
GET /api/users/{uid}/groups for an existing user returns 200 and
a JSON payload containing the user and their MemberOf list.
*/
func TestApiUsersWithPathHandler_Groups_Success(t *testing.T) {
	data := models.JldapData{
		Users: []models.JldapUser{
			{
				CN:           "Alice",
				SN:           "User",
				GivenName:    "Alice",
				UID:          "alice",
				Mail:         "alice@example.com",
				UserPassword: "ignored",
			},
		},
	}
	env := newTestEnv(t, data)

	req := httptest.NewRequest(http.MethodGet, "/api/users/alice/groups", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiUsersWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", rr.Code, rr.Body.String())
	}
	var resp struct {
		User     models.JldapUser `json:"user"`
		MemberOf []string         `json:"memberOf"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.User.UID != "alice" {
		t.Fatalf("expected user alice, got %q", resp.User.UID)
	}
	if resp.User.UserPassword != "" {
		t.Fatalf("expected UserPassword to be redacted in groups response, got %q", resp.User.UserPassword)
	}
}

/*
TestApiUsersWithPathHandler_Delete_Success ensures that
DELETE /api/users/{uid} for an existing user returns 204 No Content,
indicating successful deletion.
*/
func TestApiUsersWithPathHandler_Delete_Success(t *testing.T) {
	data := models.JldapData{
		Users: []models.JldapUser{
			{UID: "alice"},
		},
	}
	env := newTestEnv(t, data)

	req := httptest.NewRequest(http.MethodDelete, "/api/users/alice", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiUsersWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d (body=%q)", rr.Code, rr.Body.String())
	}
}

/*
TestApiUsersWithPathHandler_Get_UserNotFound verifies that
GET /api/users/{uid} for a missing user returns HTTP 404.
*/
func TestApiUsersWithPathHandler_Get_UserNotFound(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodGet, "/api/users/ghost", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiUsersWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

/*
TestApiUsersWithPathHandler_Get_Success ensures that
GET /api/users/{uid} for an existing user returns 200 and the correct
user JSON.
*/
func TestApiUsersWithPathHandler_Get_Success(t *testing.T) {
	data := models.JldapData{
		Users: []models.JldapUser{
			{UID: "alice", UserPassword: "secret"},
		},
	}
	env := newTestEnv(t, data)

	req := httptest.NewRequest(http.MethodGet, "/api/users/alice", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiUsersWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var got models.JldapUser
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if got.UID != "alice" {
		t.Fatalf("expected alice, got %q", got.UID)
	}
	if got.UserPassword != "" {
		t.Fatalf("expected UserPassword to be redacted in single-user response, got %q", got.UserPassword)
	}
}

/*
TestApiUsersWithPathHandler_MethodNotAllowed checks that an unsupported
method (PUT) on /api/users/{uid} returns HTTP 405.
*/
func TestApiUsersWithPathHandler_MethodNotAllowed(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodPut, "/api/users/alice", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiUsersWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

// ---------- apiGroupsHandler tests ----------

/*
TestApiGroupsHandler_Post_BadJSON verifies that POST /api/groups with
invalid JSON returns HTTP 400 Bad Request.
*/
func TestApiGroupsHandler_Post_BadJSON(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader("{bad"))
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiGroupsHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

/*
TestApiGroupsHandler_Post_Success ensures that POST /api/groups with a
valid group JSON returns HTTP 201 Created.
*/
func TestApiGroupsHandler_Post_Success(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	g := models.JldapGroup{CN: "devs"}
	buf, _ := json.Marshal(g)

	req := httptest.NewRequest(http.MethodPost, "/api/groups", bytes.NewReader(buf))
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiGroupsHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (body=%q)", rr.Code, rr.Body.String())
	}
}

/*
TestApiGroupsHandler_Get_ListGroups verifies that GET /api/groups
returns 200 and includes the configured groups.
*/
func TestApiGroupsHandler_Get_ListGroups(t *testing.T) {
	data := models.JldapData{
		Groups: []models.JldapGroup{
			{CN: "devs"},
			{CN: "ops"},
		},
	}
	env := newTestEnv(t, data)

	req := httptest.NewRequest(http.MethodGet, "/api/groups", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiGroupsHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var got []models.JldapGroup
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(got) < 2 {
		t.Fatalf("expected at least 2 groups (devs, ops), got %d", len(got))
	}
}

/*
TestApiGroupsHandler_MethodNotAllowed checks that an unsupported method
(PUT) on /api/groups returns 405 Method Not Allowed.
*/
func TestApiGroupsHandler_MethodNotAllowed(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodPut, "/api/groups", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiGroupsHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

// ---------- apiGroupsWithPathHandler tests ----------

/*
TestApiGroupsWithPathHandler_CNRequired ensures that requesting
/api/groups/ without a CN returns 400 with "cn required".
*/
func TestApiGroupsWithPathHandler_CNRequired(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodGet, "/api/groups/", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiGroupsWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

/*
TestApiGroupsWithPathHandler_Members_MethodNotAllowed verifies that
POST /api/groups/{cn}/members returns 405 because only GET is allowed
on the /members subresource.
*/
func TestApiGroupsWithPathHandler_Members_MethodNotAllowed(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodPost, "/api/groups/devs/members", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiGroupsWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

/*
TestApiGroupsWithPathHandler_Members_CNRequired documents the actual
behavior of the handler when given the path /api/groups//members.

Due to the trimming logic, "rest" becomes "members", which is treated
as a CN. The handler then calls GetGroup("members") and returns 404
"group not found", so we assert 404 here.
*/
func TestApiGroupsWithPathHandler_Members_CNRequired(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	// This particular path results in rest == "members" (a non-empty CN)
	// so it falls through to GetGroup("members") and returns 404.
	req := httptest.NewRequest(http.MethodGet, "/api/groups//members", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiGroupsWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

/*
TestApiGroupsWithPathHandler_Members_GroupNotFound verifies that
GET /api/groups/{cn}/members for a non-existing group returns 404.
*/

func TestApiGroupsWithPathHandler_Members_GroupNotFound(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodGet, "/api/groups/unknown/members", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiGroupsWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

/*
TestApiGroupsWithPathHandler_Members_Success_Dedupe ensures that
members resolved via MemberUID and Member DN entries are returned as
unique users, and that case differences are handled correctly.
It sets up a group with:
  - MemberUID ["alice", "ALICE"]
  - Member ["uid=bob,ou=users,..."]

and expects exactly 2 unique member users in the response.
*/
func TestApiGroupsWithPathHandler_Members_Success_Dedupe(t *testing.T) {
	users := []models.JldapUser{
		{UID: "alice"},
		{UID: "bob"},
	}
	group := models.JldapGroup{
		CN:        "devs",
		MemberUID: []string{"alice", "ALICE"}, // duplicates different case
		Member:    []string{"uid=bob,ou=users," + testBaseDN},
	}
	data := models.JldapData{
		Users:  users,
		Groups: []models.JldapGroup{group},
	}
	env := newTestEnv(t, data)

	req := httptest.NewRequest(http.MethodGet, "/api/groups/devs/members", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiGroupsWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Group       models.JldapGroup  `json:"group"`
		Members     []models.JldapUser `json:"members"`
		MemberUID   []string           `json:"memberUid"`
		MemberDN    []string           `json:"memberDn"`
		MemberCount int                `json:"memberCount"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Group.CN != "devs" {
		t.Fatalf("expected group devs, got %q", resp.Group.CN)
	}
	if resp.MemberCount != 2 {
		t.Fatalf("expected 2 members, got %d", resp.MemberCount)
	}
}

/*
TestApiGroupsWithPathHandler_Delete_Success verifies that
DELETE /api/groups/{cn} for an existing group returns 204 No Content,
indicating a successful deletion.
*/
func TestApiGroupsWithPathHandler_Delete_Success(t *testing.T) {
	group := models.JldapGroup{CN: "devs"}
	data := models.JldapData{
		Groups: []models.JldapGroup{group},
	}
	env := newTestEnv(t, data)

	req := httptest.NewRequest(http.MethodDelete, "/api/groups/devs", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiGroupsWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d (body=%q)", rr.Code, rr.Body.String())
	}
}

/*
TestApiGroupsWithPathHandler_Get_GroupNotFound ensures that
GET /api/groups/{cn} for a non-existent group returns HTTP 404.
*/
func TestApiGroupsWithPathHandler_Get_GroupNotFound(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodGet, "/api/groups/devs", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiGroupsWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

/*
TestApiGroupsWithPathHandler_Get_Success verifies that
GET /api/groups/{cn} for an existing group returns HTTP 200 and the
correct group JSON.
*/
func TestApiGroupsWithPathHandler_Get_Success(t *testing.T) {
	group := models.JldapGroup{CN: "devs"}
	data := models.JldapData{
		Groups: []models.JldapGroup{group},
	}
	env := newTestEnv(t, data)

	req := httptest.NewRequest(http.MethodGet, "/api/groups/devs", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiGroupsWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var got models.JldapGroup
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if got.CN != "devs" {
		t.Fatalf("expected devs, got %q", got.CN)
	}
}

/*
TestApiGroupsWithPathHandler_MethodNotAllowed checks that an unsupported
method (PUT) on /api/groups/{cn} returns 405 Method Not Allowed.
*/
func TestApiGroupsWithPathHandler_MethodNotAllowed(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodPut, "/api/groups/devs", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiGroupsWithPathHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

// ---------- apiDebugDumpHandler tests ----------

/*
TestApiDebugDumpHandler_MethodNotAllowed ensures that using an
unsupported method (POST) on /api/debug/dump returns 405.
*/
func TestApiDebugDumpHandler_MethodNotAllowed(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodPost, "/api/debug/dump", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiDebugDumpHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

/*
TestApiDebugDumpHandler_Get_Success verifies that
GET /api/debug/dump returns 200 OK and a JSON payload containing the
current config (JldapData) as stored in the ConfigStore.
*/
func TestApiDebugDumpHandler_Get_Success(t *testing.T) {
	data := models.JldapData{
		BaseDN:       testBaseDN,
		AdminUsersCN: testAdminGroup,
	}
	env := newTestEnv(t, data)

	req := httptest.NewRequest(http.MethodGet, "/api/debug/dump", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiDebugDumpHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Config models.JldapData `json:"config"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Config.BaseDN != testBaseDN {
		t.Fatalf("expected BaseDN %q, got %q", testBaseDN, resp.Config.BaseDN)
	}
	// Ensure no userPassword values are exposed in the debug dump.
	for _, u := range resp.Config.Users {
		if u.UserPassword != "" {
			t.Fatalf("expected UserPassword to be redacted in debug dump, got %q for uid %q", u.UserPassword, u.UID)
		}
	}
}

// ---------- apiReloadHandler tests ----------

/*
TestApiReloadHandler_MethodNotAllowed ensures that GET /api/reload
returns 405 because the handler only allows POST for reload.
*/
func TestApiReloadHandler_MethodNotAllowed(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	req := httptest.NewRequest(http.MethodGet, "/api/reload", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiReloadHandler(env.store, env.cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

/*
TestApiReloadHandler_LoadDirectoryError verifies that when
LoadDirectoryFromJSON fails (because cfg.Path points to a non-existent
file), the handler responds with HTTP 500 and a "reload failed" message.
*/
func TestApiReloadHandler_LoadDirectoryError(t *testing.T) {
	// normal env for directory/admin auth
	env := newTestEnv(t, models.JldapData{})

	// cfgBad points to a non-existent file so LoadDirectoryFromJSON fails.
	cfgBad := &json_config.ConfigStore{
		Path: filepath.Join(t.TempDir(), "does_not_exist.json"),
		Data: models.JldapData{
			BaseDN:       testBaseDN,
			AdminUsersCN: env.cfg.Data.AdminUsersCN,
		},
		Mu: sync.RWMutex{},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/reload", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiReloadHandler(env.store, cfgBad).ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (body=%q)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "reload failed") {
		t.Fatalf("expected reload failed message, got %q", rr.Body.String())
	}
}

/*
TestApiReloadHandler_Success verifies a full successful reload flow:

  - On-disk config has AdminUsersCN empty but an admin group present.
  - ConfigStore.Data has AdminUsersCN set so auth works.
  - POST /api/reload loads a fresh Directory, reloads ConfigStore from disk,
    and then defaults AdminUsersCN to "homelab_admins" when empty.
*/
func TestApiReloadHandler_Success(t *testing.T) {
	// We want:
	// - ConfigStore.Data.AdminUsersCN non-empty so auth works
	// - JSON file AdminUsersCN empty so LoadFromDisk will set it to "" and then the handler will default it.

	// Prepare on-disk data with empty AdminUsersCN but with admin group present.
	onDiskData := models.JldapData{
		BaseDN:       testBaseDN,
		AdminUsersCN: "", // will be defaulted inside handler after LoadFromDisk
		Users: []models.JldapUser{
			{
				CN:           testAdminCN,
				SN:           "User",
				GivenName:    "Admin",
				UID:          testAdminUID,
				Mail:         "admin@example.com",
				UserPassword: testAdminPass,
			},
		},
		Groups: []models.JldapGroup{
			{
				CN:        testAdminGroup,
				MemberUID: []string{testAdminUID},
			},
		},
	}

	// Write this config file manually.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	buf, err := json.MarshalIndent(onDiskData, "", "  ")
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write error: %v", err)
	}

	// Build Directory from disk.
	d, err := json_config.LoadDirectoryFromJSON(path)
	if err != nil {
		t.Fatalf("LoadDirectoryFromJSON failed: %v", err)
	}
	store := &directory.DirStore{}
	store.Set(d)

	// ConfigStore.Data has AdminUsersCN set so auth & isAdminDN work.
	cfg := &json_config.ConfigStore{
		Path: path,
		Data: models.JldapData{
			BaseDN:       testBaseDN,
			AdminUsersCN: testAdminGroup,
		},
		Mu: sync.RWMutex{},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/reload", nil)
	setAdminAuth(req)
	rr := httptest.NewRecorder()

	apiReloadHandler(store, cfg).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d (body=%q)", rr.Code, rr.Body.String())
	}

	// After reload, AdminUsersCN should be defaulted if blank in file.
	cfg.Mu.RLock()
	defer cfg.Mu.RUnlock()
	if strings.TrimSpace(cfg.Data.AdminUsersCN) == "" {
		t.Fatalf("expected AdminUsersCN to be defaulted, still empty")
	}
}

// ---------- httpStatusFromErr coverage ----------

/*
TestHttpStatusFromErr_KnownMapping checks that httpStatusFromErr maps
error messages containing certain substrings to the expected HTTP
status codes:

  - "not found"     -> 404
  - "already exists" -> 409
  - "required"      -> 400
  - everything else -> 400 (default)
*/
func TestHttpStatusFromErr_KnownMapping(t *testing.T) {
	if got := httpStatusFromErr(&testErr{msg: "not found"}); got != http.StatusNotFound {
		t.Fatalf("expected 404 for 'not found', got %d", got)
	}
	if got := httpStatusFromErr(&testErr{msg: "already exists"}); got != http.StatusConflict {
		t.Fatalf("expected 409 for 'already exists', got %d", got)
	}
	if got := httpStatusFromErr(&testErr{msg: "required"}); got != http.StatusBadRequest {
		t.Fatalf("expected 400 for 'required', got %d", got)
	}
	if got := httpStatusFromErr(&testErr{msg: "something else"}); got != http.StatusBadRequest {
		t.Fatalf("expected default 400, got %d", got)
	}
}

/*
testErr is a simple error type used to feed specific message strings
into httpStatusFromErr for testing its mapping behavior.
*/
type testErr struct{ msg string }

// Error implements the error interface for testErr by returning its message.
func (e *testErr) Error() string { return e.msg }
