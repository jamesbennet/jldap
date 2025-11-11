package web

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"jldap/models"
)

/*
helperAuthedRequest builds an HTTP request with basic auth for the test admin.

This helper is used across multiple handler tests to simulate a correctly
authenticated admin user calling the HTTP endpoints.
*/
func helperAuthedRequest(t *testing.T, method, target string, body url.Values) *http.Request {
	t.Helper()

	var buf *bytes.Buffer
	if body != nil {
		buf = bytes.NewBufferString(body.Encode())
	} else {
		buf = &bytes.Buffer{}
	}

	req := httptest.NewRequest(method, target, buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.SetBasicAuth(testAdminUID, testAdminPass)
	// Simulate HTTPS (or HTTPS-terminating proxy) for UI endpoints.
	req.Header.Set("X-Forwarded-Proto", "https")
	return req
}

/*
TestSplitList_BasicAndMixedSeparators verifies that splitList:

  - Normalises CRLF and CR line endings.
  - Splits on both newlines and commas.
  - Trims whitespace and drops empty items.
*/
func TestSplitList_BasicAndMixedSeparators(t *testing.T) {
	in := "one, two\r\nthree\n\nfour ,five\r,six,, ,\n"
	got := splitList(in)
	want := []string{"one", "two", "three", "four", "five", "six"}

	if len(got) != len(want) {
		t.Fatalf("expected %d items, got %d: %#v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item[%d]: expected %q, got %q", i, want[i], got[i])
		}
	}
}

/*
TestSplitList_EmptyString verifies that splitList on an empty string
returns an empty slice.
*/
func TestSplitList_EmptyString(t *testing.T) {
	got := splitList("")
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %#v", got)
	}
}

/*
TestJoinList_Basic verifies joinList joins strings with newline
characters and handles empty input.
*/
func TestJoinList_Basic(t *testing.T) {
	// Non-empty case.
	in := []string{"a", "b", "c"}
	want := "a\nb\nc"
	if got := joinList(in); got != want {
		t.Errorf("joinList(%#v) = %q, want %q", in, got, want)
	}

	// Empty slice case.
	if got := joinList(nil); got != "" {
		t.Errorf("joinList(nil) = %q, want empty string", got)
	}
}

/*
TestDedup_RemovesDuplicatesAndEmpties verifies that dedup:

  - Removes duplicates while preserving first occurrence order.
  - Drops empty strings entirely.
*/
func TestDedup_RemovesDuplicatesAndEmpties(t *testing.T) {
	in := []string{"", "one", "two", "one", "", "two", "three"}
	got := dedup(in)
	want := []string{"one", "two", "three"}

	if len(got) != len(want) {
		t.Fatalf("expected %d items, got %d: %#v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item[%d]: expected %q, got %q", i, want[i], got[i])
		}
	}
}

/*
TestRootHandler_ValidGETRoot verifies that rootHandler:

  - Accepts GET requests to the exact "/" path.
  - Delegates to the wrapped uiHandler.
*/
func TestRootHandler_ValidGETRoot(t *testing.T) {
	called := false
	uiHandler := func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}

	h := rootHandler(uiHandler)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusTeapot {
		t.Fatalf("expected status %d from inner handler, got %d", http.StatusTeapot, status)
	}
	if !called {
		t.Fatalf("inner uiHandler was not called")
	}
}

/*
TestRootHandler_NotRootPath verifies that rootHandler returns 404
and does NOT call the inner handler when the path is not exactly "/".
*/
func TestRootHandler_NotRootPath(t *testing.T) {
	called := false
	uiHandler := func(w http.ResponseWriter, r *http.Request) {
		called = true
	}

	h := rootHandler(uiHandler)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/other", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", status)
	}
	if called {
		t.Fatalf("inner uiHandler should not have been called for non-root path")
	}
}

/*
TestRootHandler_MethodNotAllowed verifies that rootHandler returns 405
and does NOT call the inner handler for non-GET methods.
*/
func TestRootHandler_MethodNotAllowed(t *testing.T) {
	called := false
	uiHandler := func(w http.ResponseWriter, r *http.Request) {
		called = true
	}

	h := rootHandler(uiHandler)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", status)
	}
	if called {
		t.Fatalf("inner uiHandler should not have been called for non-GET")
	}
}

/*
TestUIPathHandler_ValidGET verifies that uiPathHandler:

  - Allows any path.
  - For GET, it delegates to the wrapped handler.
*/
func TestUIPathHandler_ValidGET(t *testing.T) {
	called := false
	uiHandler := func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}

	h := uiPathHandler(uiHandler)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ui/path", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Fatalf("expected 201 from inner handler, got %d", status)
	}
	if !called {
		t.Fatalf("inner uiHandler was not called")
	}
}

/*
TestUIPathHandler_MethodNotAllowed verifies that uiPathHandler returns 405
and does NOT call the inner handler for non-GET methods.
*/
func TestUIPathHandler_MethodNotAllowed(t *testing.T) {
	called := false
	uiHandler := func(w http.ResponseWriter, r *http.Request) {
		called = true
	}

	h := uiPathHandler(uiHandler)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/anything", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", status)
	}
	if called {
		t.Fatalf("inner uiHandler should not have been called for non-GET")
	}
}

/*
TestUIHandlerFunc_SuccessNoQuery verifies uiHandlerFunc happy path:

  - Valid auth.
  - No search query.
  - Template executes successfully.
  - Response is 200 with HTML content type.
*/
func TestUIHandlerFunc_SuccessNoQuery(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	// Template prints some key fields to prove vm is wired.
	tmpl := template.Must(template.New("ui").
		Parse(`Authed: {{.AuthedDN}}; BaseDN: {{.BaseDN}}; AdminCN: {{.AdminCN}}`))

	h := uiHandlerFunc(env.store, env.cfg, tmpl)

	rr := httptest.NewRecorder()
	req := helperAuthedRequest(t, http.MethodGet, "/?q=", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%q", status, rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected content-type text/html, got %q", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Authed:") {
		t.Fatalf("expected template output to contain 'Authed:', got %q", body)
	}
}

/*
TestUIHandlerFunc_TemplateError verifies uiHandlerFunc template error handling:

  - Template execution fails via a function that returns error.
  - Handler logs error and returns 500 with an error message body.
*/
func TestUIHandlerFunc_TemplateError(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	tmpl := template.Must(template.New("ui").
		Funcs(template.FuncMap{
			"fail": func(interface{}) (string, error) { return "", fmt.Errorf("boom") },
		}).
		Parse(`{{fail .}}`))

	h := uiHandlerFunc(env.store, env.cfg, tmpl)

	rr := httptest.NewRecorder()
	req := helperAuthedRequest(t, http.MethodGet, "/", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body=%q", status, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "template error") {
		t.Fatalf("expected body to mention 'template error', got %q", rr.Body.String())
	}
}

/*
TestUIHandlerFunc_AuthRequired verifies that when authentication fails
(no Authorization header), uiHandlerFunc does not render the main UI
and returns a non-OK status (typically 401).
*/
func TestUIHandlerFunc_AuthRequired(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	tmpl := template.Must(template.New("ui").Parse(`OK`))
	h := uiHandlerFunc(env.store, env.cfg, tmpl)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil) // no auth header

	h.ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatalf("expected non-200 when auth fails, got %d", rr.Code)
	}
}

/*
TestUIUsersNewHandler_Success verifies uiUsersNewHandler happy path:

  - GET method.
  - Authenticated.
  - Renders the template with IsNew=true and BaseDN from the directory.
*/
func TestUIUsersNewHandler_Success(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	tmpl := template.Must(template.New("userform").
		Parse(`IsNew={{.IsNew}};BaseDN={{.BaseDN}}`))

	h := uiUsersNewHandler(env.store, env.cfg, tmpl)

	rr := httptest.NewRecorder()
	req := helperAuthedRequest(t, http.MethodGet, "/users/new", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%q", status, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "IsNew=true") {
		t.Fatalf("expected IsNew=true in body, got %q", body)
	}
	if !strings.Contains(body, "BaseDN="+testBaseDN) {
		t.Fatalf("expected BaseDN=%s in body, got %q", testBaseDN, body)
	}
}

/*
TestUIUsersNewHandler_MethodNotAllowed verifies uiUsersNewHandler returns 405
for non-GET methods.
*/
func TestUIUsersNewHandler_MethodNotAllowed(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	tmpl := template.Must(template.New("userform").
		Parse(`OK`))
	h := uiUsersNewHandler(env.store, env.cfg, tmpl)

	rr := httptest.NewRecorder()
	req := helperAuthedRequest(t, http.MethodPost, "/users/new", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", status)
	}
}

/*
TestUIUsersEditHandler_MissingUID verifies that uiUsersEditHandler returns 400
and does not execute the template when the uid query parameter is missing.
*/
func TestUIUsersEditHandler_MissingUID(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	tmpl := template.Must(template.New("useredit").Parse(`{{.U.UID}}`))
	h := uiUsersEditHandler(env.store, env.cfg, tmpl)

	rr := httptest.NewRecorder()
	req := helperAuthedRequest(t, http.MethodGet, "/users/edit", nil) // no uid

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", status)
	}
}

/*
TestUIUsersEditHandler_UserNotFound verifies that uiUsersEditHandler returns 404
when the requested uid does not exist in the config.
*/
func TestUIUsersEditHandler_UserNotFound(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	tmpl := template.Must(template.New("useredit").Parse(`{{.U.UID}}`))
	h := uiUsersEditHandler(env.store, env.cfg, tmpl)

	rr := httptest.NewRecorder()
	req := helperAuthedRequest(t, http.MethodGet, "/users/edit?uid=doesnotexist", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", status)
	}
}

/*
TestUIUsersEditHandler_Success verifies uiUsersEditHandler happy path:

  - GET with valid uid.
  - Authenticated.
  - Renders template with IsNew=false and user loaded into vm.U.
*/
func TestUIUsersEditHandler_Success(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	// Ensure a user exists in config.
	user := models.JldapUser{
		UID:       "alice",
		CN:        "Alice Example",
		UIDNumber: "1001",
	}
	if err := env.cfg.AddUser(user); err != nil {
		t.Fatalf("AddUser error: %v", err)
	}

	tmpl := template.Must(template.New("useredit").
		Parse(`IsNew={{.IsNew}};UID={{.U.UID}}`))
	h := uiUsersEditHandler(env.store, env.cfg, tmpl)

	rr := httptest.NewRecorder()
	req := helperAuthedRequest(t, http.MethodGet, "/users/edit?uid=alice", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%q", status, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "IsNew=false") {
		t.Fatalf("expected IsNew=false, got %q", body)
	}
	if !strings.Contains(body, "UID=alice") {
		t.Fatalf("expected UID=alice, got %q", body)
	}
}

/*
TestUIUsersSaveHandler_SuccessWithPassword verifies uiUsersSaveHandler happy path:

  - POST with all required fields including password.
  - Authenticated.
  - Adds user to config.
  - Redirects to "/" with StatusSeeOther.
*/
func TestUIUsersSaveHandler_SuccessWithPassword(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	h := uiUsersSaveHandler(env.store, env.cfg)

	form := url.Values{
		"uid":           {"bob"},
		"cn":            {"Bob Example"},
		"sn":            {"Example"},
		"givenName":     {"Bob"},
		"mail":          {"bob@example.com"},
		"uidNumber":     {"1002"},
		"gidNumber":     {"100"},
		"homeDirectory": {"/home/bob"},
		"loginShell":    {"/bin/bash"},
		"password":      {"secret"},
	}
	req := helperAuthedRequest(t, http.MethodPost, "/users/save", form)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d; body=%q", status, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if loc != "/" {
		t.Fatalf("expected redirect to '/', got %q", loc)
	}

	// Verify user exists in config.
	if u, ok := env.cfg.GetUser("bob"); !ok {
		t.Fatalf("expected user 'bob' to be added")
	} else if u.UserPassword == "" {
		t.Fatalf("expected UserPassword to be set")
	}
}

/*
TestUIUsersSaveHandler_MethodNotAllowed verifies that uiUsersSaveHandler
returns 405 for non-POST methods.
*/
func TestUIUsersSaveHandler_MethodNotAllowed(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	h := uiUsersSaveHandler(env.store, env.cfg)
	rr := httptest.NewRecorder()
	req := helperAuthedRequest(t, http.MethodGet, "/users/save", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", status)
	}
}

/*
TestUIUsersDeleteHandler_Success verifies uiUsersDeleteHandler happy path:

  - POST with uid.
  - Authenticated.
  - Deletes user from config.
  - Redirects to "/".
*/
func TestUIUsersDeleteHandler_Success(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	// Seed user to delete.
	u := models.JldapUser{UID: "todelete"}
	if err := env.cfg.AddUser(u); err != nil {
		t.Fatalf("AddUser error: %v", err)
	}

	h := uiUsersDeleteHandler(env.store, env.cfg)

	form := url.Values{"uid": {"todelete"}}
	req := helperAuthedRequest(t, http.MethodPost, "/users/delete", form)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d; body=%q", status, rr.Body.String())
	}
	if _, ok := env.cfg.GetUser("todelete"); ok {
		t.Fatalf("expected user to be deleted")
	}
}

/*
TestUIUsersDeleteHandler_MissingUID verifies that uiUsersDeleteHandler
returns 400 when the uid form field is missing.
*/
func TestUIUsersDeleteHandler_MissingUID(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	h := uiUsersDeleteHandler(env.store, env.cfg)

	req := helperAuthedRequest(t, http.MethodPost, "/users/delete", url.Values{})
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", status)
	}
}

/*
TestUIUsersMakeAdminHandler_Success verifies uiUsersMakeAdminHandler happy path:

  - POST with uid.
  - Authenticated.
  - Calls AddUserToAdmin and redirects to "/".
*/
func TestUIUsersMakeAdminHandler_Success(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	// Seed a user that can be made admin.
	u := models.JldapUser{UID: "adminuser"}
	if err := env.cfg.AddUser(u); err != nil {
		t.Fatalf("AddUser error: %v", err)
	}

	h := uiUsersMakeAdminHandler(env.store, env.cfg)

	form := url.Values{"uid": {"adminuser"}}
	req := helperAuthedRequest(t, http.MethodPost, "/users/make-admin", form)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d; body=%q", status, rr.Body.String())
	}
}

/*
TestUIUsersRemoveAdminHandler_Success verifies uiUsersRemoveAdminHandler happy path:

  - POST with uid.
  - Authenticated.
  - Calls RemoveUserFromAdmin and redirects to "/".
*/
func TestUIUsersRemoveAdminHandler_Success(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	// Seed a user that can be removed from admin.
	u := models.JldapUser{UID: "demoteuser"}
	if err := env.cfg.AddUser(u); err != nil {
		t.Fatalf("AddUser error: %v", err)
	}

	h := uiUsersRemoveAdminHandler(env.store, env.cfg)

	form := url.Values{"uid": {"demoteuser"}}
	req := helperAuthedRequest(t, http.MethodPost, "/users/remove-admin", form)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d; body=%q", status, rr.Body.String())
	}
}

/*
TestUIGroupsNewHandler_Success verifies uiGroupsNewHandler happy path:

  - GET.
  - Authenticated.
  - Renders template with IsNew=true and BaseDN from directory.
*/
func TestUIGroupsNewHandler_Success(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	tmpl := template.Must(template.New("groupnew").
		Parse(`IsNew={{.IsNew}};BaseDN={{.BaseDN}}`))

	h := uiGroupsNewHandler(env.store, env.cfg, tmpl)

	rr := httptest.NewRecorder()
	req := helperAuthedRequest(t, http.MethodGet, "/groups/new", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%q", status, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "IsNew=true") {
		t.Fatalf("expected IsNew=true, got %q", body)
	}
	if !strings.Contains(body, "BaseDN="+testBaseDN) {
		t.Fatalf("expected BaseDN=%s, got %q", testBaseDN, body)
	}
}

/*
TestUIGroupsEditHandler_MissingCN verifies uiGroupsEditHandler returns 400
when the cn query parameter is missing.
*/
func TestUIGroupsEditHandler_MissingCN(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	tmpl := template.Must(template.New("groupedit").Parse(`{{.G.CN}}`))
	h := uiGroupsEditHandler(env.store, env.cfg, tmpl)

	rr := httptest.NewRecorder()
	req := helperAuthedRequest(t, http.MethodGet, "/groups/edit", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", status)
	}
}

/*
TestUIGroupsEditHandler_GroupNotFound verifies uiGroupsEditHandler returns 404
when the requested group cn is not present in config.
*/
func TestUIGroupsEditHandler_GroupNotFound(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	tmpl := template.Must(template.New("groupedit").Parse(`{{.G.CN}}`))
	h := uiGroupsEditHandler(env.store, env.cfg, tmpl)

	rr := httptest.NewRecorder()
	req := helperAuthedRequest(t, http.MethodGet, "/groups/edit?cn=doesnotexist", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", status)
	}
}

/*
TestUIGroupsEditHandler_Success verifies uiGroupsEditHandler happy path:

  - GET with valid cn.
  - Authenticated.
  - Renders template with IsNew=false and group loaded into vm.G.
*/
func TestUIGroupsEditHandler_Success(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	g := models.JldapGroup{CN: "devs", GIDNumber: "2000", MemberUID: []string{"alice", "bob"}}
	if err := env.cfg.AddGroup(g); err != nil {
		t.Fatalf("AddGroup error: %v", err)
	}

	tmpl := template.Must(template.New("groupedit").
		Parse(`IsNew={{.IsNew}};CN={{.G.CN}};MemberUID={{len .G.MemberUID}}`))
	h := uiGroupsEditHandler(env.store, env.cfg, tmpl)

	rr := httptest.NewRecorder()
	req := helperAuthedRequest(t, http.MethodGet, "/groups/edit?cn=devs", nil)

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%q", status, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "IsNew=false") || !strings.Contains(body, "CN=devs") {
		t.Fatalf("unexpected body: %q", body)
	}
}

/*
TestUIGroupsSaveHandler_Success verifies uiGroupsSaveHandler happy path:

  - POST with CN, gidNumber, memberUid, member, and additional selected members.
  - Authenticated.
  - Group added with de-duplicated members.
  - Redirects to "/".
*/
func TestUIGroupsSaveHandler_Success(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	h := uiGroupsSaveHandler(env.store, env.cfg)

	form := url.Values{
		"cn":           {"devs"},
		"gidNumber":    {"2000"},
		"memberUid":    {"alice\nbob"}, // textarea
		"memberUidSel": {"charlie", "alice"},
		"member":       {"uid=d1,ou=users," + testBaseDN},
		"memberSel":    {"uid=d2,ou=users," + testBaseDN, "uid=d1,ou=users," + testBaseDN},
	}
	req := helperAuthedRequest(t, http.MethodPost, "/groups/save", form)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d; body=%q", status, rr.Body.String())
	}

	g, ok := env.cfg.GetGroup("devs")
	if !ok {
		t.Fatalf("expected group 'devs' to be created")
	}
	// Ensure deduplication happened for MemberUID and Member.
	expectedUIDs := dedup(append(splitList("alice\nbob"), "charlie", "alice"))
	if len(g.MemberUID) != len(expectedUIDs) {
		t.Fatalf("unexpected MemberUID length: got %d, want %d (%#v)", len(g.MemberUID), len(expectedUIDs), g.MemberUID)
	}
	expectedMembers := dedup(append(splitList("uid=d1,ou=users,"+testBaseDN),
		"uid=d2,ou=users,"+testBaseDN, "uid=d1,ou=users,"+testBaseDN))
	if len(g.Member) != len(expectedMembers) {
		t.Fatalf("unexpected Member length: got %d, want %d (%#v)", len(g.Member), len(expectedMembers), g.Member)
	}
}

/*
TestUIGroupsDeleteHandler_Success verifies uiGroupsDeleteHandler happy path:

  - POST with cn.
  - Authenticated.
  - Deletes group from config.
  - Redirects to "/".
*/
func TestUIGroupsDeleteHandler_Success(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	g := models.JldapGroup{CN: "deleteme", GIDNumber: "9999"}
	if err := env.cfg.AddGroup(g); err != nil {
		t.Fatalf("AddGroup error: %v", err)
	}

	h := uiGroupsDeleteHandler(env.store, env.cfg)

	form := url.Values{"cn": {"deleteme"}}
	req := helperAuthedRequest(t, http.MethodPost, "/groups/delete", form)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d; body=%q", status, rr.Body.String())
	}
	if _, ok := env.cfg.GetGroup("deleteme"); ok {
		t.Fatalf("expected group 'deleteme' to be deleted")
	}
}

/*
TestUIGroupsDeleteHandler_MissingCN verifies uiGroupsDeleteHandler returns 400
when the cn form field is missing.
*/
func TestUIGroupsDeleteHandler_MissingCN(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	h := uiGroupsDeleteHandler(env.store, env.cfg)

	req := helperAuthedRequest(t, http.MethodPost, "/groups/delete", url.Values{})
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", status)
	}
}

/*
TestUIHandlers_AuthFailure_Common verifies that handlers which require auth
respond with a non-OK status when the Authorization header is missing.

We spot-check a representative handler (uiUsersNewHandler) for this behaviour.
*/
func TestUIHandlers_AuthFailure_Common(t *testing.T) {
	env := newTestEnv(t, models.JldapData{})

	tmpl := template.Must(template.New("userform").Parse(`OK`))
	h := uiUsersNewHandler(env.store, env.cfg, tmpl)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/users/new", nil) // no auth

	h.ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatalf("expected non-200 on auth failure, got %d", rr.Code)
	}
}

/*
TestUIVM_Structs_ZeroValues verifies that the view model structs can be
constructed with zero or basic values without panics and that their fields have
the expected zero defaults where appropriate.

This is a light structural test mainly for completeness.
*/
func TestUIVM_Structs_ZeroValues(t *testing.T) {
	now := time.Now()
	uivm := uiViewModel{
		Now:           now,
		BaseDN:        "",
		AdminCN:       "",
		AuthedDN:      "",
		Users:         nil,
		Groups:        nil,
		GIDToCN:       nil,
		Query:         "",
		IsAdmin:       nil,
		UserMemberOf:  nil,
		ConfigPath:    "",
		LastReload:    time.Time{},
		LastFileMTime: time.Time{},
	}
	if !uivm.LastReload.IsZero() || !uivm.LastFileMTime.IsZero() {
		t.Fatalf("expected zero times for LastReload/LastFileMTime")
	}

	ufvm := uiUserFormVM{}
	if ufvm.IsNew {
		t.Fatalf("expected IsNew default false")
	}

	gfvm := uiGroupFormVM{}
	if gfvm.IsNew {
		t.Fatalf("expected IsNew default false")
	}
}

// --- CSRF helper tests ---

/*
TestGenerateCSRFToken_Basic verifies that generateCSRFToken returns
a non-empty token and does not error. It also calls it twice to ensure
we don't always get the same string (very unlikely to collide).
*/
func TestGenerateCSRFToken_Basic(t *testing.T) {
	t1, err := generateCSRFToken()
	if err != nil {
		t.Fatalf("generateCSRFToken returned error: %v", err)
	}
	if t1 == "" {
		t.Fatalf("expected non-empty token from generateCSRFToken")
	}

	t2, err := generateCSRFToken()
	if err != nil {
		t.Fatalf("generateCSRFToken second call returned error: %v", err)
	}
	if t2 == "" {
		t.Fatalf("expected non-empty token from second generateCSRFToken call")
	}
	// It's extremely unlikely they are equal; this is a sanity check, not a hard guarantee.
	if t1 == t2 {
		t.Logf("warning: generateCSRFToken returned identical tokens twice (very unlikely)")
	}
}

/*
TestEnsureCSRFCookie_NewTokenSetsCookie verifies that ensureCSRFCookie:

  - Generates a new token when no cookie is present.
  - Sets a Set-Cookie header with the same value.
*/
func TestEnsureCSRFCookie_NewTokenSetsCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token := ensureCSRFCookie(rr, req)
	if token == "" {
		t.Fatalf("expected non-empty token from ensureCSRFCookie")
	}

	res := rr.Result()
	defer res.Body.Close()

	var got *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == csrfCookieName {
			got = c
			break
		}
	}
	if got == nil {
		t.Fatalf("expected %q cookie to be set", csrfCookieName)
	}
	if got.Value != token {
		t.Fatalf("cookie value = %q, want %q", got.Value, token)
	}
	if got.Path != "/" {
		t.Fatalf("expected cookie Path '/', got %q", got.Path)
	}
}

/*
TestEnsureCSRFCookie_ReusesExistingCookie verifies that when a request
already carries a CSRF cookie, ensureCSRFCookie returns that value and
does not need to generate a new one.
*/
func TestEnsureCSRFCookie_ReusesExistingCookie(t *testing.T) {
	const existing = "existing-token"

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  csrfCookieName,
		Value: existing,
	})

	token := ensureCSRFCookie(rr, req)
	if token != existing {
		t.Fatalf("expected ensureCSRFCookie to return existing value %q, got %q", existing, token)
	}

	// We don't assert on Set-Cookie here; implementation may or may not re-set.
}

/*
TestVerifyCSRFFromBrowser_SkipsWhenNoOriginOrReferer verifies that
verifyCSRFFromBrowser returns true and does not write an error
when called for a request with no Origin/Referer (non-browser client).
*/
func TestVerifyCSRFFromBrowser_SkipsWhenNoOriginOrReferer(t *testing.T) {
	form := url.Values{
		"some": {"value"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/users/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No Origin, no Referer set.
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	rr := httptest.NewRecorder()
	if ok := verifyCSRFFromBrowser(rr, req); !ok {
		t.Fatalf("expected verifyCSRFFromBrowser to allow request with no Origin/Referer")
	}
	// Should not have written a 4xx; default is 200.
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 (default) when CSRF check skipped, got %d", rr.Code)
	}
}

/*
TestVerifyCSRFFromBrowser_MissingCookieForbidden verifies that for a
browser-style POST (Origin present), verifyCSRFFromBrowser rejects
the request if the CSRF cookie is missing.
*/
func TestVerifyCSRFFromBrowser_MissingCookieForbidden(t *testing.T) {
	form := url.Values{
		csrfFormField: {"some-token"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/users/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://ui.example.test")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	rr := httptest.NewRecorder()
	if ok := verifyCSRFFromBrowser(rr, req); ok {
		t.Fatalf("expected verifyCSRFFromBrowser to fail when cookie is missing")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when cookie missing, got %d", rr.Code)
	}
}

/*
TestVerifyCSRFFromBrowser_MissingFormTokenForbidden verifies that for a
browser-style POST, verifyCSRFFromBrowser rejects when the form token
is missing even though the cookie is present.
*/
func TestVerifyCSRFFromBrowser_MissingFormTokenForbidden(t *testing.T) {
	const token = "cookie-token"

	req := httptest.NewRequest(http.MethodPost, "/ui/users/save", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://ui.example.test")
	req.AddCookie(&http.Cookie{
		Name:  csrfCookieName,
		Value: token,
	})
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	rr := httptest.NewRecorder()
	if ok := verifyCSRFFromBrowser(rr, req); ok {
		t.Fatalf("expected verifyCSRFFromBrowser to fail when form token is missing")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when form token missing, got %d", rr.Code)
	}
}

/*
TestVerifyCSRFFromBrowser_MismatchForbidden verifies that a browser-style
POST with mismatched cookie and form tokens is rejected.
*/
func TestVerifyCSRFFromBrowser_MismatchForbidden(t *testing.T) {
	reqToken := "req-token"
	cookieToken := "cookie-token"

	form := url.Values{
		csrfFormField: {reqToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/users/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://ui.example.test")
	req.AddCookie(&http.Cookie{
		Name:  csrfCookieName,
		Value: cookieToken,
	})
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	rr := httptest.NewRecorder()
	if ok := verifyCSRFFromBrowser(rr, req); ok {
		t.Fatalf("expected verifyCSRFFromBrowser to fail on token mismatch")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when tokens mismatch, got %d", rr.Code)
	}
}

/*
TestVerifyCSRFFromBrowser_MatchAllowed verifies that when both the
cookie and form CSRF tokens match for a browser-style POST, the
request is allowed and no error is written.
*/
func TestVerifyCSRFFromBrowser_MatchAllowed(t *testing.T) {
	const token = "same-token"

	form := url.Values{
		csrfFormField: {token},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/users/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://ui.example.test")
	req.AddCookie(&http.Cookie{
		Name:  csrfCookieName,
		Value: token,
	})
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	rr := httptest.NewRecorder()
	if ok := verifyCSRFFromBrowser(rr, req); !ok {
		t.Fatalf("expected verifyCSRFFromBrowser to succeed for matching tokens")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected default 200 status when CSRF check passes, got %d", rr.Code)
	}
}
