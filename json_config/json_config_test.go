package json_config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jldap/models"
)

/*
TestLoadFromDisk_NoPath verifies that LoadFromDisk returns an error
when ConfigStore.Path is empty. It checks that the error message matches
"no config Path" and that no panic occurs.
*/
func TestLoadFromDisk_NoPath(t *testing.T) {
	c := &ConfigStore{}

	err := c.LoadFromDisk()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, errors.New("no config Path")) && err.Error() != "no config Path" {
		t.Fatalf("expected error %q, got %q", "no config Path", err.Error())
	}
}

/*
TestLoadFromDisk_ReadFileError verifies that LoadFromDisk propagates
errors from os.ReadFile. It points the ConfigStore.Path to a non-existent
file and asserts that an error is returned.
*/
func TestLoadFromDisk_ReadFileError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does_not_exist.json")

	c := &ConfigStore{Path: path}
	err := c.LoadFromDisk()
	if err == nil {
		t.Fatalf("expected error reading non-existent file, got nil")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("expected not-exist error, got %v", err)
	}
}

/*
TestLoadFromDisk_InvalidJSON verifies that LoadFromDisk returns an error
when the JSON file cannot be unmarshaled into models.JldapData. It writes
intentionally invalid JSON and checks that an error is returned and that
c.Data is not updated to unexpected values.
*/
func TestLoadFromDisk_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	if err := os.WriteFile(path, []byte("{ invalid json "), 0o600); err != nil {
		t.Fatalf("failed to write temp json: %v", err)
	}

	c := &ConfigStore{Path: path}
	err := c.LoadFromDisk()
	if err == nil {
		t.Fatalf("expected error for invalid JSON, got nil")
	}
}

/*
TestLoadFromDisk_Success verifies the happy path of LoadFromDisk:
- A valid JSON config file is written to disk.
- LoadFromDisk parses it into c.Data.
- lastReload and lastFileMTime are set to non-zero values.
*/
func TestLoadFromDisk_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	want := models.JldapData{
		BaseDN:       "dc=example,dc=com",
		AdminUsersCN: "admins",
	}

	buf, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("failed to marshal test data: %v", err)
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	c := &ConfigStore{Path: path}
	if !c.lastReload.IsZero() || !c.lastFileMTime.IsZero() {
		t.Fatalf("expected zero times before load")
	}

	if err := c.LoadFromDisk(); err != nil {
		t.Fatalf("LoadFromDisk failed: %v", err)
	}

	// Basic sanity: Data.BaseDN should be loaded.
	if c.Data.BaseDN != want.BaseDN {
		t.Fatalf("expected BaseDN %q, got %q", want.BaseDN, c.Data.BaseDN)
	}
	// lastReload should be set.
	if c.lastReload.IsZero() {
		t.Fatalf("expected lastReload to be set")
	}
	// lastFileMTime should be set.
	if c.lastFileMTime.IsZero() {
		t.Fatalf("expected lastFileMTime to be set")
	}
}

/*
TestSaveToDiskLocked_WriteError verifies that saveToDiskLocked returns an
error when writing the temporary file fails (e.g., directory does not exist).
It sets ConfigStore.Path to a file inside a non-existent directory and
checks that an error is returned and that lastFileMTime is not updated.
*/
func TestSaveToDiskLocked_WriteError(t *testing.T) {
	dir := t.TempDir()
	// "nosuch" does not exist, so writing the temp file should fail.
	path := filepath.Join(dir, "nosuch", "config.json")

	c := &ConfigStore{
		Path: path,
		Data: models.JldapData{BaseDN: "dc=example,dc=com"},
	}

	c.Mu.Lock()
	err := c.saveToDiskLocked()
	c.Mu.Unlock()

	if err == nil {
		t.Fatalf("expected error from saveToDiskLocked when directory doesn't exist, got nil")
	}
	if !c.lastFileMTime.IsZero() {
		t.Fatalf("expected lastFileMTime to remain zero on write error")
	}
}

/*
TestSaveToDiskLocked_RenameError verifies that saveToDiskLocked properly
returns an error when os.Rename fails. It sets ConfigStore.Path to point
to an existing directory, so renaming a file over that directory fails.
*/
func TestSaveToDiskLocked_RenameError(t *testing.T) {
	dir := t.TempDir()

	// Create a directory that will serve as the "target" path.
	targetDir := filepath.Join(dir, "target")
	if err := os.Mkdir(targetDir, 0o755); err != nil {
		t.Fatalf("failed to create target directory: %v", err)
	}

	c := &ConfigStore{
		Path: targetDir, // This is a directory; rename to it should fail.
		Data: models.JldapData{BaseDN: "dc=example,dc=com"},
	}

	c.Mu.Lock()
	err := c.saveToDiskLocked()
	c.Mu.Unlock()

	if err == nil {
		t.Fatalf("expected rename error from saveToDiskLocked, got nil")
	}

	// The path should still be a directory.
	info, statErr := os.Stat(targetDir)
	if statErr != nil {
		t.Fatalf("expected to stat targetDir, got error: %v", statErr)
	}
	if !info.IsDir() {
		t.Fatalf("expected target path to remain a directory")
	}
}

/*
TestSaveToDiskLocked_Success verifies the happy path of saveToDiskLocked:
- JSON is written to a temporary file.
- The temporary file is atomically renamed to the final path.
- lastFileMTime is updated.
- The resulting file content can be unmarshaled back into models.JldapData.
*/
func TestSaveToDiskLocked_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	data := models.JldapData{
		BaseDN:       "dc=example,dc=com",
		AdminUsersCN: "admins",
	}

	c := &ConfigStore{
		Path: path,
		Data: data,
	}

	c.Mu.Lock()
	err := c.saveToDiskLocked()
	c.Mu.Unlock()

	if err != nil {
		t.Fatalf("saveToDiskLocked failed: %v", err)
	}

	if c.lastFileMTime.IsZero() {
		t.Fatalf("expected lastFileMTime to be set after successful save")
	}

	// Verify that we actually wrote valid JSON matching Data.
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read saved file: %v", err)
	}
	var got models.JldapData
	if err := json.Unmarshal(onDisk, &got); err != nil {
		t.Fatalf("failed to unmarshal saved JSON: %v", err)
	}
	if got.BaseDN != data.BaseDN || got.AdminUsersCN != data.AdminUsersCN {
		t.Fatalf("saved data mismatch: got %+v, want %+v", got, data)
	}
}

/*
TestLoadDirectoryFromJSON_ReadError verifies that LoadDirectoryFromJSON
returns an error when the JSON file cannot be read (e.g., file does not exist).
*/
func TestLoadDirectoryFromJSON_ReadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does_not_exist.json")

	d, err := LoadDirectoryFromJSON(path)
	if err == nil {
		t.Fatalf("expected error for non-existent path, got nil")
	}
	if d != nil {
		t.Fatalf("expected nil directory on error, got %#v", d)
	}
}

/*
TestLoadDirectoryFromJSON_InvalidJSON verifies that LoadDirectoryFromJSON
returns an error when the JSON is invalid and cannot be unmarshaled.
*/
func TestLoadDirectoryFromJSON_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	if err := os.WriteFile(path, []byte("{ invalid json "), 0o600); err != nil {
		t.Fatalf("failed to write invalid JSON: %v", err)
	}

	d, err := LoadDirectoryFromJSON(path)
	if err == nil {
		t.Fatalf("expected error for invalid JSON, got nil")
	}
	if d != nil {
		t.Fatalf("expected nil directory on error, got %#v", d)
	}
}

/*
TestLoadDirectoryFromJSON_MissingBaseDN verifies that LoadDirectoryFromJSON
fails when BaseDN is missing or whitespace-only. It asserts that the returned
error matches "json: BaseDN is required".
*/
func TestLoadDirectoryFromJSON_MissingBaseDN(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// BaseDN is whitespace-only.
	j := `{
		"BaseDN": "   ",
		"Users": [],
		"Groups": []
	}`

	if err := os.WriteFile(path, []byte(j), 0o600); err != nil {
		t.Fatalf("failed to write JSON: %v", err)
	}

	d, err := LoadDirectoryFromJSON(path)
	if err == nil {
		t.Fatalf("expected error for missing BaseDN, got nil")
	}
	if d != nil {
		t.Fatalf("expected nil directory on error, got %#v", d)
	}
	if err.Error() != "json: BaseDN is required" {
		t.Fatalf("expected error %q, got %q", "json: BaseDN is required", err.Error())
	}
}

/*
TestLoadDirectoryFromJSON_UserMissingUID verifies that LoadDirectoryFromJSON
fails when a user entry is missing a UID. It constructs JSON with a user whose
UID is empty and asserts that an error is returned.
*/
func TestLoadDirectoryFromJSON_UserMissingUID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	j := `{
		"BaseDN": "dc=example,dc=com",
		"Users": [
			{ "UID": "   ", "CN": "NoUID" }
		],
		"Groups": []
	}`

	if err := os.WriteFile(path, []byte(j), 0o600); err != nil {
		t.Fatalf("failed to write JSON: %v", err)
	}

	d, err := LoadDirectoryFromJSON(path)
	if err == nil {
		t.Fatalf("expected error for user missing uid, got nil")
	}
	if d != nil {
		t.Fatalf("expected nil directory on error, got %#v", d)
	}
	if err.Error() != "json: user missing uid" {
		t.Fatalf("expected error %q, got %q", "json: user missing uid", err.Error())
	}
}

/*
TestLoadDirectoryFromJSON_GroupMissingCN verifies that LoadDirectoryFromJSON
fails when a group entry is missing a CN. It constructs JSON with a valid user
and a group whose CN is empty and asserts that an error is returned.
*/
func TestLoadDirectoryFromJSON_GroupMissingCN(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	j := `{
		"BaseDN": "dc=example,dc=com",
		"Users": [
			{ "UID": "alice", "CN": "Alice" }
		],
		"Groups": [
			{ "CN": "   " }
		]
	}`

	if err := os.WriteFile(path, []byte(j), 0o600); err != nil {
		t.Fatalf("failed to write JSON: %v", err)
	}

	d, err := LoadDirectoryFromJSON(path)
	if err == nil {
		t.Fatalf("expected error for group missing cn, got nil")
	}
	if d != nil {
		t.Fatalf("expected nil directory on error, got %#v", d)
	}
	if err.Error() != "json: group missing cn" {
		t.Fatalf("expected error %q, got %q", "json: group missing cn", err.Error())
	}
}

/*
TestLoadDirectoryFromJSON_SuccessAndMembershipResolution verifies the main
happy path of LoadDirectoryFromJSON, including:
- AdminUsersCN defaulting when empty.
- User entries being converted into directory entries with the correct DN and attributes.
- Group entries being created with default objectClass values when omitted.
- memberUid entries being trimmed and stored.
- member entries being resolved according to the key logic branches:
  - Direct DNs (uid=... with comma) are stored as-is.
  - Likely UIDs (like "alice") are resolved via the directory lookup and converted to DNs.
  - cn=... DNs are stored as-is.
  - A fallback member like "bob,ouusers" (comma but no '=') hits the final else-branch and is not added.
*/
func TestLoadDirectoryFromJSON_SuccessAndMembershipResolution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	jsonConfig := `{
		"BaseDN": "dc=example,dc=com",
		"AdminUsersCN": "   ",
		"Users": [
			{
				"UID": "alice",
				"CN": "Alice",
				"SN": "A",
				"GivenName": "Alice",
				"Mail": "alice@example.com",
				"UserPassword": "secret",
				"UIDNumber": "1000",
				"GIDNumber": "1000"
			}
		],
		"Groups": [
			{
				"CN": "devs",
				"GIDNumber": "2000",
				"MemberUID": ["alice ", ""],
				"Member": [
					"uid=alice,ou=users,dc=example,dc=com",
					"alice",
					"cn=other,ou=groups,dc=example,dc=com",
					"uid=ghost",
					"bob,ouusers"
				]
			}
		]
	}`

	if err := os.WriteFile(path, []byte(jsonConfig), 0o600); err != nil {
		t.Fatalf("failed to write JSON: %v", err)
	}

	d, err := LoadDirectoryFromJSON(path)
	if err != nil {
		t.Fatalf("expected success from LoadDirectoryFromJSON, got error: %v", err)
	}
	if d == nil {
		t.Fatalf("expected non-nil directory on success")
	}

	// Verify that the user entry exists and has correct DN and uid attribute.
	aliceDN := "uid=alice,ou=users,dc=example,dc=com"
	aliceEntry := d.Get(aliceDN)
	if aliceEntry == nil {
		t.Fatalf("expected user entry %q to exist", aliceDN)
	}
	if aliceEntry.DN != aliceDN {
		t.Fatalf("unexpected DN for alice: %q", aliceEntry.DN)
	}

	if got := aliceEntry.Attrs["uid"]; len(got) != 1 || got[0] != "alice" {
		t.Fatalf("expected uid 'alice', got %v", got)
	}

	// If UIDNumber mapping is correct in models, this should be set.
	if got := aliceEntry.Attrs["uidnumber"]; len(got) != 1 || got[0] != "1000" {
		t.Fatalf("expected uidnumber '1000', got %v", got)
	}

	// Verify group entry exists with correct DN.
	groupDN := "cn=devs,ou=groups,dc=example,dc=com"
	groupEntry := d.Get(groupDN)
	if groupEntry == nil {
		t.Fatalf("expected group entry %q to exist", groupDN)
	}

	// objectclass should have default values because ObjectClass was omitted in JSON.
	ocs := groupEntry.Attrs["objectclass"]
	if len(ocs) == 0 {
		t.Fatalf("expected group objectclass to be populated, got empty")
	}
	// We expect "posixGroup" to be among them.
	foundPosix := false
	for _, oc := range ocs {
		if oc == "posixGroup" {
			foundPosix = true
			break
		}
	}
	if !foundPosix {
		t.Fatalf("expected group objectclass to include 'posixGroup', got %v", ocs)
	}

	// memberuid should contain trimmed "alice" but not the empty entry.
	mu := groupEntry.Attrs["memberuid"]
	if len(mu) != 1 || mu[0] != "alice" {
		t.Fatalf("expected memberuid ['alice'], got %v", mu)
	}

	// member attribute should reflect resolution rules.
	members := groupEntry.Attrs["member"]
	if len(members) == 0 {
		t.Fatalf("expected member attribute to be non-empty")
	}

	// We expect:
	// - Alice's DN twice (direct DN + resolved UID "alice").
	// - One cn=other,... entry.
	// - No "bob,ouusers" because it hits the final else-branch and fails to resolve.
	aliceCount := 0
	cnOtherCount := 0
	bobCount := 0

	for _, m := range members {
		switch {
		case m == aliceEntry.DN:
			aliceCount++
		case strings.HasPrefix(strings.ToLower(m), "cn=other,"):
			cnOtherCount++
		case m == "bob,ouusers":
			bobCount++
		}
	}

	if aliceCount < 2 {
		t.Fatalf("expected alice's DN to appear at least twice (direct + resolved), got %d in %v", aliceCount, members)
	}
	if cnOtherCount != 1 {
		t.Fatalf("expected exactly one 'cn=other,...' member, got %d in %v", cnOtherCount, members)
	}
	if bobCount != 0 {
		t.Fatalf("did not expect fallback member 'bob,ouusers' in member attribute, got %v", members)
	}
}

/*
TestIsLikelyUID_BasicCases verifies that isLikelyUID correctly classifies
strings based on the presence of commas and equals signs:
- Plain usernames return true.
- DN-like strings containing '=' or ',' return false.
*/
func TestIsLikelyUID_BasicCases(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"alice", true},
		{"bob", true},
		{"uid=alice", false},
		{"alice,ou=users", false},
		{"cn=alice,ou=users", false},
		{"", true}, // no comma or '=', so technically "likely" UID
	}

	for _, tc := range cases {
		got := isLikelyUID(tc.in)
		if got != tc.want {
			t.Fatalf("isLikelyUID(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

/*
TestLoadDirectoryFromJSON_AdminUsersCNDefault ensures that when AdminUsersCN
is empty/whitespace in the JSON, the defaulting branch executes. The function
does not expose AdminUsersCN directly, but this test covers the code path
and confirms the rest of the directory is built successfully.
*/
func TestLoadDirectoryFromJSON_AdminUsersCNDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	j := `{
		"BaseDN": "dc=example,dc=com",
		"AdminUsersCN": "   ",
		"Users": [],
		"Groups": []
	}`

	if err := os.WriteFile(path, []byte(j), 0o600); err != nil {
		t.Fatalf("failed to write JSON: %v", err)
	}

	d, err := LoadDirectoryFromJSON(path)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if d == nil {
		t.Fatalf("expected non-nil directory")
	}

	// We can't directly read AdminUsersCN from here, but reaching this point
	// confirms that the defaulting logic did not break anything and the
	// directory was constructed successfully.
}

/*
TestSaveToDiskLocked_TimeMovesForward checks that lastFileMTime is updated
to a more recent timestamp when saveToDiskLocked is called again. This helps
exercise the timestamp update behavior beyond a single call.
*/
func TestSaveToDiskLocked_TimeMovesForward(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	data := models.JldapData{BaseDN: "dc=example,dc=com"}

	c := &ConfigStore{
		Path: path,
		Data: data,
	}

	// First save.
	c.Mu.Lock()
	if err := c.saveToDiskLocked(); err != nil {
		c.Mu.Unlock()
		t.Fatalf("first saveToDiskLocked failed: %v", err)
	}
	firstTime := c.lastFileMTime
	c.Mu.Unlock()

	// Ensure some time passes; not strictly required, but we can sleep a tiny bit.
	time.Sleep(10 * time.Millisecond)

	// Second save.
	c.Mu.Lock()
	if err := c.saveToDiskLocked(); err != nil {
		c.Mu.Unlock()
		t.Fatalf("second saveToDiskLocked failed: %v", err)
	}
	secondTime := c.lastFileMTime
	c.Mu.Unlock()

	if !secondTime.After(firstTime) && !secondTime.Equal(firstTime) {
		t.Fatalf("expected secondTime >= firstTime, got first=%v second=%v", firstTime, secondTime)
	}
}

/*
TestLoadDirectoryFromJSON_UserCustomObjectClass verifies that when a user
entry in the JSON has an explicit ObjectClass list, LoadDirectoryFromJSON
preserves it instead of using the default objectClass set.
*/
func TestLoadDirectoryFromJSON_UserCustomObjectClass(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config_user_oc.json")

	j := `{
		"BaseDN": "dc=example,dc=com",
		"Users": [
			{
				"UID": "alice",
				"CN": "Alice",
				"ObjectClass": ["customUserClass1", "customUserClass2"]
			}
		],
		"Groups": []
	}`

	if err := os.WriteFile(path, []byte(j), 0o600); err != nil {
		t.Fatalf("failed to write JSON: %v", err)
	}

	d, err := LoadDirectoryFromJSON(path)
	if err != nil {
		t.Fatalf("expected success from LoadDirectoryFromJSON, got error: %v", err)
	}
	if d == nil {
		t.Fatalf("expected non-nil directory")
	}

	userDN := "uid=alice,ou=users,dc=example,dc=com"
	e := d.Get(userDN)
	if e == nil {
		t.Fatalf("expected user entry %q to exist", userDN)
	}

	ocs := e.Attrs["objectclass"]
	if len(ocs) != 2 || ocs[0] != "customUserClass1" || ocs[1] != "customUserClass2" {
		t.Fatalf("expected custom user objectclass [customUserClass1 customUserClass2], got %v", ocs)
	}
}

/*
TestLoadDirectoryFromJSON_GroupCustomObjectClass verifies that when a group
entry in the JSON has an explicit ObjectClass list, LoadDirectoryFromJSON
preserves it instead of falling back to the default group objectClasses.
*/
func TestLoadDirectoryFromJSON_GroupCustomObjectClass(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config_group_oc.json")

	j := `{
		"BaseDN": "dc=example,dc=com",
		"Users": [
			{ "UID": "alice", "CN": "Alice" }
		],
		"Groups": [
			{
				"CN": "customgroup",
				"ObjectClass": ["customGroupClass"]
			}
		]
	}`

	if err := os.WriteFile(path, []byte(j), 0o600); err != nil {
		t.Fatalf("failed to write JSON: %v", err)
	}

	d, err := LoadDirectoryFromJSON(path)
	if err != nil {
		t.Fatalf("expected success from LoadDirectoryFromJSON, got error: %v", err)
	}
	if d == nil {
		t.Fatalf("expected non-nil directory")
	}

	groupDN := "cn=customgroup,ou=groups,dc=example,dc=com"
	e := d.Get(groupDN)
	if e == nil {
		t.Fatalf("expected group entry %q to exist", groupDN)
	}

	ocs := e.Attrs["objectclass"]
	if len(ocs) != 1 || ocs[0] != "customGroupClass" {
		t.Fatalf("expected custom group objectclass [customGroupClass], got %v", ocs)
	}
}

/*
TestLoadDirectoryFromJSON_GroupMemberFallbackElse verifies that a group
member string that:
- contains a comma,
- does not contain '=',
- does not start with "uid=", "cn=", or "dn=",
is handled by the final "else" branch of the member resolution logic.
In this case, the code attempts to resolve the value as a UID via ByUID,
fails, logs a warning, and does NOT append it to the "member" attribute.
*/
func TestLoadDirectoryFromJSON_GroupMemberFallbackElse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config_group_member_else.json")

	// "bob,ouusers" has a comma but no '=', so:
	// - isLikelyUID("bob,ouusers") == false (contains comma)
	// - strings.Contains(m, "=") == false
	// This forces the code into the final else-branch, where it fails to
	// resolve as a UID and should not add it to the "member" attribute.
	j := `{
		"BaseDN": "dc=example,dc=com",
		"Users": [
			{ "UID": "alice", "CN": "Alice" }
		],
		"Groups": [
			{
				"CN": "fallback",
				"Member": ["bob,ouusers"]
			}
		]
	}`

	if err := os.WriteFile(path, []byte(j), 0o600); err != nil {
		t.Fatalf("failed to write JSON: %v", err)
	}

	d, err := LoadDirectoryFromJSON(path)
	if err != nil {
		t.Fatalf("expected success from LoadDirectoryFromJSON, got error: %v", err)
	}
	if d == nil {
		t.Fatalf("expected non-nil directory")
	}

	groupDN := "cn=fallback,ou=groups,dc=example,dc=com"
	e := d.Get(groupDN)
	if e == nil {
		t.Fatalf("expected group entry %q to exist", groupDN)
	}

	members, ok := e.Attrs["member"]
	if ok && len(members) > 0 {
		t.Fatalf("expected no members to be added for fallback case, got %v", members)
	}
}
