package json_config

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"jldap/models"
)

/*
TestAddUser_EmptyUID verifies that AddUser returns an error
when the provided user has an empty UID (after trimming).
*/
func TestAddUser_EmptyUID(t *testing.T) {
	cs := &ConfigStore{}

	err := cs.AddUser(models.JldapUser{UID: "   "})
	if err == nil {
		t.Fatalf("expected error for empty uid, got nil")
	}
}

/*
TestAddUser_NoBaseDN verifies that AddUser returns an error
when the config has no BaseDN set.
*/
func TestAddUser_NoBaseDN(t *testing.T) {
	cs := &ConfigStore{
		Data: models.JldapData{
			BaseDN: "",
		},
	}

	err := cs.AddUser(models.JldapUser{UID: "alice"})
	if err == nil {
		t.Fatalf("expected error for missing BaseDN, got nil")
	}
}

/*
TestAddUser_NewUser verifies that AddUser appends a new user
when the UID does not already exist, and that the user fields
are stored as provided.
*/
func TestAddUser_NewUser(t *testing.T) {
	dir := t.TempDir()
	cs := &ConfigStore{
		Path: filepath.Join(dir, "config.json"),
		Data: models.JldapData{
			BaseDN: "dc=example,dc=com",
		},
	}

	u := models.JldapUser{
		UID:          "alice",
		CN:           "Alice Example",
		SN:           "Example",
		GivenName:    "Alice",
		Mail:         "alice@example.com",
		UserPassword: "secret",
		UIDNumber:    "1000",
		GIDNumber:    "1000",
		HomeDir:      "/home/alice",
		LoginShell:   "/bin/bash",
		ObjectClass:  []string{"inetOrgPerson"},
	}

	if err := cs.AddUser(u); err != nil {
		t.Fatalf("AddUser returned error: %v", err)
	}

	if len(cs.Data.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(cs.Data.Users))
	}
	got := cs.Data.Users[0]
	if !reflect.DeepEqual(got, u) {
		t.Fatalf("stored user mismatch:\nwant %#v\n got %#v", u, got)
	}
}

/*
TestAddUser_UpdateExistingUser verifies that AddUser updates an
existing user with the same UID (case-insensitive), only overwriting
fields that are non-empty in the new user struct.
*/
func TestAddUser_UpdateExistingUser(t *testing.T) {
	dir := t.TempDir()
	existing := models.JldapUser{
		UID:          "alice",
		CN:           "Old CN",
		SN:           "Old SN",
		GivenName:    "Old Given",
		Mail:         "old@example.com",
		UserPassword: "oldpass",
		UIDNumber:    "1000",
		GIDNumber:    "1000",
		HomeDir:      "/home/old",
		LoginShell:   "/bin/sh",
		ObjectClass:  []string{"oldObjectClass"},
	}
	cs := &ConfigStore{
		Path: filepath.Join(dir, "config.json"),
		Data: models.JldapData{
			BaseDN: "dc=example,dc=com",
			Users:  []models.JldapUser{existing},
		},
	}

	// Only some fields non-empty -> should partially update.
	update := models.JldapUser{
		UID:         "ALICE", // different case, should match
		CN:          "New CN",
		Mail:        "new@example.com",
		HomeDir:     "/home/new",
		ObjectClass: []string{"newObjectClass"},
		// Leave others empty to ensure they remain unchanged.
	}

	if err := cs.AddUser(update); err != nil {
		t.Fatalf("AddUser returned error: %v", err)
	}

	if len(cs.Data.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(cs.Data.Users))
	}
	got := cs.Data.Users[0]

	// Updated fields
	if got.CN != "New CN" {
		t.Errorf("expected CN updated to %q, got %q", "New CN", got.CN)
	}
	if got.Mail != "new@example.com" {
		t.Errorf("expected Mail updated to %q, got %q", "new@example.com", got.Mail)
	}
	if got.HomeDir != "/home/new" {
		t.Errorf("expected HomeDir updated to %q, got %q", "/home/new", got.HomeDir)
	}
	if !reflect.DeepEqual(got.ObjectClass, []string{"newObjectClass"}) {
		t.Errorf("expected ObjectClass updated, got %#v", got.ObjectClass)
	}

	// Unchanged fields
	if got.SN != existing.SN {
		t.Errorf("expected SN unchanged (%q), got %q", existing.SN, got.SN)
	}
	if got.GivenName != existing.GivenName {
		t.Errorf("expected GivenName unchanged (%q), got %q", existing.GivenName, got.GivenName)
	}
	if got.UserPassword != existing.UserPassword {
		t.Errorf("expected UserPassword unchanged (%q), got %q", existing.UserPassword, got.UserPassword)
	}
	if got.UIDNumber != existing.UIDNumber {
		t.Errorf("expected UIDNumber unchanged (%q), got %q", existing.UIDNumber, got.UIDNumber)
	}
	if got.GIDNumber != existing.GIDNumber {
		t.Errorf("expected GIDNumber unchanged (%q), got %q", existing.GIDNumber, got.GIDNumber)
	}
	if got.LoginShell != existing.LoginShell {
		t.Errorf("expected LoginShell unchanged (%q), got %q", existing.LoginShell, got.LoginShell)
	}
}

/*
TestDeleteUser_EmptyUID verifies that DeleteUser returns an error
when called with an empty UID (after trimming).
*/
func TestDeleteUser_EmptyUID(t *testing.T) {
	cs := &ConfigStore{}

	if err := cs.DeleteUser("   "); err == nil {
		t.Fatalf("expected error for empty uid, got nil")
	}
}

/*
TestDeleteUser_NotFound verifies that DeleteUser returns an error
when the user with the given UID is not present in the store.
*/
func TestDeleteUser_NotFound(t *testing.T) {
	cs := &ConfigStore{
		Data: models.JldapData{
			BaseDN: "dc=example,dc=com",
			Users: []models.JldapUser{
				{UID: "bob"},
			},
		},
	}

	if err := cs.DeleteUser("alice"); err == nil {
		t.Fatalf("expected error for missing user, got nil")
	}
}

/*
TestDeleteUser_Success verifies that DeleteUser removes the user from
the Users slice and also removes the user's UID and DN from all groups'
MemberUID and Member slices.
*/
func TestDeleteUser_Success(t *testing.T) {
	dir := t.TempDir()
	baseDN := "dc=example,dc=com"
	cs := &ConfigStore{
		Path: filepath.Join(dir, "config.json"),
		Data: models.JldapData{
			BaseDN: baseDN,
			Users: []models.JldapUser{
				{UID: "alice"},
				{UID: "bob"},
			},
			Groups: []models.JldapGroup{
				{
					CN:        "devs",
					MemberUID: []string{"alice", "bob"},
					Member: []string{
						"uid=alice,ou=users," + baseDN,
						"uid=bob,ou=users," + baseDN,
					},
				},
			},
		},
	}

	if err := cs.DeleteUser("alice"); err != nil {
		t.Fatalf("DeleteUser returned error: %v", err)
	}

	// alice should be gone
	if len(cs.Data.Users) != 1 || cs.Data.Users[0].UID != "bob" {
		t.Fatalf("expected only bob to remain, got %#v", cs.Data.Users)
	}

	// Group membership should no longer include alice.
	g := cs.Data.Groups[0]
	if len(g.MemberUID) != 1 || !stringsEqualIgnoreCase(g.MemberUID[0], "bob") {
		t.Fatalf("expected MemberUID to contain only bob, got %#v", g.MemberUID)
	}
	expectedDN := "uid=bob,ou=users," + baseDN
	if len(g.Member) != 1 || !stringsEqualIgnoreCase(g.Member[0], expectedDN) {
		t.Fatalf("expected Member to contain only %q, got %#v", expectedDN, g.Member)
	}
}

/*
TestAddGroup_EmptyCN verifies that AddGroup returns an error
when the group CN is empty (after trimming).
*/
func TestAddGroup_EmptyCN(t *testing.T) {
	cs := &ConfigStore{}

	if err := cs.AddGroup(models.JldapGroup{CN: "  "}); err == nil {
		t.Fatalf("expected error for empty cn, got nil")
	}
}

/*
TestAddGroup_NewGroup verifies that AddGroup appends a new group
when no existing group with the same CN exists.
*/
func TestAddGroup_NewGroup(t *testing.T) {
	dir := t.TempDir()
	cs := &ConfigStore{
		Path: filepath.Join(dir, "config.json"),
		Data: models.JldapData{},
	}

	g := models.JldapGroup{
		CN:          "devs",
		GIDNumber:   "2000",
		Member:      []string{"uid=alice,ou=users,dc=example,dc=com"},
		MemberUID:   []string{"alice"},
		ObjectClass: []string{"posixGroup"},
	}

	if err := cs.AddGroup(g); err != nil {
		t.Fatalf("AddGroup returned error: %v", err)
	}

	if len(cs.Data.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(cs.Data.Groups))
	}
	if !reflect.DeepEqual(cs.Data.Groups[0], g) {
		t.Fatalf("stored group mismatch:\nwant %#v\n got %#v", g, cs.Data.Groups[0])
	}
}

/*
TestAddGroup_UpdateExistingGroup verifies that AddGroup updates an
existing group when the CN matches (case-insensitive), only overwriting
fields that are non-empty or non-nil in the new group struct.
*/
func TestAddGroup_UpdateExistingGroup(t *testing.T) {
	dir := t.TempDir()
	existing := models.JldapGroup{
		CN:          "devs",
		GIDNumber:   "2000",
		Member:      []string{"oldMember"},
		MemberUID:   []string{"oldUID"},
		ObjectClass: []string{"oldClass"},
	}
	cs := &ConfigStore{
		Path: filepath.Join(dir, "config.json"),
		Data: models.JldapData{
			Groups: []models.JldapGroup{existing},
		},
	}

	update := models.JldapGroup{
		CN:          "DEVS", // same CN, different case
		GIDNumber:   "3000",
		Member:      []string{"newMember"},
		MemberUID:   []string{"newUID"},
		ObjectClass: []string{"newClass"},
	}

	if err := cs.AddGroup(update); err != nil {
		t.Fatalf("AddGroup returned error: %v", err)
	}

	if len(cs.Data.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(cs.Data.Groups))
	}

	got := cs.Data.Groups[0]
	if got.GIDNumber != "3000" {
		t.Errorf("expected GIDNumber updated to 3000, got %q", got.GIDNumber)
	}
	if !reflect.DeepEqual(got.Member, []string{"newMember"}) {
		t.Errorf("expected Member replaced, got %#v", got.Member)
	}
	if !reflect.DeepEqual(got.MemberUID, []string{"newUID"}) {
		t.Errorf("expected MemberUID replaced, got %#v", got.MemberUID)
	}
	if !reflect.DeepEqual(got.ObjectClass, []string{"newClass"}) {
		t.Errorf("expected ObjectClass replaced, got %#v", got.ObjectClass)
	}
}

/*
TestDeleteGroup_EmptyCN verifies that DeleteGroup returns an error
when called with an empty CN (after trimming).
*/
func TestDeleteGroup_EmptyCN(t *testing.T) {
	cs := &ConfigStore{}

	if err := cs.DeleteGroup("   "); err == nil {
		t.Fatalf("expected error for empty cn, got nil")
	}
}

/*
TestDeleteGroup_NotFound verifies that DeleteGroup returns an error
when no group with the given CN exists.
*/
func TestDeleteGroup_NotFound(t *testing.T) {
	cs := &ConfigStore{
		Data: models.JldapData{
			Groups: []models.JldapGroup{
				{CN: "devs"},
			},
		},
	}

	if err := cs.DeleteGroup("admins"); err == nil {
		t.Fatalf("expected error for missing group, got nil")
	}
}

/*
TestDeleteGroup_Success verifies that DeleteGroup removes the group
with the specified CN and preserves the others.
*/
func TestDeleteGroup_Success(t *testing.T) {
	dir := t.TempDir()
	cs := &ConfigStore{
		Path: filepath.Join(dir, "config.json"),
		Data: models.JldapData{
			Groups: []models.JldapGroup{
				{CN: "devs"},
				{CN: "admins"},
			},
		},
	}

	if err := cs.DeleteGroup("devs"); err != nil {
		t.Fatalf("DeleteGroup returned error: %v", err)
	}

	if len(cs.Data.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(cs.Data.Groups))
	}
	if cs.Data.Groups[0].CN != "admins" {
		t.Fatalf("expected remaining group to be admins, got %q", cs.Data.Groups[0].CN)
	}
}

/*
TestListUsers_ReturnsCopy verifies that ListUsers returns a copy of
the internal users slice, so that modifying the returned slice does
not affect the underlying store.
*/
func TestListUsers_ReturnsCopy(t *testing.T) {
	cs := &ConfigStore{
		Data: models.JldapData{
			Users: []models.JldapUser{
				{UID: "alice"},
				{UID: "bob"},
			},
		},
	}

	users := cs.ListUsers()
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}

	// Mutate returned slice
	users[0].UID = "hacked"

	// Original should be unaffected
	if cs.Data.Users[0].UID != "alice" {
		t.Fatalf("expected store user UID to remain 'alice', got %q", cs.Data.Users[0].UID)
	}
}

/*
TestGetUser_Found verifies that GetUser returns the matching user and
true when a user with the given UID (case-insensitive) exists.
*/
func TestGetUser_Found(t *testing.T) {
	cs := &ConfigStore{
		Data: models.JldapData{
			Users: []models.JldapUser{
				{UID: "alice"},
			},
		},
	}

	u, ok := cs.GetUser(" ALICE ")
	if !ok {
		t.Fatalf("expected user to be found")
	}
	if u.UID != "alice" {
		t.Fatalf("expected UID 'alice', got %q", u.UID)
	}
}

/*
TestGetUser_NotFound verifies that GetUser returns the zero-value user
and false when no user with the given UID exists.
*/
func TestGetUser_NotFound(t *testing.T) {
	cs := &ConfigStore{
		Data: models.JldapData{
			Users: []models.JldapUser{
				{UID: "alice"},
			},
		},
	}

	u, ok := cs.GetUser("bob")
	if ok {
		t.Fatalf("expected user not to be found")
	}
	if u.UID != "" {
		t.Fatalf("expected zero-value user, got %#v", u)
	}
}

/*
TestListGroups_ReturnsCopy verifies that ListGroups returns a copy of
the internal groups slice, so that modifications to the returned slice
do not impact the stored groups.
*/
func TestListGroups_ReturnsCopy(t *testing.T) {
	cs := &ConfigStore{
		Data: models.JldapData{
			Groups: []models.JldapGroup{
				{CN: "devs"},
				{CN: "admins"},
			},
		},
	}

	grps := cs.ListGroups()
	if len(grps) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(grps))
	}

	// Mutate returned slice
	grps[0].CN = "hacked"

	if cs.Data.Groups[0].CN != "devs" {
		t.Fatalf("expected store group CN to remain 'devs', got %q", cs.Data.Groups[0].CN)
	}
}

/*
TestGetGroup_Found verifies that GetGroup returns the matching group
and true when a group with the given CN (case-insensitive) exists.
*/
func TestGetGroup_Found(t *testing.T) {
	cs := &ConfigStore{
		Data: models.JldapData{
			Groups: []models.JldapGroup{
				{CN: "devs"},
			},
		},
	}

	g, ok := cs.GetGroup(" DEVS ")
	if !ok {
		t.Fatalf("expected group to be found")
	}
	if g.CN != "devs" {
		t.Fatalf("expected CN 'devs', got %q", g.CN)
	}
}

/*
TestGetGroup_NotFound verifies that GetGroup returns the zero-value
group and false when the group is not present.
*/
func TestGetGroup_NotFound(t *testing.T) {
	cs := &ConfigStore{
		Data: models.JldapData{
			Groups: []models.JldapGroup{
				{CN: "devs"},
			},
		},
	}

	g, ok := cs.GetGroup("admins")
	if ok {
		t.Fatalf("expected group not to be found")
	}
	if g.CN != "" {
		t.Fatalf("expected zero-value group, got %#v", g)
	}
}

/*
TestInfo_ReturnsValues verifies that Info returns the path, lastReload,
and lastMtime fields as stored on the ConfigStore, under a read lock.
*/
func TestInfo_ReturnsValues(t *testing.T) {
	now := time.Now()
	mt := now.Add(-time.Hour)

	cs := &ConfigStore{
		Path:          "/tmp/config.json",
		lastReload:    now,
		lastFileMTime: mt,
	}

	path, lastReload, lastMtime := cs.Info()
	if path != cs.Path {
		t.Errorf("expected path %q, got %q", cs.Path, path)
	}
	if !lastReload.Equal(now) {
		t.Errorf("expected lastReload %v, got %v", now, lastReload)
	}
	if !lastMtime.Equal(mt) {
		t.Errorf("expected lastMtime %v, got %v", mt, lastMtime)
	}
}

/*
TestAddUserToAdmin_EmptyUID verifies that AddUserToAdmin returns an
error when the provided UID is empty (after trimming).
*/
func TestAddUserToAdmin_EmptyUID(t *testing.T) {
	cs := &ConfigStore{
		Data: models.JldapData{
			AdminUsersCN: "admins",
			BaseDN:       "dc=example,dc=com",
		},
	}

	if err := cs.AddUserToAdmin("   "); err == nil {
		t.Fatalf("expected error for empty uid, got nil")
	}
}

/*
TestAddUserToAdmin_AdminUsersCNNotConfigured verifies that
AddUserToAdmin returns an error when AdminUsersCN is not set.
*/
func TestAddUserToAdmin_AdminUsersCNNotConfigured(t *testing.T) {
	cs := &ConfigStore{
		Data: models.JldapData{
			AdminUsersCN: "",
			BaseDN:       "dc=example,dc=com",
		},
	}

	if err := cs.AddUserToAdmin("alice"); err == nil {
		t.Fatalf("expected error when adminUsersCN not configured, got nil")
	}
}

/*
TestAddUserToAdmin_CreatesGroupAndAddsMembership verifies that
AddUserToAdmin creates the admin group if it does not exist and adds
both the UID and DN to MemberUID and Member respectively.
*/
func TestAddUserToAdmin_CreatesGroupAndAddsMembership(t *testing.T) {
	dir := t.TempDir()
	baseDN := "dc=example,dc=com"
	cs := &ConfigStore{
		Path: filepath.Join(dir, "config.json"),
		Data: models.JldapData{
			AdminUsersCN: "admins",
			BaseDN:       baseDN,
			Groups:       []models.JldapGroup{},
		},
	}

	if err := cs.AddUserToAdmin("alice"); err != nil {
		t.Fatalf("AddUserToAdmin returned error: %v", err)
	}

	if len(cs.Data.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(cs.Data.Groups))
	}

	g := cs.Data.Groups[0]
	if !stringsEqualIgnoreCase(g.CN, "admins") {
		t.Fatalf("expected admin group CN 'admins', got %q", g.CN)
	}

	if len(g.MemberUID) != 1 || !stringsEqualIgnoreCase(g.MemberUID[0], "alice") {
		t.Fatalf("expected MemberUID to contain 'alice', got %#v", g.MemberUID)
	}

	expectedDN := "uid=alice,ou=users," + baseDN
	if len(g.Member) != 1 || !stringsEqualIgnoreCase(g.Member[0], expectedDN) {
		t.Fatalf("expected Member to contain %q, got %#v", expectedDN, g.Member)
	}
}

/*
TestAddUserToAdmin_Idempotent verifies that calling AddUserToAdmin
multiple times for the same user does not add duplicate entries to
MemberUID or Member.
*/
func TestAddUserToAdmin_Idempotent(t *testing.T) {
	dir := t.TempDir()
	baseDN := "dc=example,dc=com"
	cs := &ConfigStore{
		Path: filepath.Join(dir, "config.json"),
		Data: models.JldapData{
			AdminUsersCN: "admins",
			BaseDN:       baseDN,
		},
	}

	if err := cs.AddUserToAdmin("alice"); err != nil {
		t.Fatalf("first AddUserToAdmin returned error: %v", err)
	}
	if err := cs.AddUserToAdmin("alice"); err != nil {
		t.Fatalf("second AddUserToAdmin returned error: %v", err)
	}

	if len(cs.Data.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(cs.Data.Groups))
	}
	g := cs.Data.Groups[0]

	if len(g.MemberUID) != 1 {
		t.Fatalf("expected MemberUID length 1, got %d (%#v)", len(g.MemberUID), g.MemberUID)
	}
	expectedDN := "uid=alice,ou=users," + baseDN
	if len(g.Member) != 1 || !stringsEqualIgnoreCase(g.Member[0], expectedDN) {
		t.Fatalf("expected Member length 1 with %q, got %#v", expectedDN, g.Member)
	}
}

/*
TestRemoveUserFromAdmin_RemovesMembership verifies that
RemoveUserFromAdmin removes the user's UID and DN from the admin group's
MemberUID and Member slices.
*/
func TestRemoveUserFromAdmin_RemovesMembership(t *testing.T) {
	dir := t.TempDir()
	baseDN := "dc=example,dc=com"
	adminGroup := models.JldapGroup{
		CN:        "admins",
		MemberUID: []string{"alice", "bob"},
		Member: []string{
			"uid=alice,ou=users," + baseDN,
			"uid=bob,ou=users," + baseDN,
		},
	}
	cs := &ConfigStore{
		Path: filepath.Join(dir, "config.json"),
		Data: models.JldapData{
			AdminUsersCN: "admins",
			BaseDN:       baseDN,
			Groups:       []models.JldapGroup{adminGroup},
		},
	}

	if err := cs.RemoveUserFromAdmin("alice"); err != nil {
		t.Fatalf("RemoveUserFromAdmin returned error: %v", err)
	}

	if len(cs.Data.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(cs.Data.Groups))
	}
	g := cs.Data.Groups[0]

	if len(g.MemberUID) != 1 || !stringsEqualIgnoreCase(g.MemberUID[0], "bob") {
		t.Fatalf("expected MemberUID to contain only 'bob', got %#v", g.MemberUID)
	}
	expectedDN := "uid=bob,ou=users," + baseDN
	if len(g.Member) != 1 || !stringsEqualIgnoreCase(g.Member[0], expectedDN) {
		t.Fatalf("expected Member to contain only %q, got %#v", expectedDN, g.Member)
	}
}

/*
TestListUsers_ConcurrentAccess verifies that ListUsers can be safely
called concurrently with writers mutating the underlying store via
AddUser. It starts multiple goroutines repeatedly calling ListUsers
while other goroutines call AddUser, and asserts that the test completes
without panic and with the expected number of users added.
Run with -race to explicitly check for data races.
*/
func TestListUsers_ConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	cs := &ConfigStore{
		Path: filepath.Join(dir, "config.json"),
		Data: models.JldapData{
			BaseDN: "dc=example,dc=com",
		},
	}

	const (
		numReaders = 10
		numWriters = 5
		readLoops  = 500
		writeLoops = 100
	)

	var wg sync.WaitGroup
	wg.Add(numReaders + numWriters)

	// Readers: repeatedly call ListUsers concurrently.
	for r := 0; r < numReaders; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < readLoops; i++ {
				users := cs.ListUsers()

				// Perform a trivial read of the returned slice to ensure it is usable.
				// Also mutate the returned slice to further exercise the copy semantics.
				if len(users) > 0 {
					_ = users[0].UID
					users[0].UID = "does-not-affect-store"
				}
			}
		}()
	}

	// Writers: concurrently add users using AddUser (which takes a write lock).
	for w := 0; w < numWriters; w++ {
		go func(writerID int) {
			defer wg.Done()
			for i := 0; i < writeLoops; i++ {
				uid := fmt.Sprintf("user-%d-%d", writerID, i)
				if err := cs.AddUser(models.JldapUser{UID: uid}); err != nil {
					t.Errorf("AddUser returned error: %v", err)
					return
				}
			}
		}(w)
	}

	wg.Wait()

	// After all writers complete, we should have at least numWriters*writeLoops users.
	users := cs.ListUsers()
	if len(users) < numWriters*writeLoops {
		t.Fatalf("expected at least %d users, got %d", numWriters*writeLoops, len(users))
	}
}

/*
TestListGroups_ConcurrentAccess verifies that ListGroups can be safely
called concurrently with writers mutating the underlying store via
AddGroup. It starts several goroutines repeatedly calling ListGroups
while other goroutines call AddGroup, and asserts that the test completes
without panic and that groups have been added as expected.
Run with -race to explicitly check for data races.
*/
func TestListGroups_ConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	cs := &ConfigStore{
		Path: filepath.Join(dir, "config.json"),
		Data: models.JldapData{},
	}

	const (
		numReaders = 10
		numWriters = 5
		readLoops  = 500
		writeLoops = 100
	)

	var wg sync.WaitGroup
	wg.Add(numReaders + numWriters)

	// Readers: repeatedly call ListGroups concurrently.
	for r := 0; r < numReaders; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < readLoops; i++ {
				grps := cs.ListGroups()

				// Trivial read and mutation of the returned slice to exercise copying.
				if len(grps) > 0 {
					_ = grps[0].CN
					grps[0].CN = "does-not-affect-store"
				}
			}
		}()
	}

	// Writers: concurrently add groups using AddGroup (which takes a write lock).
	for w := 0; w < numWriters; w++ {
		go func(writerID int) {
			defer wg.Done()
			for i := 0; i < writeLoops; i++ {
				cn := fmt.Sprintf("group-%d-%d", writerID, i)
				g := models.JldapGroup{
					CN:        cn,
					GIDNumber: fmt.Sprintf("%d", i),
				}
				if err := cs.AddGroup(g); err != nil {
					t.Errorf("AddGroup returned error: %v", err)
					return
				}
			}
		}(w)
	}

	wg.Wait()

	// After all writers complete, we should have at least numWriters*writeLoops groups.
	grps := cs.ListGroups()
	if len(grps) < numWriters*writeLoops {
		t.Fatalf("expected at least %d groups, got %d", numWriters*writeLoops, len(grps))
	}
}

// --- small helpers used only in tests ---

func stringsEqualIgnoreCase(a, b string) bool {
	if len(a) != len(b) {
		// quick path, but still rely on case-insensitive check to be precise
	}
	return stringsEqualFold(a, b)
}

func stringsEqualFold(a, b string) bool {
	// re-use strings.EqualFold via a small wrapper so we don't have to bring
	// it into every test body.
	return strings.EqualFold(a, b)
}
