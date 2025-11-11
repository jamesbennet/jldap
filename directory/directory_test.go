package directory

import (
	"bytes"
	"log"
	"sort"
	"strings"
	"sync"
	"testing"
)

// --- helpers ---

func mustGet(t *testing.T, d *Directory, dn string) *Entry {
	t.Helper()
	e := d.Get(dn)
	if e == nil {
		t.Fatalf("expected entry %q, got nil", dn)
	}
	return e
}

func stringSlicesEqualIgnoreOrder(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

// --- attrs tests ---

// TestAttrs_Basic
// Ensures that attrs() correctly:
//   - lowercases keys
//   - groups multiple values under same key
//   - handles common LDAP attributes
func TestAttrs_Basic(t *testing.T) {
	m := attrs(
		"Cn", "Alice",
		"cn", "Bob",
		"UID", "alice",
	)

	if len(m) != 2 {
		t.Fatalf("expected 2 keys, got %d (%v)", len(m), m)
	}

	if got := m["cn"]; len(got) != 2 || got[0] != "Alice" || got[1] != "Bob" {
		t.Fatalf("expected cn=[Alice Bob], got %v", got)
	}
	if got := m["uid"]; len(got) != 1 || got[0] != "alice" {
		t.Fatalf("expected uid=[alice], got %v", got)
	}
}

// --- NewDirectory / Add / Get / indexes ---

// TestNewDirectory_InitialStructure
// Verifies that NewDirectory:
//   - creates root, ou=users, ou=groups
//   - populates parent/child relationships correctly
//   - normalizes DN lookups case-insensitively
func TestNewDirectory_InitialStructure(t *testing.T) {
	base := "dc=example,dc=com"
	d := NewDirectory(base)

	if d.BaseDN != base {
		t.Fatalf("BaseDN = %q, want %q", d.BaseDN, base)
	}

	// It should have at least the three initial entries (root + users + groups).
	if len(d.ByDN) != 3 {
		t.Fatalf("expected 3 initial entries in ByDN, got %d", len(d.ByDN))
	}

	// Root entry must be retrievable case-insensitively.
	root := d.Get("DC=EXAMPLE,DC=COM")
	if root == nil {
		t.Fatalf("expected root entry, got nil")
	}
	if root.DN != base {
		t.Fatalf("root DN = %q, want %q", root.DN, base)
	}

	// Check that ou=users and ou=groups exist and have correct parent.
	usersDN := "ou=users," + base
	groupsDN := "ou=groups," + base

	users := d.Get(usersDN)
	if users == nil {
		t.Fatalf("expected %q entry, got nil", usersDN)
	}
	if users.Parent != base {
		t.Fatalf("users.Parent = %q, want %q", users.Parent, base)
	}

	groups := d.Get(groupsDN)
	if groups == nil {
		t.Fatalf("expected %q entry, got nil", groupsDN)
	}
	if groups.Parent != base {
		t.Fatalf("groups.Parent = %q, want %q", groups.Parent, base)
	}

	// Root children should include ou=users and ou=groups (case-sensitive DNs as stored).
	if len(root.Children) != 2 {
		t.Fatalf("root.Children len = %d, want 2", len(root.Children))
	}
	wantChildren := []string{usersDN, groupsDN}
	if !stringSlicesEqualIgnoreOrder(root.Children, wantChildren) {
		t.Fatalf("root.Children = %v, want same elements as %v", root.Children, wantChildren)
	}
}

// TestDirectory_AddAndGet_CaseInsensitive
// Ensures that Add() stores DNs lowercased internally and Get() resolves case-insensitive lookups.
// Also confirms parent.Children is updated with the original (unmodified) DN.
func TestDirectory_AddAndGet_CaseInsensitive(t *testing.T) {
	base := "dc=example,dc=com"
	d := NewDirectory(base)

	e := &Entry{
		DN:     "uid=Alice,ou=users," + base,
		Parent: "ou=users," + base,
		Attrs:  attrs("uid", "Alice"),
	}
	d.Add(e)

	// Should be retrievable with different case.
	got := d.Get("UID=alice,OU=USERS," + base)
	if got == nil {
		t.Fatalf("expected entry, got nil")
	}
	if got.DN != e.DN {
		t.Fatalf("got.DN = %q, want %q", got.DN, e.DN)
	}

	// Parent's Children should contain the original DN.
	parent := mustGet(t, d, e.Parent)
	if len(parent.Children) != 1 || parent.Children[0] != e.DN {
		t.Fatalf("parent.Children = %v, want [%q]", parent.Children, e.DN)
	}
}

// TestDirectory_Add_IndexesByUIDAndCN
// Ensures Add() populates:
//   - ByUID index (lowercased)
//   - byCN index for multiple CN values
//   - multi-entry CN groups (non-unique CNs)
func TestDirectory_Add_IndexesByUIDAndCN(t *testing.T) {
	base := "dc=example,dc=com"
	d := NewDirectory(base)

	e1 := &Entry{
		DN:     "uid=alice,ou=users," + base,
		Parent: "ou=users," + base,
		Attrs:  attrs("uid", "Alice", "cn", "Alice", "cn", "A. Smith"),
	}
	d.Add(e1)

	e2 := &Entry{
		DN:     "uid=bob,ou=users," + base,
		Parent: "ou=users," + base,
		Attrs:  attrs("uid", "bob", "cn", "Alice"), // same CN as e1
	}
	d.Add(e2)

	// ByUID should be lowercased uid -> lowercased DN.
	if gotDN, ok := d.ByUID["alice"]; !ok {
		t.Fatalf("expected ByUID to contain 'alice'")
	} else if gotDN != "uid=alice,ou=users,"+base {
		t.Fatalf("ByUID['alice'] = %q, want %q", gotDN, "uid=alice,ou=users,"+base)
	}

	// CN index: "alice" should map to both e1 and e2.
	cnKey := "alice"
	cns, ok := d.byCN[cnKey]
	if !ok {
		t.Fatalf("expected cn index for %q", cnKey)
	}
	want := []string{
		"uid=alice,ou=users," + base,
		"uid=bob,ou=users," + base,
	}
	if !stringSlicesEqualIgnoreOrder(cns, want) {
		t.Fatalf("byCN[%q] = %v, want same elements as %v", cnKey, cns, want)
	}

	// CN index for "a. smith" should have only e1.
	if cns, ok := d.byCN["a. smith"]; !ok {
		t.Fatalf("expected cn index for %q", "a. smith")
	} else if len(cns) != 1 || cns[0] != "uid=alice,ou=users,"+base {
		t.Fatalf("byCN['a. smith'] = %v, want [%q]", cns, "uid=alice,ou=users,"+base)
	}
}

// TestDirectory_Add_MissingParent_DoesNotPanic
// Add() should tolerate a missing parent DN gracefully, updating only the indexes that exist.
// The entry should *still* be present in ByDN.
func TestDirectory_Add_MissingParent_DoesNotPanic(t *testing.T) {
	base := "dc=example,dc=com"
	d := NewDirectory(base)

	// Parent DN does not exist in directory; should not panic.
	e := &Entry{
		DN:     "uid=ghost,ou=nowhere," + base,
		Parent: "ou=nowhere," + base,
		Attrs:  attrs("uid", "ghost"),
	}
	d.Add(e)

	// Entry should still be in ByDN.
	if got := d.Get(e.DN); got == nil {
		t.Fatalf("expected to retrieve entry even with missing parent")
	}
}

// --- Subtree / ChildrenOf ---

// TestDirectory_Subtree_DepthFirstPreorder
// Verifies that Subtree() returns:
//   - preorder depth-first traversal
//   - including the starting DN
//   - with correct recursive descent
func TestDirectory_Subtree_DepthFirstPreorder(t *testing.T) {
	base := "dc=example,dc=com"
	d := NewDirectory(base)

	// Build a small tree:
	// ou=users,base
	//   ou=engineering,ou=users,base
	//     uid=alice,ou=engineering,ou=users,base
	usersDN := "ou=users," + base
	engDN := "ou=engineering," + usersDN

	eng := &Entry{
		DN:     engDN,
		Parent: usersDN,
		Attrs:  attrs("objectClass", "organizationalUnit", "ou", "engineering"),
	}
	d.Add(eng)

	user := &Entry{
		DN:     "uid=alice," + engDN,
		Parent: engDN,
		Attrs:  attrs("uid", "alice"),
	}
	d.Add(user)

	sub := d.Subtree(usersDN)
	if sub == nil {
		t.Fatalf("expected non-nil subtree slice")
	}

	// Expect preorder: users, engineering, alice
	if len(sub) != 3 {
		t.Fatalf("expected 3 entries in subtree, got %d", len(sub))
	}
	if sub[0].DN != usersDN {
		t.Fatalf("sub[0].DN = %q, want %q", sub[0].DN, usersDN)
	}
	if sub[1].DN != engDN {
		t.Fatalf("sub[1].DN = %q, want %q", sub[1].DN, engDN)
	}
	if sub[2].DN != user.DN {
		t.Fatalf("sub[2].DN = %q, want %q", sub[2].DN, user.DN)
	}
}

// TestDirectory_Subtree_UnknownDN
// Ensures Subtree() returns nil for non-existent DNs (not an empty slice).
func TestDirectory_Subtree_UnknownDN(t *testing.T) {
	base := "dc=example,dc=com"
	d := NewDirectory(base)

	if got := d.Subtree("cn=missing," + base); got != nil {
		t.Fatalf("expected nil for unknown DN subtree, got %#v", got)
	}
}

// TestDirectory_Subtree_SkipsMissingChildEntries
// Ensures Subtree():
//   - ignores child DNs not present in ByDN
//   - never panics
//   - returns correct count despite corrupted Children[]
func TestDirectory_Subtree_SkipsMissingChildEntries(t *testing.T) {
	base := "dc=example,dc=com"
	d := NewDirectory(base)

	rootDN := base
	root := mustGet(t, d, rootDN)

	// Initial subtree should contain: root, ou=users, ou=groups
	initial := d.Subtree(rootDN)
	if len(initial) != 3 {
		t.Fatalf("expected 3 entries in initial subtree (root + users + groups), got %d", len(initial))
	}

	// Add a real child under the root
	childDN := "uid=alice," + rootDN
	child := &Entry{
		DN:     childDN,
		Parent: rootDN,
		Attrs:  attrs("uid", "alice"),
	}
	d.Add(child)

	subWithChild := d.Subtree(rootDN)
	if len(subWithChild) != 4 {
		t.Fatalf("expected 4 entries in subtree after adding child, got %d", len(subWithChild))
	}

	// Now corrupt root.Children with a bogus DN that does not exist in ByDN
	root.Children = append(root.Children, "uid=missing,"+rootDN)

	subWithBogus := d.Subtree(rootDN)
	// Missing child should be silently skipped; count must remain 4
	if len(subWithBogus) != 4 {
		t.Fatalf("expected 4 entries in subtree even with missing child DN, got %d", len(subWithBogus))
	}

	// Ensure the real child is still present
	foundChild := false
	for _, e := range subWithBogus {
		if e.DN == childDN {
			foundChild = true
			break
		}
	}
	if !foundChild {
		t.Fatalf("expected subtree to still contain real child %q", childDN)
	}
}

// TestDirectory_ChildrenOf
// Ensures ChildrenOf():
//   - returns only existing children
//   - in insertion order
//   - never returns nil for valid parent
func TestDirectory_ChildrenOf(t *testing.T) {
	base := "dc=example,dc=com"
	d := NewDirectory(base)

	parentDN := "ou=users," + base

	c1 := &Entry{
		DN:     "uid=alice," + parentDN,
		Parent: parentDN,
		Attrs:  attrs("uid", "alice"),
	}
	d.Add(c1)

	c2 := &Entry{
		DN:     "uid=bob," + parentDN,
		Parent: parentDN,
		Attrs:  attrs("uid", "bob"),
	}
	d.Add(c2)

	children := d.ChildrenOf(parentDN)
	if children == nil {
		t.Fatalf("expected non-nil slice for existing parent")
	}
	if len(children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(children))
	}
	// order should match the order added to parent.Children
	if children[0].DN != c1.DN || children[1].DN != c2.DN {
		t.Fatalf("children order = [%q, %q], want [%q, %q]",
			children[0].DN, children[1].DN, c1.DN, c2.DN)
	}
}

// TestDirectory_ChildrenOf_UnknownDN
// Ensures that ChildrenOf() returns nil for unknown DNs.
func TestDirectory_ChildrenOf_UnknownDN(t *testing.T) {
	base := "dc=example,dc=com"
	d := NewDirectory(base)

	if got := d.ChildrenOf("cn=missing," + base); got != nil {
		t.Fatalf("expected nil for unknown DN ChildrenOf, got %#v", got)
	}
}

// TestDirectory_ChildrenOf_SkipsMissingChildEntries
// Ensures that ChildrenOf():
//   - gracefully ignores missing child DNs
//   - returns only valid children
func TestDirectory_ChildrenOf_SkipsMissingChildEntries(t *testing.T) {
	base := "dc=example,dc=com"
	d := NewDirectory(base)

	parentDN := "ou=users," + base

	c1 := &Entry{
		DN:     "uid=alice," + parentDN,
		Parent: parentDN,
		Attrs:  attrs("uid", "alice"),
	}
	d.Add(c1)

	// Inject a bogus child DN that is not present in ByDN
	parent := mustGet(t, d, parentDN)
	parent.Children = append(parent.Children, "uid=missing,"+parentDN)

	children := d.ChildrenOf(parentDN)
	if len(children) != 1 {
		t.Fatalf("expected 1 valid child, got %d", len(children))
	}
	if children[0].DN != c1.DN {
		t.Fatalf("expected only child %q, got %q", c1.DN, children[0].DN)
	}
}

// --- MemberOf ---

// TestDirectory_MemberOf_ByDNAndUID_NoDuplicates
// Ensures MemberOf():
//   - matches membership via DN in "member"
//   - matches membership via UID in "memberUid"
//   - treats DN and UID matching case-insensitively
//   - deduplicates groups referenced by both methods
func TestDirectory_MemberOf_ByDNAndUID_NoDuplicates(t *testing.T) {
	base := "dc=example,dc=com"
	d := NewDirectory(base)

	usersDN := "ou=users," + base
	groupsDN := "ou=groups," + base

	// User
	user := &Entry{
		DN:     "uid=alice," + usersDN,
		Parent: usersDN,
		Attrs:  attrs("uid", "Alice", "cn", "Alice"),
	}
	d.Add(user)

	// Group referencing user by DN
	g1 := &Entry{
		DN:     "cn=team1," + groupsDN,
		Parent: groupsDN,
		Attrs:  attrs("cn", "team1", "member", user.DN),
	}
	d.Add(g1)

	// Group referencing user by UID (different case)
	g2 := &Entry{
		DN:     "cn=team2," + groupsDN,
		Parent: groupsDN,
		Attrs:  attrs("cn", "team2", "memberUid", "ALICE"),
	}
	d.Add(g2)

	// Group referencing both DN (different case) and UID;
	// user should still see this group only once.
	g3 := &Entry{
		DN:     "cn=team3," + groupsDN,
		Parent: groupsDN,
		Attrs: attrs(
			"cn", "team3",
			"member", "UID=ALICE,"+usersDN, // different case DN
			"memberUid", "alice",
		),
	}
	d.Add(g3)

	memberOf := d.MemberOf(user.DN)
	if memberOf == nil {
		t.Fatalf("expected non-nil memberOf slice")
	}

	want := []string{g1.DN, g2.DN, g3.DN}
	if !stringSlicesEqualIgnoreOrder(memberOf, want) {
		t.Fatalf("MemberOf(%q) = %v, want same elements as %v", user.DN, memberOf, want)
	}
}

// TestDirectory_MemberOf_UnknownDN
// If the target DN does not exist, MemberOf() must return nil (not empty slice).
func TestDirectory_MemberOf_UnknownDN(t *testing.T) {
	base := "dc=example,dc=com"
	d := NewDirectory(base)

	if got := d.MemberOf("uid=missing,ou=users," + base); got != nil {
		t.Fatalf("expected nil for unknown DN, got %#v", got)
	}
}

// TestDirectory_MemberOf_NoUIDInEntry_UsesDNOnly
// Ensures that entries WITHOUT a uid attribute:
//   - still match "member" (DN-based membership)
//   - but NEVER match "memberUid"
//
// Entry has no UID: membership is resolved only via DN, not memberUid.
func TestDirectory_MemberOf_NoUIDInEntry_UsesDNOnly(t *testing.T) {
	base := "dc=example,dc=com"
	d := NewDirectory(base)

	usersDN := "ou=users," + base
	groupsDN := "ou=groups," + base

	user := &Entry{
		DN:     "cn=nuid," + usersDN,
		Parent: usersDN,
		Attrs:  attrs("cn", "NoUIDUser"),
	}
	d.Add(user)

	// Group referencing the user by DN
	g1 := &Entry{
		DN:     "cn=bydn," + groupsDN,
		Parent: groupsDN,
		Attrs:  attrs("cn", "bydn", "member", user.DN),
	}
	d.Add(g1)

	// Group referencing some UID, but user does not have uid attribute
	g2 := &Entry{
		DN:     "cn=byuid," + groupsDN,
		Parent: groupsDN,
		Attrs:  attrs("cn", "byuid", "memberUid", "nouid"),
	}
	d.Add(g2)

	memberOf := d.MemberOf(user.DN)
	// Only DN-based group should appear.
	if len(memberOf) != 1 || memberOf[0] != g1.DN {
		t.Fatalf("MemberOf(no-uid user) = %v, want [%q]", memberOf, g1.DN)
	}
}

// TestDirectory_MemberOf_UIDButNoMatchingGroups
// Ensures that a user WITH a UID but no matching groups:
//   - returns an EMPTY slice
//   - not nil, because the user *exists*
//
// Entry has UID, but no groups match either DN or UID; result should be empty.
func TestDirectory_MemberOf_UIDButNoMatchingGroups(t *testing.T) {
	base := "dc=example,dc=com"
	d := NewDirectory(base)

	usersDN := "ou=users," + base
	groupsDN := "ou=groups," + base

	user := &Entry{
		DN:     "uid=alice," + usersDN,
		Parent: usersDN,
		Attrs:  attrs("uid", "alice"),
	}
	d.Add(user)

	// Group that references a different DN and UID
	g1 := &Entry{
		DN:     "cn=other," + groupsDN,
		Parent: groupsDN,
		Attrs: attrs(
			"cn", "other",
			"member", "uid=bob,"+usersDN,
			"memberUid", "bob",
		),
	}
	d.Add(g1)

	memberOf := d.MemberOf(user.DN)
	if len(memberOf) != 0 {
		t.Fatalf("expected empty membership for non-matching groups, got %v", memberOf)
	}
}

// --- DirStore ---

// TestDirStore_GetSet_Basic
// Ensures atomic DirStore:
//   - initializes nil
//   - returns stored *Directory pointer
//   - overwrites correctly
func TestDirStore_GetSet_Basic(t *testing.T) {
	var s DirStore

	// zero value should return nil
	if got := s.Get(); got != nil {
		t.Fatalf("expected nil from zero-value DirStore.Get, got %#v", got)
	}

	d1 := NewDirectory("dc=example,dc=com")
	s.Set(d1)

	got := s.Get()
	if got == nil {
		t.Fatalf("expected non-nil directory after Set")
	}
	if got != d1 {
		t.Fatalf("Get() = %p, want %p", got, d1)
	}

	// Overwrite with a different directory
	d2 := NewDirectory("dc=other,dc=com")
	s.Set(d2)
	got = s.Get()
	if got != d2 {
		t.Fatalf("Get() after overwrite = %p, want %p", got, d2)
	}
}

// TestDirStore_ConcurrentAccess_NoPanics
// Stress test ensuring DirStore operations remain safe under:
//   - simultaneous writers calling Set()
//   - many readers calling Get()
//   - no panics, races, or corrupt data
func TestDirStore_ConcurrentAccess_NoPanics(t *testing.T) {
	var s DirStore

	d := NewDirectory("dc=example,dc=com")
	s.Set(d)

	var wg sync.WaitGroup
	const readers = 50
	const writers = 10

	// Writers swap directories
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			dir := NewDirectory("dc=example" + string(rune('a'+i)) + ",dc=com")
			s.Set(dir)
		}(i)
	}

	// Readers read repeatedly
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				got := s.Get()
				// should always be either nil or a *Directory; type assertion is in Get, so
				// just ensure we don't panic and basic field is accessible.
				if got != nil && got.ByDN == nil {
					t.Errorf("Get() returned directory with nil ByDN")
				}
			}
		}()
	}

	wg.Wait()
}

// --- firstDC ---

// TestFirstDC_Extraction
// Ensures firstDC():
//   - correctly extracts first dc= value
//   - handles case-insensitivity
//   - ignores other DN components
//   - trims whitespace
func TestFirstDC_Extraction(t *testing.T) {
	tests := []struct {
		base string
		want string
	}{
		{"dc=example,dc=com", "example"},
		{"DC=Example,dc=com", "Example"},
		{"ou=users,dc=example,dc=com", "example"},
		{" cn=foo, dc=bar , dc=baz ", "bar"},
	}

	for _, tt := range tests {
		if got := firstDC(tt.base); got != tt.want {
			t.Fatalf("firstDC(%q) = %q, want %q", tt.base, got, tt.want)
		}
	}
}

// TestFirstDC_Fallback
// Ensures that if no dc= components exist, firstDC() returns "homelab".
func TestFirstDC_Fallback(t *testing.T) {
	tests := []string{
		"ou=users,ou=people",
		"cn=foo,ou=bar",
		"",
	}

	for _, base := range tests {
		if got := firstDC(base); got != "homelab" {
			t.Fatalf("firstDC(%q) = %q, want %q", base, got, "homelab")
		}
	}
}

// TestAttrs_OddLength_LogsAndIgnoresLast verifies that attrs() handles an
// odd number of string arguments by logging a warning and ignoring the
// final unmatched key instead of panicking, while still parsing the valid
// key/value pairs before it.
func TestAttrs_OddLength_LogsAndIgnoresLast(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	// Odd length: "cn", "Alice", "uid" (uid has no value)
	m := attrs("cn", "Alice", "uid")

	// "cn" should still be present
	vals, ok := m["cn"]
	if !ok {
		t.Fatalf(`expected key "cn" to be present`)
	}
	if len(vals) != 1 || vals[0] != "Alice" {
		t.Fatalf(`unexpected value for "cn": %#v`, vals)
	}

	// "uid" should be ignored
	if _, ok := m["uid"]; ok {
		t.Fatalf(`expected key "uid" to be ignored for odd-length input`)
	}

	// Log should mention that we ignored the last element
	if !strings.Contains(buf.String(), "ignoring last.") {
		t.Fatalf("expected log output to mention 'ignoring last.', got: %q", buf.String())
	}
}

func TestAttrs_OddLength_IgnoresLastElement(t *testing.T) {
	// Capture log output.
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	m := attrs("cn", "Alice", "uid") // odd number: "uid" has no value

	// Expect that we still got the "cn" key
	vals, ok := m["cn"]
	if !ok {
		t.Fatalf(`expected key "cn" to be present`)
	}
	if len(vals) != 1 || vals[0] != "Alice" {
		t.Fatalf(`unexpected value for "cn": %#v`, vals)
	}

	// And that no key "uid" was created.
	if _, ok := m["uid"]; ok {
		t.Fatalf(`expected key "uid" to be ignored for odd-length input`)
	}

	// Check that the log message mentions ignoring last.
	logOutput := buf.String()
	if !strings.Contains(logOutput, "ignoring last.") {
		t.Fatalf("expected log output to mention 'ignoring last.', got: %q", logOutput)
	}
}

// TestAttrs_SingleElement_ReturnsEmptyMapButLogs ensures that attrs() called
// with a single string (no value to pair with it) returns an empty map and
// logs a warning indicating that the final element was ignored.
func TestAttrs_SingleElement_ReturnsEmptyMapButLogs(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	// Odd length = 1
	m := attrs("cn") // just one element, nothing to pair it with

	if len(m) != 0 {
		t.Fatalf("expected empty map for single-element attrs, got %#v", m)
	}

	if !strings.Contains(buf.String(), "ignoring last.") {
		t.Fatalf("expected log output to mention 'ignoring last.' for single element")
	}
}

// TestSubtree_IgnoresCycles verifies that Directory.Subtree handles cyclic
// Parent/Children relationships safely by tracking visited DNs and
// preventing infinite recursion, returning each reachable entry exactly once
// even when cycles exist in the directory graph.
func TestSubtree_IgnoresCycles(t *testing.T) {
	d := &Directory{
		ByDN:  make(map[string]*Entry),
		ByUID: make(map[string]string),
	}

	// Create two entries with a cycle:
	// root -> child -> root
	root := &Entry{
		DN:       "dc=example,dc=com",
		Parent:   "",
		Children: []string{"cn=child,dc=example,dc=com"},
		Attrs:    attrs("cn", "root"),
	}

	child := &Entry{
		DN:       "cn=child,dc=example,dc=com",
		Parent:   "dc=example,dc=com",
		Children: []string{"dc=example,dc=com"}, // cycle back to root
		Attrs:    attrs("cn", "child"),
	}

	d.ByDN[strings.ToLower(root.DN)] = root
	d.ByDN[strings.ToLower(child.DN)] = child

	subtree := d.Subtree(root.DN)

	if len(subtree) != 2 {
		t.Fatalf("expected subtree to contain exactly 2 entries, got %d", len(subtree))
	}

	// Ensure each DN appears only once
	seen := make(map[string]bool)
	for _, e := range subtree {
		ldn := strings.ToLower(e.DN)
		if seen[ldn] {
			t.Fatalf("entry %q appeared more than once in subtree", e.DN)
		}
		seen[ldn] = true
	}

	if !seen[strings.ToLower(root.DN)] || !seen[strings.ToLower(child.DN)] {
		t.Fatalf("subtree missing root or child entries, got %#v", subtree)
	}
}
