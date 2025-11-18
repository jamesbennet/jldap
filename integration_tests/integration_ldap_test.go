package integration_tests

import (
	"crypto/tls"
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

/*
NOTE: go-ldap does not provide a high-level SASL helper out-of-the-box. So we do NOT test SASL PLAIN bind.
*/

const (
	ldapHost     = "127.0.0.1"
	ldapPort     = 1389
	ldapsPort    = 1636
	baseDN       = "dc=homelab,dc=lan"
	bindDN       = "uid=jbennet,ou=users,dc=homelab,dc=lan"
	bindPassword = "password1234"
	testUserUID  = "jbennet"
	testUserUID2 = "potato"
	testGroupCN1 = "homelab_admins"
	testGroupCN2 = "homelab_users"
)

// Helper: connect to plain LDAP
func dialLDAP(t *testing.T) *ldap.Conn {
	t.Helper()
	addr := fmt.Sprintf("%s:%d", ldapHost, ldapPort)
	conn, err := ldap.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to dial LDAP %s: %v", addr, err)
	}
	return conn
}

// Helper: connect to LDAPS
func dialLDAPS(t *testing.T) *ldap.Conn {
	t.Helper()
	addr := fmt.Sprintf("%s:%d", ldapHost, ldapsPort)
	conn, err := ldap.DialTLS("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // OK for tests; use proper validation in prod
	})
	if err != nil {
		t.Fatalf("failed to dial LDAPS %s: %v", addr, err)
	}
	return conn
}

// Helper: search for a filter and assert at least one entry exists
func mustFindAtLeastOne(t *testing.T, conn *ldap.Conn, filter string) {
	t.Helper()

	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	res, err := conn.Search(searchReq)
	if err != nil {
		t.Fatalf("search %q failed: %v", filter, err)
	}
	if len(res.Entries) == 0 {
		t.Fatalf("search %q returned no entries", filter)
	}
}

// Helper: assert users & groups we expect are present
func assertUsersAndGroups(t *testing.T, conn *ldap.Conn) {
	t.Helper()

	// Users: uid=jbennet, uid=potato
	mustFindAtLeastOne(t, conn, fmt.Sprintf("(uid=%s)", testUserUID))
	mustFindAtLeastOne(t, conn, fmt.Sprintf("(uid=%s)", testUserUID2))

	// Groups: cn=homelab_admins, cn=homelab_users
	mustFindAtLeastOne(t, conn, fmt.Sprintf("(cn=%s)", testGroupCN1))
	mustFindAtLeastOne(t, conn, fmt.Sprintf("(cn=%s)", testGroupCN2))
}

// Helper: assert that a write operation failed (because server is read-only)
func assertReadOnlyFailure(t *testing.T, opName string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s unexpectedly succeeded on a read-only server", opName)
	}
	if ldapErr, ok := err.(*ldap.Error); ok {
		if ldapErr.ResultCode == ldap.LDAPResultSuccess {
			t.Fatalf("%s returned LDAP success on a read-only server", opName)
		}
		// Otherwise non-success is exactly what we want.
	}
}

// Helper: case-insensitive slice contains
func containsCI(xs []string, want string) bool {
	wantLower := strings.ToLower(want)
	for _, x := range xs {
		if strings.ToLower(x) == wantLower {
			return true
		}
	}
	return false
}

// Helper: check if an entry has attr with a specific value
func containsStringAttr(e *ldap.Entry, attr, want string) bool {
	for _, v := range e.GetAttributeValues(attr) {
		if v == want {
			return true
		}
	}
	return false
}

// Helper: check if an entry has a given attribute at all
func containsAttr(e *ldap.Entry, attr string) bool {
	for _, a := range e.Attributes {
		if a.Name == attr {
			return true
		}
	}
	return false
}

// Helper: check if an LDAP error is "unwillingToPerform"
func isUnwillingToPerform(err error) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*ldap.Error); ok {
		return e.ResultCode == ldap.LDAPResultUnwillingToPerform
	}
	return false
}

// --- Tests ---

// 1) Anonymous bind + search over plain LDAP
func TestAnonymousBindAndSearch_LDAP(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	// Some servers require an explicit anonymous bind; if yours does not,
	// this call can be omitted.
	if err := conn.UnauthenticatedBind(""); err != nil {
		t.Fatalf("anonymous/unauthenticated bind failed: %v", err)
	}

	// Check that we can at least see the expected entries
	assertUsersAndGroups(t, conn)
}

// 2) Simple bind with DN over plain LDAP
func TestSimpleBindAndSearch_LDAP(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("simple bind failed for %s: %v", bindDN, err)
	}

	assertUsersAndGroups(t, conn)
}

// 3) STARTTLS + simple bind + search
func TestStartTLS_SimpleBindAndSearch(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.StartTLS(&tls.Config{
		InsecureSkipVerify: true, // test-only
	}); err != nil {
		t.Fatalf("StartTLS failed: %v", err)
	}

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("simple bind after StartTLS failed for %s: %v", bindDN, err)
	}

	assertUsersAndGroups(t, conn)
}

// 4) LDAPS direct connect + simple bind + search
func TestLDAPS_SimpleBindAndSearch(t *testing.T) {
	conn := dialLDAPS(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("simple bind over LDAPS failed for %s: %v", bindDN, err)
	}

	assertUsersAndGroups(t, conn)
}

// 5) Invalid credentials must fail
func TestSimpleBind_InvalidCredentialsFails(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	err := conn.Bind(bindDN, "wrong-password")
	if err == nil {
		t.Fatalf("bind with invalid credentials unexpectedly succeeded")
	}
	if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultSuccess {
		t.Fatalf("bind with invalid credentials returned LDAP success")
	}
}

// 6) Read-only: Add operation must fail
func TestReadOnly_AddFails(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("simple bind failed for %s: %v", bindDN, err)
	}

	targetDN := "uid=integration_test_user,ou=users," + baseDN

	addReq := ldap.NewAddRequest(targetDN, nil)
	addReq.Attribute("objectClass", []string{"inetOrgPerson"})
	addReq.Attribute("sn", []string{"Test"})
	addReq.Attribute("cn", []string{"Integration Test User"})

	err := conn.Add(addReq)
	assertReadOnlyFailure(t, "Add", err)
}

// 7) Read-only: Modify operation must fail
func TestReadOnly_ModifyFails(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("simple bind failed for %s: %v", bindDN, err)
	}

	// Try to modify an existing user (jbennet)
	targetDN := "uid=" + testUserUID + ",ou=users," + baseDN

	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Replace("description", []string{"this must not be written"})

	err := conn.Modify(modReq)
	assertReadOnlyFailure(t, "Modify", err)
}

// 8) Read-only: Delete operation must fail
func TestReadOnly_DeleteFails(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("simple bind failed for %s: %v", bindDN, err)
	}

	// Try to delete an existing user (potato)
	targetDN := "uid=" + testUserUID2 + ",ou=users," + baseDN

	delReq := ldap.NewDelRequest(targetDN, nil)
	err := conn.Del(delReq)
	assertReadOnlyFailure(t, "Delete", err)
}

// 9) Read-only: ModifyDN (rename/move) must fail
func TestReadOnly_ModifyDNFails(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("simple bind failed for %s: %v", bindDN, err)
	}

	// Try to rename the "potato" user
	targetDN := "uid=" + testUserUID2 + ",ou=users," + baseDN
	newRDN := "uid=" + testUserUID2 + "-renamed"

	modDNReq := ldap.NewModifyDNRequest(
		targetDN,
		newRDN,
		true, // delete old RDN
		"",   // same parent
	)

	err := conn.ModifyDN(modDNReq)
	assertReadOnlyFailure(t, "ModifyDN", err)
}

func TestReadOnly_AddReturnsUnwillingToPerform(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("simple bind failed for %s: %v", bindDN, err)
	}

	targetDN := "uid=integration_test_user_codecheck,ou=users," + baseDN
	addReq := ldap.NewAddRequest(targetDN, nil)
	addReq.Attribute("objectClass", []string{"inetOrgPerson"})
	addReq.Attribute("sn", []string{"Temp"})
	addReq.Attribute("cn", []string{"Temp User"})

	err := conn.Add(addReq)
	if !isUnwillingToPerform(err) {
		t.Fatalf("expected Add to fail with unwillingToPerform, got %v", err)
	}
}

// --- FILTER TESTS: present, equality, AND, OR, NOT, substring, any ---

func TestSearch_Filters(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	t.Run("Present", func(t *testing.T) {
		req := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(uid=*)",
			[]string{"uid"},
			nil,
		)
		res, err := conn.Search(req)
		if err != nil {
			t.Fatalf("present filter search failed: %v", err)
		}
		if len(res.Entries) < 2 {
			t.Fatalf("expected at least 2 uid entries, got %d", len(res.Entries))
		}
	})

	t.Run("Equality", func(t *testing.T) {
		req := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf("(uid=%s)", testUserUID),
			[]string{"uid"},
			nil,
		)
		res, err := conn.Search(req)
		if err != nil {
			t.Fatalf("equality filter search failed: %v", err)
		}
		if len(res.Entries) == 0 {
			t.Fatalf("expected at least 1 entry for uid=%s", testUserUID)
		}
	})

	t.Run("AND", func(t *testing.T) {
		filter := fmt.Sprintf("(&(objectClass=*)(uid=%s))", testUserUID)
		req := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			filter,
			[]string{"uid"},
			nil,
		)
		res, err := conn.Search(req)
		if err != nil {
			t.Fatalf("AND filter search failed: %v", err)
		}
		if len(res.Entries) == 0 {
			t.Fatalf("expected at least 1 entry for filter %q", filter)
		}
	})

	t.Run("OR", func(t *testing.T) {
		filter := fmt.Sprintf("(|(uid=%s)(uid=%s))", testUserUID, testUserUID2)
		req := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			filter,
			[]string{"uid"},
			nil,
		)
		res, err := conn.Search(req)
		if err != nil {
			t.Fatalf("OR filter search failed: %v", err)
		}
		if len(res.Entries) < 2 {
			t.Fatalf("expected at least 2 entries for filter %q, got %d", filter, len(res.Entries))
		}
	})

	t.Run("NOT", func(t *testing.T) {
		// NOT used as a sub-filter; logically equivalent to equality but exercises NOT.
		filter := fmt.Sprintf("(&(!(uid=nonexistent))(uid=%s))", testUserUID)
		req := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			filter,
			[]string{"uid"},
			nil,
		)
		res, err := conn.Search(req)
		if err != nil {
			t.Fatalf("NOT filter search failed: %v", err)
		}
		if len(res.Entries) == 0 {
			t.Fatalf("expected at least 1 entry for filter %q", filter)
		}
	})

	t.Run("Substring", func(t *testing.T) {
		filter := "(uid=jb*)"
		req := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			filter,
			[]string{"uid"},
			nil,
		)
		res, err := conn.Search(req)
		if err != nil {
			t.Fatalf("substring filter search failed: %v", err)
		}
		found := false
		for _, e := range res.Entries {
			if e.GetAttributeValue("uid") == testUserUID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected to find uid=%s with substring filter %q", testUserUID, filter)
		}
	})

	t.Run("Any", func(t *testing.T) {
		// "Any" here: match any of multiple conditions (uid or cn).
		filter := fmt.Sprintf("(|(uid=%s)(cn=%s))", testUserUID, testGroupCN1)
		req := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			filter,
			[]string{"uid", "cn"},
			nil,
		)
		res, err := conn.Search(req)
		if err != nil {
			t.Fatalf("multi-branch OR (any) filter search failed: %v", err)
		}
		if len(res.Entries) < 2 {
			t.Fatalf("expected at least 2 entries (user+group) for filter %q, got %d",
				filter, len(res.Entries))
		}
	})
}

// --- SEARCH SCOPES: baseObject, singleLevel, wholeSubtree ---

func TestSearch_Scopes(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	userDN := fmt.Sprintf("uid=%s,ou=users,%s", testUserUID, baseDN)

	t.Run("BaseObject", func(t *testing.T) {
		req := ldap.NewSearchRequest(
			userDN,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"uid"},
			nil,
		)
		res, err := conn.Search(req)
		if err != nil {
			t.Fatalf("baseObject scope search failed: %v", err)
		}
		if len(res.Entries) != 1 {
			t.Fatalf("expected exactly 1 entry for baseObject, got %d", len(res.Entries))
		}
		if res.Entries[0].DN != userDN {
			t.Fatalf("expected DN %q, got %q", userDN, res.Entries[0].DN)
		}
	})

	t.Run("SingleLevelAndWholeSubtree", func(t *testing.T) {
		usersBase := "ou=users," + baseDN

		// Single level under ou=users
		reqOne := ldap.NewSearchRequest(
			usersBase,
			ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
			"(uid=*)",
			[]string{"uid"},
			nil,
		)
		resOne, err := conn.Search(reqOne)
		if err != nil {
			t.Fatalf("single-level scope search failed: %v", err)
		}
		if len(resOne.Entries) == 0 {
			t.Fatalf("expected some entries with uid under %s", usersBase)
		}

		// Whole subtree from baseDN
		reqSub := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(uid=*)",
			[]string{"uid"},
			nil,
		)
		resSub, err := conn.Search(reqSub)
		if err != nil {
			t.Fatalf("wholeSubtree scope search failed: %v", err)
		}
		if len(resSub.Entries) < len(resOne.Entries) {
			t.Fatalf("expected wholeSubtree to return >= singleLevel entries, got %d vs %d",
				len(resSub.Entries), len(resOne.Entries))
		}
	})
}

// --- RootDSE and cn=subschema special cases ---

func TestRootDSE_Search(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	// RootDSE: base="", scope=baseObject
	req := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"*", "+"}, // all user + operational attributes
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("RootDSE search failed: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("expected exactly 1 RootDSE entry, got %d", len(res.Entries))
	}
	if res.Entries[0].DN != "" {
		t.Fatalf("expected RootDSE DN to be empty string, got %q", res.Entries[0].DN)
	}
}

func TestRootDSE_Attributes(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	req := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"namingcontexts", "supportedldapversion", "supportedsaslmechanisms"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("RootDSE attribute search failed: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("expected exactly 1 RootDSE entry, got %d", len(res.Entries))
	}
	e := res.Entries[0]

	// implementation: namingcontexts contains BaseDN, supportedldapversion contains "3",
	// supportedsaslmechanisms is present (PLAIN may be advertised). :contentReference[oaicite:2]{index=2} :contentReference[oaicite:3]{index=3}
	if !containsStringAttr(e, "namingcontexts", baseDN) {
		t.Fatalf("RootDSE.namingcontexts does not contain %q", baseDN)
	}
	if !containsStringAttr(e, "supportedldapversion", "3") {
		t.Fatalf("RootDSE.supportedldapversion does not contain 3")
	}
	if !containsAttr(e, "supportedsaslmechanisms") {
		t.Fatalf("expected RootDSE to expose supportedsaslmechanisms")
	}
}

func TestSubschema_Search(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	req := ldap.NewSearchRequest(
		"cn=subschema",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"objectClasses", "attributeTypes", "ldapSyntaxes"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("cn=subschema search failed: %v", err)
	}
	if len(res.Entries) == 0 {
		t.Fatalf("expected at least 1 subschema entry")
	}
}

// --- Attribute selection, 1.1 (no attributes), computed memberOf ---

func TestSearch_AttributeSelection(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	userDN := fmt.Sprintf("uid=%s,ou=users,%s", testUserUID, baseDN)

	t.Run("SpecificAttributes", func(t *testing.T) {
		req := ldap.NewSearchRequest(
			userDN,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"uid", "cn"},
			nil,
		)
		res, err := conn.Search(req)
		if err != nil {
			t.Fatalf("attribute selection search failed: %v", err)
		}
		if len(res.Entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(res.Entries))
		}
		e := res.Entries[0]
		if e.GetAttributeValue("uid") == "" {
			t.Fatalf("uid attribute missing in selected attributes")
		}
		if e.GetAttributeValue("cn") == "" {
			t.Fatalf("cn attribute missing in selected attributes")
		}
	})

	t.Run("NoAttributes_1_1", func(t *testing.T) {
		req := ldap.NewSearchRequest(
			userDN,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"1.1"}, // special: return no attributes
			nil,
		)
		res, err := conn.Search(req)
		if err != nil {
			t.Fatalf("1.1 attribute-only search failed: %v", err)
		}
		if len(res.Entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(res.Entries))
		}
		if len(res.Entries[0].Attributes) != 0 {
			t.Fatalf("expected 0 attributes for 1.1 selection, got %d",
				len(res.Entries[0].Attributes))
		}
	})

	t.Run("TypesOnly", func(t *testing.T) {
		req := ldap.NewSearchRequest(
			userDN,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			0, 0,
			true, // typesOnly = true
			"(objectClass=*)",
			[]string{"uid", "cn"},
			nil,
		)
		res, err := conn.Search(req)
		if err != nil {
			t.Fatalf("typesOnly search failed: %v", err)
		}
		if len(res.Entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(res.Entries))
		}
		e := res.Entries[0]
		for _, a := range e.Attributes {
			if len(a.Values) != 0 {
				t.Fatalf("expected no values for attribute %s in typesOnly mode, got %v", a.Name, a.Values)
			}
		}
	})
}

func TestComputedMemberOf(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	userDN := fmt.Sprintf("uid=%s,ou=users,%s", testUserUID, baseDN)

	req := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"memberof"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("memberof search failed: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(res.Entries))
	}

	values := res.Entries[0].GetAttributeValues("memberof")
	if len(values) == 0 {
		t.Fatalf("expected computed memberof values, got none")
	}

	var hasAdmins, hasUsers bool
	for _, v := range values {
		if strings.Contains(strings.ToLower(v), strings.ToLower(testGroupCN1)) {
			hasAdmins = true
		}
		if strings.Contains(strings.ToLower(v), strings.ToLower(testGroupCN2)) {
			hasUsers = true
		}
	}
	if !hasAdmins {
		t.Fatalf("expected memberof to contain %q", testGroupCN1)
	}
	if !hasUsers {
		t.Fatalf("expected memberof to contain %q", testGroupCN2)
	}
}

// --- Compare operation ---

func TestCompare(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	userDN := fmt.Sprintf("uid=%s,ou=users,%s", testUserUID, baseDN)

	ok, err := conn.Compare(userDN, "uid", testUserUID)
	if err != nil {
		t.Fatalf("compare (true) failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected compare(uid=%s) to be true", testUserUID)
	}

	ok, err = conn.Compare(userDN, "uid", testUserUID2)
	if err != nil {
		t.Fatalf("compare (false) failed: %v", err)
	}
	if ok {
		t.Fatalf("expected compare(uid=%s) to be false for value %q", testUserUID, testUserUID2)
	}
}

// --- Unbind ---

func TestUnbind(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	if err := conn.Unbind(); err != nil {
		t.Fatalf("unbind failed: %v", err)
	}

	// After Unbind, connection should be closed and operations should fail.
	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)
	_, err := conn.Search(req)
	if err == nil {
		t.Fatalf("expected search after unbind to fail, but it succeeded")
	}
}

// Unsupported ExtendedRequest OID must return UnwillingToPerform.
func TestExtended_UnsupportedOID_UnwillingToPerform(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	req := ldap.NewExtendedRequest("1.2.3.4.5.6.7", nil)
	res, err := conn.Extended(req)

	// We don't actually care about res here; an error is expected.
	_ = res

	if err == nil {
		t.Fatalf("expected Extended request with unsupported OID to fail, but got nil error")
	}

	ldapErr, ok := err.(*ldap.Error)
	if !ok {
		t.Fatalf("expected *ldap.Error from Extended, got %T (%v)", err, err)
	}
	if ldapErr.ResultCode != ldap.LDAPResultUnwillingToPerform {
		t.Fatalf("expected LDAPResultUnwillingToPerform, got %v", ldapErr.ResultCode)
	}
}

// A search with a control attached should still work (controls are ignored by the server).
func TestSearch_WithControl_Ignored(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(uid=*)",
		[]string{"uid"},
		nil,
	)

	// Use a standard paging control purely to exercise the controls path.
	paging := ldap.NewControlPaging(1)
	req.Controls = []ldap.Control{paging}

	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("search with control failed: %v", err)
	}
	if len(res.Entries) < 2 {
		t.Fatalf("expected search with control to return entries, got %d", len(res.Entries))
	}
}

// RootDSE must advertise namingcontexts, StartTLS extension and SASL PLAIN.
func TestRootDSE_AdvertisesCapabilities(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	req := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"namingcontexts", "supportedExtension", "supportedSASLMechanisms"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("RootDSE capabilities search failed: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("expected exactly 1 RootDSE entry, got %d", len(res.Entries))
	}
	e := res.Entries[0]

	naming := e.GetAttributeValues("namingcontexts")
	if len(naming) == 0 || naming[0] != baseDN {
		t.Fatalf("expected namingcontexts to contain %q, got %v", baseDN, naming)
	}

	exts := e.GetAttributeValues("supportedextension")
	// StartTLS OID from session.go
	const startTLSOID = "1.3.6.1.4.1.1466.20037"
	if !containsCI(exts, startTLSOID) {
		t.Fatalf("expected supportedExtension to advertise StartTLS OID %q, got %v", startTLSOID, exts)
	}

	mechs := e.GetAttributeValues("supportedsaslmechanisms")
	if !containsCI(mechs, "PLAIN") {
		t.Fatalf("expected supportedsaslmechanisms to contain PLAIN, got %v", mechs)
	}
}

// When typesOnly=true, attributes should be present but have no values.
func TestSearch_TypesOnlyAttributes(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	userDN := fmt.Sprintf("uid=%s,ou=users,%s", testUserUID, baseDN)

	req := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, true, // typesOnly = true
		"(objectClass=*)",
		[]string{"uid", "cn"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("typesOnly search failed: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(res.Entries))
	}

	attrs := res.Entries[0].Attributes
	if len(attrs) == 0 {
		t.Fatalf("expected attributes to be returned (types only), got none")
	}
	for _, a := range attrs {
		if len(a.Values) != 0 {
			t.Fatalf("expected no values for attribute %q when typesOnly=true, got %v", a.Name, a.Values)
		}
	}
}

// Compare on a non-existent DN should return NoSuchObject.
func TestCompare_NoSuchDN(t *testing.T) {
	conn := dialLDAP(t)
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	missingDN := fmt.Sprintf("uid=does-not-exist,ou=users,%s", baseDN)

	ok, err := conn.Compare(missingDN, "uid", "whatever")
	if err == nil {
		t.Fatalf("expected compare on missing DN to return an error")
	}
	if ok {
		t.Fatalf("expected compare result to be false for missing DN")
	}

	ldapErr, okErr := err.(*ldap.Error)
	if !okErr {
		t.Fatalf("expected *ldap.Error, got %T (%v)", err, err)
	}
	if ldapErr.ResultCode != ldap.LDAPResultNoSuchObject {
		t.Fatalf("expected LDAPResultNoSuchObject, got %v", ldapErr.ResultCode)
	}
}
