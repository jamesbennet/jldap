package ldap

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"jldap/ber"
	"jldap/directory"
)

/*
memConn is an in-memory net.Conn implementation used for testing.
It buffers what is written to it and reads from an internal buffer.
*/
type memConn struct {
	readBuf  bytes.Buffer
	writeBuf bytes.Buffer
	closed   bool
}

func (c *memConn) Read(b []byte) (int, error)  { return c.readBuf.Read(b) }
func (c *memConn) Write(b []byte) (int, error) { return c.writeBuf.Write(b) }
func (c *memConn) Close() error {
	c.closed = true
	return nil
}
func (c *memConn) LocalAddr() net.Addr                { return dummyAddr("local") }
func (c *memConn) RemoteAddr() net.Addr               { return dummyAddr("remote") }
func (c *memConn) SetDeadline(t time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(t time.Time) error { return nil }

/*
dummyAddr is a trivial net.Addr implementation for memConn.
*/
type dummyAddr string

func (d dummyAddr) Network() string { return "mem" }
func (d dummyAddr) String() string  { return string(d) }

// ---- small helpers for decoding BER in tests ----

/*
decodeLDAPMessage decodes an outer LDAPMessage SEQUENCE from a byte slice
and returns the message ID and the protocolOp TLV.
*/
func decodeLDAPMessage(t *testing.T, packet []byte) (int, ber.BerTLV) {
	t.Helper()
	r := bytes.NewReader(packet)
	return decodeLDAPMessageFromReader(t, r)
}

/*
decodeLDAPMessageFromReader decodes one LDAPMessage SEQUENCE from an existing
bytes.Reader and returns the message ID and the protocolOp TLV.
*/
func decodeLDAPMessageFromReader(t *testing.T, r *bytes.Reader) (int, ber.BerTLV) {
	t.Helper()

	outer, err := ber.BerReadTLV(r)
	if err != nil {
		t.Fatalf("failed to read outer TLV: %v", err)
	}
	if outer.Tag != (ber.ClassUniversal | ber.PcConstructed | ber.TagSequence) {
		t.Fatalf("unexpected outer tag: 0x%X", outer.Tag)
	}

	rr := bytes.NewReader(outer.Value)
	idTLV, err := ber.BerReadTLV(rr)
	if err != nil {
		t.Fatalf("failed to read messageID TLV: %v", err)
	}
	if idTLV.Tag != (ber.ClassUniversal | ber.PcPrimitive | ber.TagInteger) {
		t.Fatalf("unexpected messageID tag: 0x%X", idTLV.Tag)
	}
	msgID := ber.BerDecodeInt(idTLV.Value)

	opTLV, err := ber.BerReadTLV(rr)
	if err != nil {
		t.Fatalf("failed to read protocolOp TLV: %v", err)
	}
	return msgID, opTLV
}

/*
decodeLDAPResult parses resultCode, matchedDN, diagnosticMessage from a
protocolOp TLV that contains a standard LDAPResult layout.
*/
func decodeLDAPResult(t *testing.T, op ber.BerTLV) (code int, matchedDN, diag string) {
	t.Helper()

	rr := bytes.NewReader(op.Value)

	codeTLV, err := ber.BerReadTLV(rr)
	if err != nil {
		t.Fatalf("failed to read resultCode: %v", err)
	}
	if codeTLV.Tag != (ber.ClassUniversal | ber.PcPrimitive | ber.TagEnum) {
		t.Fatalf("unexpected resultCode tag: 0x%X", codeTLV.Tag)
	}
	code = ber.BerDecodeInt(codeTLV.Value)

	mdnTLV, err := ber.BerReadTLV(rr)
	if err != nil {
		t.Fatalf("failed to read matchedDN: %v", err)
	}
	if mdnTLV.Tag != (ber.ClassUniversal | ber.PcPrimitive | ber.TagOctetString) {
		t.Fatalf("unexpected matchedDN tag: 0x%X", mdnTLV.Tag)
	}
	matchedDN = string(mdnTLV.Value)

	diagTLV, err := ber.BerReadTLV(rr)
	if err != nil {
		t.Fatalf("failed to read diagnosticMessage: %v", err)
	}
	if diagTLV.Tag != (ber.ClassUniversal | ber.PcPrimitive | ber.TagOctetString) {
		t.Fatalf("unexpected diagMessage tag: 0x%X", diagTLV.Tag)
	}
	diag = string(diagTLV.Value)

	return
}

// -----------------------------------------------------------------------------
// contains
// -----------------------------------------------------------------------------

/*
TestContains_FindsExistingValue verifies that the contains helper returns true
when the given slice contains the target string, in a case-insensitive way.
*/
func TestContains_FindsExistingValue(t *testing.T) {
	xs := []string{"foo", "BAR", "baz"}
	if !contains(xs, "bar") {
		t.Fatalf("expected contains(xs, \"bar\") to be true")
	}
}

/*
TestContains_DoesNotFindMissingValue verifies that contains returns false when
the target is not present in the slice.
*/
func TestContains_DoesNotFindMissingValue(t *testing.T) {
	xs := []string{"foo", "bar", "baz"}
	if contains(xs, "qux") {
		t.Fatalf("expected contains(xs, \"qux\") to be false")
	}
}

// -----------------------------------------------------------------------------
// errOr
// -----------------------------------------------------------------------------

/*
TestErrOr_PassesThroughError verifies that errOr simply returns the error
passed into it without modification.
*/
func TestErrOr_PassesThroughError(t *testing.T) {
	errSentinel := &testError{"boom"}
	if got := errOr(errSentinel); got != errSentinel {
		t.Fatalf("expected errOr to return the same error pointer")
	}
}

/*
testError is a simple error implementation used to test errOr.
*/
type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

// -----------------------------------------------------------------------------
// buildRootDSE
// -----------------------------------------------------------------------------

/*
TestBuildRootDSE_TLSSaslEnabled verifies that buildRootDSE:
- sets namingcontexts to BaseDN
- advertises StartTLS OID when TLS is enabled
- advertises SASL PLAIN when saslPLAIN is true.
*/
func TestBuildRootDSE_TLSSaslEnabled(t *testing.T) {
	d := &directory.Directory{
		BaseDN: "dc=example,dc=com",
	}

	root := buildRootDSE(d, true, true)

	if root.DN != "" {
		t.Fatalf("expected RootDSE DN to be empty, got %q", root.DN)
	}
	if !contains(root.Attrs["namingcontexts"], "dc=example,dc=com") {
		t.Fatalf("expected namingcontexts to contain base DN")
	}
	if !contains(root.Attrs["supportedextension"], startTLSOID) {
		t.Fatalf("expected supportedextension to contain StartTLS OID")
	}
	if !contains(root.Attrs["supportedsaslmechanisms"], "PLAIN") {
		t.Fatalf("expected supportedsaslmechanisms to contain PLAIN")
	}
}

/*
TestBuildRootDSE_NoTlsNoSasl verifies that when both tlsEnabled and saslPLAIN
are false, buildRootDSE does not advertise StartTLS nor SASL mechanisms.
*/
func TestBuildRootDSE_NoTlsNoSasl(t *testing.T) {
	d := &directory.Directory{
		BaseDN: "dc=example,dc=com",
	}

	root := buildRootDSE(d, false, false)

	if contains(root.Attrs["supportedextension"], startTLSOID) {
		t.Fatalf("expected StartTLS OID not to be advertised")
	}
	if len(root.Attrs["supportedsaslmechanisms"]) != 0 {
		t.Fatalf("expected no SASL mechanisms advertised")
	}
}

// -----------------------------------------------------------------------------
// buildSubschemaEntry
// -----------------------------------------------------------------------------

/*
TestBuildSubschemaEntry_BasicStructure verifies that buildSubschemaEntry
returns the expected DN and includes key schema attributes.
*/
func TestBuildSubschemaEntry_BasicStructure(t *testing.T) {
	e := buildSubschemaEntry()

	if e.DN != "cn=subschema" {
		t.Fatalf("expected DN 'cn=subschema', got %q", e.DN)
	}
	if !contains(e.Attrs["objectclass"], "subschema") {
		t.Fatalf("expected objectClass to include 'subschema'")
	}
	if _, ok := e.Attrs["attributetypes"]; !ok {
		t.Fatalf("expected attributetypes attribute to exist")
	}
	if _, ok := e.Attrs["objectclasses"]; !ok {
		t.Fatalf("expected objectclasses attribute to exist")
	}
}

// -----------------------------------------------------------------------------
// nearestExistingAncestor
// -----------------------------------------------------------------------------

/*
TestNearestExistingAncestor_FindsNearestParent verifies that
nearestExistingAncestor returns the closest existing ancestor DN.
*/
func TestNearestExistingAncestor_FindsNearestParent(t *testing.T) {
	base := "dc=example,dc=com"
	d := &directory.Directory{
		BaseDN: base,
		ByDN: map[string]*directory.Entry{
			strings.ToLower(base): {DN: base},
		},
	}

	got := nearestExistingAncestor(d, "cn=foo,"+base)
	if got != base {
		t.Fatalf("expected nearest ancestor %q, got %q", base, got)
	}
}

/*
TestNearestExistingAncestor_NoAncestorFound verifies that when no part of the
DN exists, nearestExistingAncestor returns an empty string.
*/
func TestNearestExistingAncestor_NoAncestorFound(t *testing.T) {
	d := &directory.Directory{
		BaseDN: "dc=example,dc=com",
		ByDN:   map[string]*directory.Entry{},
	}

	got := nearestExistingAncestor(d, "cn=foo,dc=example,dc=com")
	if got != "" {
		t.Fatalf("expected empty nearest ancestor, got %q", got)
	}
}

// -----------------------------------------------------------------------------
// writeLDAPMessage / writeBindResult / writeLDAPResult
// -----------------------------------------------------------------------------

/*
TestWriteLDAPMessage_EncodesSequenceAndMessageID verifies that writeLDAPMessage
wraps msgID and protocolOp into a proper LDAPMessage SEQUENCE.
*/
func TestWriteLDAPMessage_EncodesSequenceAndMessageID(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	protocolOp := ber.BerWrapApp(appBindResp, nil)
	const msgID = 7

	if err := s.writeLDAPMessage(msgID, protocolOp, nil); err != nil {
		t.Fatalf("writeLDAPMessage returned error: %v", err)
	}

	packet := conn.writeBuf.Bytes()
	if len(packet) == 0 {
		t.Fatalf("expected bytes to be written")
	}

	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
	}
	if opTLV.Tag&0x1F != appBindResp {
		t.Fatalf("expected appBindResp tag, got 0x%X", opTLV.Tag&0x1F)
	}
}

/*
TestWriteBindResult_SuccessCode verifies that writeBindResult emits a
BindResponse with the correct msgID and result code.
*/
func TestWriteBindResult_SuccessCode(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	const msgID = 3
	if err := s.writeBindResult(msgID, rcSuccess, "", ""); err != nil {
		t.Fatalf("writeBindResult returned error: %v", err)
	}

	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
	}
	if opTLV.Tag&0x1F != appBindResp {
		t.Fatalf("expected appBindResp tag, got 0x%X", opTLV.Tag&0x1F)
	}
	code, matched, diag := decodeLDAPResult(t, opTLV)
	if code != rcSuccess {
		t.Fatalf("expected rcSuccess, got %d", code)
	}
	if matched != "" || diag != "" {
		t.Fatalf("expected empty matched/diag, got %q / %q", matched, diag)
	}
}

/*
TestWriteLDAPResult_UsesAppTagAndCode verifies that writeLDAPResult encodes
generic LDAPResult with correct app tag, code, and strings.
*/
func TestWriteLDAPResult_UsesAppTagAndCode(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	const msgID = 4
	if err := s.writeLDAPResult(msgID, rcNoSuchObject, "dc=example,dc=com", "no such dn", appSearchDone); err != nil {
		t.Fatalf("writeLDAPResult returned error: %v", err)
	}

	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
	}
	if opTLV.Tag&0x1F != appSearchDone {
		t.Fatalf("expected appSearchDone tag, got 0x%X", opTLV.Tag&0x1F)
	}
	code, matched, diag := decodeLDAPResult(t, opTLV)
	if code != rcNoSuchObject {
		t.Fatalf("expected rcNoSuchObject, got %d", code)
	}
	if matched != "dc=example,dc=com" || diag != "no such dn" {
		t.Fatalf("unexpected matched/diag: %q / %q", matched, diag)
	}
}

// -----------------------------------------------------------------------------
// handleBind – simple bind and SASL bind
// -----------------------------------------------------------------------------

/*
TestHandleBind_AnonymousBindSuccess verifies that an anonymous simple bind
(empty DN and empty password) succeeds and clears s.bindDN.
*/
func TestHandleBind_AnonymousBindSuccess(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	var body bytes.Buffer
	body.Write(ber.BerWrapInteger(3))                // version
	body.Write(ber.BerWrapString(""))                // name
	body.Write(ber.BerWrapCtx(0, []byte(""), false)) // simple auth, empty password
	const msgID = 1

	if err := s.handleBind(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleBind returned error: %v", err)
	}
	if s.bindDN != "" {
		t.Fatalf("expected bindDN to be empty for anonymous bind, got %q", s.bindDN)
	}

	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
	}
	code, _, _ := decodeLDAPResult(t, opTLV)
	if code != rcSuccess {
		t.Fatalf("expected rcSuccess, got %d", code)
	}
}

/*
TestHandleBind_SimpleBindSuccess verifies that a normal simple bind with a
DN and matching userpassword attribute succeeds.
*/
func TestHandleBind_SimpleBindSuccess(t *testing.T) {
	conn := &memConn{}

	d := directory.NewDirectory("dc=example,dc=com")
	userDN := "uid=jdoe,ou=users,dc=example,dc=com"
	d.Add(&directory.Entry{
		DN: userDN,
		Attrs: map[string][]string{
			"userpassword": {"secret"},
		},
		Parent: "ou=users,dc=example,dc=com",
	})
	store := &directory.DirStore{}
	store.Set(d)

	s := &Session{Conn: conn, Store: store}

	var body bytes.Buffer
	body.Write(ber.BerWrapInteger(3))
	body.Write(ber.BerWrapString(userDN))
	body.Write(ber.BerWrapCtx(0, []byte("secret"), false))

	const msgID = 6
	if err := s.handleBind(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleBind returned error: %v", err)
	}
	if s.bindDN != userDN {
		t.Fatalf("expected bindDN %q, got %q", userDN, s.bindDN)
	}
	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
	}
	code, _, _ := decodeLDAPResult(t, opTLV)
	if code != rcSuccess {
		t.Fatalf("expected rcSuccess, got %d", code)
	}
}

/*
TestHandleBind_SimpleBindInvalidPassword verifies that an incorrect password
returns rcInvalidCredentials.
*/
func TestHandleBind_SimpleBindInvalidPassword(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	userDN := "uid=jdoe,ou=users,dc=example,dc=com"
	d.Add(&directory.Entry{
		DN: userDN,
		Attrs: map[string][]string{
			"userpassword": {"secret"},
		},
		Parent: "ou=users,dc=example,dc=com",
	})
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	var body bytes.Buffer
	body.Write(ber.BerWrapInteger(3))
	body.Write(ber.BerWrapString(userDN))
	body.Write(ber.BerWrapCtx(0, []byte("wrong"), false))

	const msgID = 7
	if err := s.handleBind(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleBind returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcInvalidCredentials {
		t.Fatalf("expected rcInvalidCredentials, got %d", code)
	}
	if diag != "invalid credentials" {
		t.Fatalf("unexpected diag: %q", diag)
	}
}

/*
buildSASLPlainAuthTLV constructs the SASL [3] auth choice TLV for mechanism PLAIN
with given mech and credentials.
*/
func buildSASLPlainAuthTLV(mech string, creds []byte) []byte {
	var inner bytes.Buffer
	inner.Write(ber.BerWrapString(mech))
	if creds != nil {
		inner.Write(ber.BerWrapString(string(creds)))
	}
	return ber.BerWrapCtx(3, inner.Bytes(), true)
}

/*
TestHandleBind_SASLPlain_WithBindName verifies SASL PLAIN where the DN comes
from BindRequest name (non-empty bindName).
*/
func TestHandleBind_SASLPlain_WithBindName(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	userDN := "uid=jdoe,ou=users,dc=example,dc=com"

	d.Add(&directory.Entry{
		DN: userDN,
		Attrs: map[string][]string{
			"userpassword": {"pw123"},
		},
		Parent: "ou=users,dc=example,dc=com",
	})
	store := &directory.DirStore{}
	store.Set(d)

	s := &Session{Conn: conn, Store: store}

	// PLAIN: authzid\0authcid\0password
	creds := []byte("\x00ignored\x00pw123")

	var body bytes.Buffer
	body.Write(ber.BerWrapInteger(3))
	body.Write(ber.BerWrapString(userDN))
	body.Write(buildSASLPlainAuthTLV("PLAIN", creds))

	const msgID = 8
	if err := s.handleBind(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleBind returned error: %v", err)
	}
	if s.bindDN != userDN {
		t.Fatalf("expected bindDN %q, got %q", userDN, s.bindDN)
	}
	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	code, _, _ := decodeLDAPResult(t, opTLV)
	if code != rcSuccess {
		t.Fatalf("expected rcSuccess, got %d", code)
	}
}

/*
TestHandleBind_SASLPlain_AuthcidDN verifies SASL PLAIN where the DN is taken
from authcid because it “looks like” a DN.
*/
func TestHandleBind_SASLPlain_AuthcidDN(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	userDN := "uid=jdoe,ou=users,dc=example,dc=com"

	d.Add(&directory.Entry{
		DN: userDN,
		Attrs: map[string][]string{
			"userpassword": {"pw123"},
		},
		Parent: "ou=users,dc=example,dc=com",
	})
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	// authzid="", authcid=userDN, password=pw123
	creds := []byte("\x00" + userDN + "\x00pw123")

	var body bytes.Buffer
	body.Write(ber.BerWrapInteger(3))
	body.Write(ber.BerWrapString("")) // no bindName
	body.Write(buildSASLPlainAuthTLV("PLAIN", creds))

	const msgID = 9
	if err := s.handleBind(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleBind returned error: %v", err)
	}
	if s.bindDN != userDN {
		t.Fatalf("expected bindDN %q, got %q", userDN, s.bindDN)
	}
}

/*
TestHandleBind_SASLPlain_AuthcidUID verifies SASL PLAIN where the DN is
resolved via ByUID from authcid.
*/
func TestHandleBind_SASLPlain_AuthcidUID(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	userDN := "uid=jdoe,ou=users,dc=example,dc=com"

	d.Add(&directory.Entry{
		DN: userDN,
		Attrs: map[string][]string{
			"uid":          {"jdoe"},
			"userpassword": {"pw123"},
		},
		Parent: "ou=users,dc=example,dc=com",
	})
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	// authzid="", authcid="jdoe", password=pw123
	creds := []byte("\x00jdoe\x00pw123")

	var body bytes.Buffer
	body.Write(ber.BerWrapInteger(3))
	body.Write(ber.BerWrapString("")) // no bindName
	body.Write(buildSASLPlainAuthTLV("PLAIN", creds))

	const msgID = 14
	if err := s.handleBind(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleBind returned error: %v", err)
	}
	if s.bindDN != userDN {
		t.Fatalf("expected bindDN %q, got %q", userDN, s.bindDN)
	}
}

/*
TestHandleBind_SASLPlain_UnknownAuthcid verifies that when no DN can be
resolved from authcid, handleBind returns rcInvalidCredentials with
"unknown authcid".
*/
func TestHandleBind_SASLPlain_UnknownAuthcid(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	store := &directory.DirStore{}
	store.Set(d)

	s := &Session{Conn: conn, Store: store}

	creds := []byte("\x00unknown\x00pw")

	var body bytes.Buffer
	body.Write(ber.BerWrapInteger(3))
	body.Write(ber.BerWrapString(""))
	body.Write(buildSASLPlainAuthTLV("PLAIN", creds))

	const msgID = 15
	if err := s.handleBind(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleBind returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcInvalidCredentials {
		t.Fatalf("expected rcInvalidCredentials, got %d", code)
	}
	if diag != "unknown authcid" {
		t.Fatalf("expected diag 'unknown authcid', got %q", diag)
	}
}

/*
TestHandleBind_SASLPlain_BadBlob verifies that malformed PLAIN blobs result
in rcInvalidCredentials with "bad PLAIN blob".
*/
func TestHandleBind_SASLPlain_BadBlob(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	creds := []byte("no-null-separators")

	var body bytes.Buffer
	body.Write(ber.BerWrapInteger(3))
	body.Write(ber.BerWrapString(""))
	body.Write(buildSASLPlainAuthTLV("PLAIN", creds))

	const msgID = 16
	if err := s.handleBind(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleBind returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcInvalidCredentials {
		t.Fatalf("expected rcInvalidCredentials, got %d", code)
	}
	if diag != "bad PLAIN blob" {
		t.Fatalf("expected diag 'bad PLAIN blob', got %q", diag)
	}
}

/*
TestHandleBind_SASLExternalNotSupported verifies SASL mechanism EXTERNAL is
rejected with rcAuthMethodNotSupported.
*/
func TestHandleBind_SASLExternalNotSupported(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	var inner bytes.Buffer
	inner.Write(ber.BerWrapString("EXTERNAL"))
	body := bytes.Buffer{}
	body.Write(ber.BerWrapInteger(3))
	body.Write(ber.BerWrapString(""))
	body.Write(ber.BerWrapCtx(3, inner.Bytes(), true))

	const msgID = 17
	if err := s.handleBind(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleBind returned error: %v", err)
	}

	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcAuthMethodNotSupported {
		t.Fatalf("expected rcAuthMethodNotSupported, got %d", code)
	}
	if diag != "SASL EXTERNAL not supported" {
		t.Fatalf("unexpected diag: %q", diag)
	}
}

/*
TestHandleBind_SASLUnsupportedMechanism verifies that any other SASL mechanism
is rejected with rcAuthMethodNotSupported and "unsupported SASL mechanism".
*/
func TestHandleBind_SASLUnsupportedMechanism(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	var inner bytes.Buffer
	inner.Write(ber.BerWrapString("GSSAPI"))
	body := bytes.Buffer{}
	body.Write(ber.BerWrapInteger(3))
	body.Write(ber.BerWrapString(""))
	body.Write(ber.BerWrapCtx(3, inner.Bytes(), true))

	const msgID = 18
	if err := s.handleBind(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleBind returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcAuthMethodNotSupported {
		t.Fatalf("expected rcAuthMethodNotSupported, got %d", code)
	}
	if diag != "unsupported SASL mechanism" {
		t.Fatalf("unexpected diag: %q", diag)
	}
}

/*
TestHandleBind_BadSASLMechanismTLV verifies that if the SASL mechanism TLV is
not an OCTET STRING, handleBind returns rcAuthMethodNotSupported with
"bad sasl mechanism".
*/
func TestHandleBind_BadSASLMechanismTLV(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	var inner bytes.Buffer
	inner.Write(ber.BerWrapInteger(5)) // bad tag for mechanism
	body := bytes.Buffer{}
	body.Write(ber.BerWrapInteger(3))
	body.Write(ber.BerWrapString(""))
	body.Write(ber.BerWrapCtx(3, inner.Bytes(), true))

	const msgID = 19
	if err := s.handleBind(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleBind returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcAuthMethodNotSupported {
		t.Fatalf("expected rcAuthMethodNotSupported, got %d", code)
	}
	if diag != "bad sasl mechanism" {
		t.Fatalf("unexpected diag: %q", diag)
	}
}

/*
TestHandleBind_BadVersionTagTriggersProtocolError verifies that if the
version field is not an INTEGER, handleBind returns rcProtocolError.
*/
func TestHandleBind_BadVersionTagTriggersProtocolError(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	var body bytes.Buffer
	body.Write(ber.BerWrapString("not-int"))
	body.Write(ber.BerWrapString(""))
	body.Write(ber.BerWrapCtx(0, []byte(""), false))
	const msgID = 2

	if err := s.handleBind(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleBind returned error: %v", err)
	}

	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
	}
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcProtocolError {
		t.Fatalf("expected rcProtocolError, got %d", code)
	}
	if diag != "bad bind version" {
		t.Fatalf("expected diag 'bad bind version', got %q", diag)
	}
}

/*
TestHandleBind_UnsupportedVersionReturnsProtocolError verifies that a version
different from 3 results in rcProtocolError.
*/
func TestHandleBind_UnsupportedVersionReturnsProtocolError(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	var body bytes.Buffer
	body.Write(ber.BerWrapInteger(2))
	body.Write(ber.BerWrapString("cn=foo"))
	body.Write(ber.BerWrapCtx(0, []byte("bar"), false))
	const msgID = 3

	if err := s.handleBind(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleBind returned error: %v", err)
	}

	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
	}
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcProtocolError {
		t.Fatalf("expected rcProtocolError, got %d", code)
	}
	if diag != "only LDAPv3 supported" {
		t.Fatalf("expected diag 'only LDAPv3 supported', got %q", diag)
	}
}

/*
TestHandleBind_BadNameTagTriggersProtocolError verifies that a bad name tag
results in rcProtocolError and "bad bind name".
*/
func TestHandleBind_BadNameTagTriggersProtocolError(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	var body bytes.Buffer
	body.Write(ber.BerWrapInteger(3))
	body.Write(ber.BerWrapInteger(42)) // bad name
	body.Write(ber.BerWrapCtx(0, []byte(""), false))
	const msgID = 4

	if err := s.handleBind(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleBind returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
	}
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcProtocolError {
		t.Fatalf("expected rcProtocolError, got %d", code)
	}
	if diag != "bad bind name" {
		t.Fatalf("expected diag 'bad bind name', got %q", diag)
	}
}

/*
TestHandleBind_BadAuthChoiceTriggersAuthMethodNotSupported verifies that when
auth choice isn't context-specific, rcAuthMethodNotSupported is returned.
*/
func TestHandleBind_BadAuthChoiceTriggersAuthMethodNotSupported(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	var body bytes.Buffer
	body.Write(ber.BerWrapInteger(3))
	body.Write(ber.BerWrapString(""))
	body.Write(ber.BerWrapString("x")) // wrong auth tag
	const msgID = 5

	if err := s.handleBind(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleBind returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
	}
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcAuthMethodNotSupported {
		t.Fatalf("expected rcAuthMethodNotSupported, got %d", code)
	}
	if diag != "bad auth choice - only simple bind supported" {
		t.Fatalf("unexpected diag: %q", diag)
	}
}

// -----------------------------------------------------------------------------
// handleExtended – StartTLS & unsupported
// -----------------------------------------------------------------------------

/*
TestHandleExtended_UnsupportedOIDReturnsUnwillingToPerform verifies that an
ExtendedRequest with unknown OID results in rcUnwillingToPerform.
*/
func TestHandleExtended_UnsupportedOIDReturnsUnwillingToPerform(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	body := ber.BerWrapCtx(0, []byte("1.2.3.4"), false)
	const msgID = 10

	if err := s.handleExtended(msgID, body); err != nil {
		t.Fatalf("handleExtended returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
	}
	if opTLV.Tag&0x1F != appExtendedResp {
		t.Fatalf("expected appExtendedResp tag, got 0x%X", opTLV.Tag&0x1F)
	}
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcUnwillingToPerform {
		t.Fatalf("expected rcUnwillingToPerform, got %d", code)
	}
	if diag != "extended op not supported" {
		t.Fatalf("expected diag 'extended op not supported', got %q", diag)
	}
}

/*
TestHandleExtended_StartTLS_NoTLSConfigRejects verifies that when StartTLS is
requested but TlsConfig is nil, rcUnwillingToPerform is returned.
*/
func TestHandleExtended_StartTLS_NoTLSConfigRejects(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn, TlsConfig: nil}

	body := ber.BerWrapCtx(0, []byte(startTLSOID), false)
	const msgID = 11

	if err := s.handleExtended(msgID, body); err != nil {
		t.Fatalf("handleExtended returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
	}
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcUnwillingToPerform {
		t.Fatalf("expected rcUnwillingToPerform, got %d", code)
	}
	if diag != "no TLS configured" {
		t.Fatalf("expected diag 'no TLS configured', got %q", diag)
	}
}

/*
TestHandleExtended_StartTLS_AlreadyActiveRejects verifies that when TLS is
already active, StartTLS is rejected with rcOperationsError.
*/
func TestHandleExtended_StartTLS_AlreadyActiveRejects(t *testing.T) {
	conn := &memConn{}
	s := &Session{
		Conn:      conn,
		TlsConfig: &tls.Config{},
		TlsActive: true,
	}

	body := ber.BerWrapCtx(0, []byte(startTLSOID), false)
	const msgID = 12

	if err := s.handleExtended(msgID, body); err != nil {
		t.Fatalf("handleExtended returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
	}
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcOperationsError {
		t.Fatalf("expected rcOperationsError, got %d", code)
	}
	if diag != "TLS already active" {
		t.Fatalf("expected diag 'TLS already active', got %q", diag)
	}
}

/*
TestHandleExtended_StartTLS_HandshakeErrorStillAttempts verifies that when
StartTLS is requested and the TLS handshake fails, handleExtended returns
an error (i.e. it actually attempted the handshake after sending success).
*/
func TestHandleExtended_StartTLS_HandshakeErrorStillAttempts(t *testing.T) {
	// memConn has an empty read buffer; TLS handshake will hit EOF quickly.
	conn := &memConn{}

	s := &Session{
		Conn:      conn,
		TlsConfig: &tls.Config{}, // non-nil so StartTLS path is taken
	}

	// ExtendedRequest body with StartTLS OID as requestName
	body := ber.BerWrapCtx(0, []byte(startTLSOID), false)
	const msgID = 13

	err := s.handleExtended(msgID, body)
	if err == nil {
		t.Fatalf("expected StartTLS handshake to fail and return an error")
	}

	// We also implicitly exercised the path that writes an ExtendedResponse
	// before attempting the handshake, since memConn.Write always succeeds.
	if conn.writeBuf.Len() == 0 {
		t.Fatalf("expected StartTLS success ExtendedResponse to be written before handshake failure")
	}
}

// -----------------------------------------------------------------------------
// handleCompare
// -----------------------------------------------------------------------------

/*
TestHandleCompare_TrueMatch verifies that handleCompare returns rcCompareTrue
when the value matches an attribute of the target entry.
*/
func TestHandleCompare_TrueMatch(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	userDN := "uid=jdoe,ou=users,dc=example,dc=com"
	d.Add(&directory.Entry{
		DN: userDN,
		Attrs: map[string][]string{
			"cn":  {"John Doe"},
			"foo": {"Bar"},
		},
		Parent: "ou=users,dc=example,dc=com",
	})
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	var ava bytes.Buffer
	ava.Write(ber.BerWrapString("foo"))
	ava.Write(ber.BerWrapString("bar"))

	body := bytes.Buffer{}
	body.Write(ber.BerWrapString(userDN))
	body.Write(ber.BerWrapSequence(ava.Bytes()))

	const msgID = 20
	if err := s.handleCompare(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleCompare returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
	}
	code, _, _ := decodeLDAPResult(t, opTLV)
	if code != rcCompareTrue {
		t.Fatalf("expected rcCompareTrue, got %d", code)
	}
}

/*
TestHandleCompare_FalseMatch verifies that handleCompare returns rcCompareFalse
when the attribute value does not match.
*/
func TestHandleCompare_FalseMatch(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	userDN := "uid=jdoe,ou=users,dc=example,dc=com"
	d.Add(&directory.Entry{
		DN: userDN,
		Attrs: map[string][]string{
			"foo": {"Bar"},
		},
		Parent: "ou=users,dc=example,dc=com",
	})
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	var ava bytes.Buffer
	ava.Write(ber.BerWrapString("foo"))
	ava.Write(ber.BerWrapString("baz"))

	body := bytes.Buffer{}
	body.Write(ber.BerWrapString(userDN))
	body.Write(ber.BerWrapSequence(ava.Bytes()))

	const msgID = 21
	if err := s.handleCompare(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleCompare returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	code, _, _ := decodeLDAPResult(t, opTLV)
	if code != rcCompareFalse {
		t.Fatalf("expected rcCompareFalse, got %d", code)
	}
}

/*
TestHandleCompare_NoSuchDN verifies that handleCompare returns rcNoSuchObject
when the target DN does not exist.
*/
func TestHandleCompare_NoSuchDN(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	var ava bytes.Buffer
	ava.Write(ber.BerWrapString("foo"))
	ava.Write(ber.BerWrapString("bar"))

	body := bytes.Buffer{}
	body.Write(ber.BerWrapString("uid=missing,ou=users,dc=example,dc=com"))
	body.Write(ber.BerWrapSequence(ava.Bytes()))

	const msgID = 22
	if err := s.handleCompare(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleCompare returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcNoSuchObject {
		t.Fatalf("expected rcNoSuchObject, got %d", code)
	}
	if diag != "no such DN" {
		t.Fatalf("unexpected diag: %q", diag)
	}
}

/*
TestHandleCompare_BadDNTagProtocolError verifies that a bad DN tag results in
rcProtocolError and "bad compare DN".
*/
func TestHandleCompare_BadDNTagProtocolError(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	body := bytes.Buffer{}
	body.Write(ber.BerWrapInteger(42)) // bad DN
	body.Write(ber.BerWrapSequence(nil))
	const msgID = 23

	if err := s.handleCompare(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleCompare returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcProtocolError {
		t.Fatalf("expected rcProtocolError, got %d", code)
	}
	if diag != "bad compare DN" {
		t.Fatalf("expected diag 'bad compare DN', got %q", diag)
	}
}

/*
TestHandleCompare_BadAVATagProtocolError verifies that a bad AVA SEQUENCE tag
results in rcProtocolError.
*/
func TestHandleCompare_BadAVATagProtocolError(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	body := bytes.Buffer{}
	body.Write(ber.BerWrapString("uid=jdoe,dc=example,dc=com"))
	body.Write(ber.BerWrapInteger(99)) // not SEQUENCE
	const msgID = 24

	if err := s.handleCompare(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleCompare returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcProtocolError {
		t.Fatalf("expected rcProtocolError, got %d", code)
	}
	if diag != "bad compare AVA" {
		t.Fatalf("expected diag 'bad compare AVA', got %q", diag)
	}
}

/*
TestHandleCompare_BadAttrOrValueTLVProtocolError verifies that bad attribute
or value TLVs in AVA cause rcProtocolError.
*/
func TestHandleCompare_BadAttrOrValueTLVProtocolError(t *testing.T) {
	// Bad attr
	{
		conn := &memConn{}
		s := &Session{Conn: conn}
		var seq bytes.Buffer
		seq.Write(ber.BerWrapInteger(1)) // bad attr tag
		seq.Write(ber.BerWrapString("v"))
		body := bytes.Buffer{}
		body.Write(ber.BerWrapString("cn=foo"))
		body.Write(ber.BerWrapSequence(seq.Bytes()))
		const msgID = 25
		if err := s.handleCompare(msgID, body.Bytes()); err != nil {
			t.Fatalf("handleCompare returned error: %v", err)
		}
		packet := conn.writeBuf.Bytes()
		_, opTLV := decodeLDAPMessage(t, packet)
		code, _, diag := decodeLDAPResult(t, opTLV)
		if code != rcProtocolError || diag != "bad compare attr" {
			t.Fatalf("expected bad compare attr, got code %d diag %q", code, diag)
		}
	}
	// Bad value
	{
		conn := &memConn{}
		s := &Session{Conn: conn}
		var seq bytes.Buffer
		seq.Write(ber.BerWrapString("attr"))
		seq.Write(ber.BerWrapInteger(5)) // bad value tag
		body := bytes.Buffer{}
		body.Write(ber.BerWrapString("cn=foo"))
		body.Write(ber.BerWrapSequence(seq.Bytes()))
		const msgID = 26
		if err := s.handleCompare(msgID, body.Bytes()); err != nil {
			t.Fatalf("handleCompare returned error: %v", err)
		}
		packet := conn.writeBuf.Bytes()
		_, opTLV := decodeLDAPMessage(t, packet)
		code, _, diag := decodeLDAPResult(t, opTLV)
		if code != rcProtocolError || diag != "bad compare value" {
			t.Fatalf("expected bad compare value, got code %d diag %q", code, diag)
		}
	}
}

// -----------------------------------------------------------------------------
// writeSearchEntry – attributes, memberOf, typesOnly, noAttrs
// -----------------------------------------------------------------------------

/*
TestWriteSearchEntry_ReturnAllWithMemberOf verifies that when all attributes
are requested, writeSearchEntry returns all entry attributes plus MemberOf.
*/
func TestWriteSearchEntry_ReturnAllWithMemberOf(t *testing.T) {
	conn := &memConn{}

	d := directory.NewDirectory("dc=example,dc=com")
	userDN := "uid=jdoe,ou=users,dc=example,dc=com"
	groupDN := "cn=devs,ou=groups,dc=example,dc=com"

	d.Add(&directory.Entry{
		DN: userDN,
		Attrs: map[string][]string{
			"uid":  {"jdoe"},
			"cn":   {"John Doe"},
			"mail": {"jdoe@example.com"},
		},
		Parent: "ou=users,dc=example,dc=com",
	})
	d.Add(&directory.Entry{
		DN: groupDN,
		Attrs: map[string][]string{
			"cn":     {"devs"},
			"member": {userDN},
		},
		Parent: "ou=groups,dc=example,dc=com",
	})

	store := &directory.DirStore{}
	store.Set(d)

	s := &Session{Conn: conn, Store: store}

	e := d.Get(userDN)
	const msgID = 30

	if err := s.writeSearchEntry(msgID, e, nil, false, false); err != nil {
		t.Fatalf("writeSearchEntry returned error: %v", err)
	}

	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
	}
	if opTLV.Tag&0x1F != appSearchResEntry {
		t.Fatalf("expected appSearchResEntry tag, got 0x%X", opTLV.Tag&0x1F)
	}

	rr := bytes.NewReader(opTLV.Value)
	dnTLV, err := ber.BerReadTLV(rr)
	if err != nil {
		t.Fatalf("failed reading entry DN: %v", err)
	}
	if string(dnTLV.Value) != userDN {
		t.Fatalf("expected DN %q, got %q", userDN, string(dnTLV.Value))
	}
	attrSeqTLV, err := ber.BerReadTLV(rr)
	if err != nil {
		t.Fatalf("failed reading attributes SEQUENCE: %v", err)
	}

	attrMap := map[string][]string{}
	ar := bytes.NewReader(attrSeqTLV.Value)
	for ar.Len() > 0 {
		aTLV, err := ber.BerReadTLV(ar)
		if err != nil {
			t.Fatalf("failed reading attribute: %v", err)
		}
		ar2 := bytes.NewReader(aTLV.Value)
		nameTLV, err := ber.BerReadTLV(ar2)
		if err != nil {
			t.Fatalf("failed reading attr name: %v", err)
		}
		name := string(nameTLV.Value)
		setTLV, err := ber.BerReadTLV(ar2)
		if err != nil {
			t.Fatalf("failed reading attr SET: %v", err)
		}
		var vals []string
		vr := bytes.NewReader(setTLV.Value)
		for vr.Len() > 0 {
			vTLV, err := ber.BerReadTLV(vr)
			if err != nil {
				t.Fatalf("failed reading attr value: %v", err)
			}
			vals = append(vals, string(vTLV.Value))
		}
		attrMap[name] = vals
	}

	if attrMap["uid"][0] != "jdoe" {
		t.Fatalf("expected uid=jdoe, got %#v", attrMap["uid"])
	}
	if len(attrMap["MemberOf"]) == 0 || attrMap["MemberOf"][0] != groupDN {
		t.Fatalf("expected MemberOf=%q, got %#v", groupDN, attrMap["MemberOf"])
	}
}

/*
TestWriteSearchEntry_RequestedAttrsOnly_NoMemberOf verifies that when only
specific attributes are requested, MemberOf is omitted unless requested.
*/
func TestWriteSearchEntry_RequestedAttrsOnly_NoMemberOf(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")

	userDN := "uid=jdoe,ou=users,dc=example,dc=com"
	d.Add(&directory.Entry{
		DN: userDN,
		Attrs: map[string][]string{
			"uid": {"jdoe"},
			"cn":  {"John Doe"},
		},
		Parent: "ou=users,dc=example,dc=com",
	})
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	e := d.Get(userDN)
	const msgID = 31

	if err := s.writeSearchEntry(msgID, e, []string{"cn"}, false, false); err != nil {
		t.Fatalf("writeSearchEntry returned error: %v", err)
	}

	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	rr := bytes.NewReader(opTLV.Value)
	_, _ = ber.BerReadTLV(rr) // DN
	attrSeqTLV, err := ber.BerReadTLV(rr)
	if err != nil {
		t.Fatalf("failed reading attributes: %v", err)
	}

	ar := bytes.NewReader(attrSeqTLV.Value)
	var names []string
	for ar.Len() > 0 {
		aTLV, err := ber.BerReadTLV(ar)
		if err != nil {
			t.Fatalf("failed reading attribute: %v", err)
		}
		ar2 := bytes.NewReader(aTLV.Value)
		nameTLV, err := ber.BerReadTLV(ar2)
		if err != nil {
			t.Fatalf("failed reading attr name: %v", err)
		}
		names = append(names, string(nameTLV.Value))
	}
	if len(names) != 1 || names[0] != "cn" {
		t.Fatalf("expected only 'cn' attr, got %#v", names)
	}
}

/*
TestWriteSearchEntry_TypesOnlyOmitsValues verifies that when typesOnly is
true, attribute values are omitted but the types are still present.
*/
func TestWriteSearchEntry_TypesOnlyOmitsValues(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")

	userDN := "uid=jdoe,ou=users,dc=example,dc=com"
	d.Add(&directory.Entry{
		DN: userDN,
		Attrs: map[string][]string{
			"uid": {"jdoe"},
			"cn":  {"John Doe"},
		},
		Parent: "ou=users,dc=example,dc=com",
	})
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	e := d.Get(userDN)
	const msgID = 32

	if err := s.writeSearchEntry(msgID, e, nil, true, false); err != nil {
		t.Fatalf("writeSearchEntry returned error: %v", err)
	}

	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	rr := bytes.NewReader(opTLV.Value)
	_, _ = ber.BerReadTLV(rr) // DN
	attrSeqTLV, err := ber.BerReadTLV(rr)
	if err != nil {
		t.Fatalf("failed reading attributes: %v", err)
	}
	ar := bytes.NewReader(attrSeqTLV.Value)
	for ar.Len() > 0 {
		aTLV, err := ber.BerReadTLV(ar)
		if err != nil {
			t.Fatalf("failed reading attribute: %v", err)
		}
		ar2 := bytes.NewReader(aTLV.Value)
		_, _ = ber.BerReadTLV(ar2)         // name
		setTLV, err := ber.BerReadTLV(ar2) // SET
		if err != nil {
			t.Fatalf("failed reading attr SET: %v", err)
		}
		if len(setTLV.Value) != 0 {
			t.Fatalf("expected empty SET for typesOnly, got %d bytes", len(setTLV.Value))
		}
	}
}

/*
TestWriteSearchEntry_NoAttrsSuppressesEverything verifies that when noAttrs is
true, no attributes are returned (including MemberOf).
*/
func TestWriteSearchEntry_NoAttrsSuppressesEverything(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")

	userDN := "uid=jdoe,ou=users,dc=example,dc=com"
	d.Add(&directory.Entry{
		DN: userDN,
		Attrs: map[string][]string{
			"uid": {"jdoe"},
			"cn":  {"John Doe"},
		},
		Parent: "ou=users,dc=example,dc=com",
	})
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}
	e := d.Get(userDN)
	const msgID = 33

	if err := s.writeSearchEntry(msgID, e, nil, false, true); err != nil {
		t.Fatalf("writeSearchEntry returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	rr := bytes.NewReader(opTLV.Value)
	_, _ = ber.BerReadTLV(rr)
	attrSeqTLV, err := ber.BerReadTLV(rr)
	if err != nil {
		t.Fatalf("failed reading attributes: %v", err)
	}
	if len(attrSeqTLV.Value) != 0 {
		t.Fatalf("expected no attributes, got %d bytes", len(attrSeqTLV.Value))
	}
}

// -----------------------------------------------------------------------------
// handleSearch – real paths using parseFilter
// -----------------------------------------------------------------------------

/*
buildBoolTLV creates a BER BOOLEAN TLV with the given truth value.
*/
func buildBoolTLV(v bool) []byte {
	b := byte(0x00)
	if v {
		b = 0xFF
	}
	return ber.BerWrapTLV(ber.ClassUniversal|ber.PcPrimitive|ber.TagBoolean, []byte{b})
}

/*
TestHandleSearch_BadBaseTagProtocolError verifies that a bad base tag
returns rcProtocolError "bad base".
*/
func TestHandleSearch_BadBaseTagProtocolError(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	body := bytes.Buffer{}
	body.Write(ber.BerWrapInteger(1)) // bad base
	body.Write(ber.BerWrapEnum(0))    // scope
	body.Write(ber.BerWrapEnum(0))    // deref
	body.Write(ber.BerWrapInteger(0)) // size
	body.Write(ber.BerWrapInteger(0)) // time
	body.Write(buildBoolTLV(false))   // typesOnly
	body.Write(ber.BerWrapString("")) // dummy filter

	const msgID = 40
	if err := s.handleSearch(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleSearch returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcProtocolError || diag != "bad base" {
		t.Fatalf("expected bad base protocol error, got code %d diag %q", code, diag)
	}
}

/*
TestHandleSearch_BadScopeTagProtocolError verifies that a bad scope tag
returns rcProtocolError "bad scope".
*/
func TestHandleSearch_BadScopeTagProtocolError(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	body := bytes.Buffer{}
	body.Write(ber.BerWrapString("")) // base
	body.Write(ber.BerWrapInteger(0)) // bad scope
	body.Write(ber.BerWrapEnum(0))    // deref
	body.Write(ber.BerWrapInteger(0)) // size
	body.Write(ber.BerWrapInteger(0)) // time
	body.Write(buildBoolTLV(false))
	body.Write(ber.BerWrapString(""))

	const msgID = 41
	if err := s.handleSearch(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleSearch returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcProtocolError || diag != "bad scope" {
		t.Fatalf("expected bad scope protocol error, got code %d diag %q", code, diag)
	}
}

/*
TestHandleSearch_RootDSE_BaseScope returns the RootDSE entry (base="" scope=0)
followed by a SearchResultDone success.
*/
func TestHandleSearch_RootDSE_BaseScope(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	store := &directory.DirStore{}
	store.Set(d)

	s := &Session{
		Conn:      conn,
		Store:     store,
		TlsConfig: &tls.Config{},
	}

	// base = "", scope=0 (baseObject)
	body := bytes.Buffer{}
	body.Write(ber.BerWrapString(""))
	body.Write(ber.BerWrapEnum(0))    // scope baseObject
	body.Write(ber.BerWrapEnum(0))    // deref
	body.Write(ber.BerWrapInteger(0)) // size
	body.Write(ber.BerWrapInteger(0)) // time
	body.Write(buildBoolTLV(false))   // typesOnly=false

	// filter: present(objectclass)
	filterTLV := ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcPrimitive|7, []byte("objectClass"))
	body.Write(filterTLV)

	const msgID = 42
	if err := s.handleSearch(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleSearch returned error: %v", err)
	}

	r := bytes.NewReader(conn.writeBuf.Bytes())

	// First message: SearchResultEntry
	mid1, op1 := decodeLDAPMessageFromReader(t, r)
	if mid1 != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, mid1)
	}
	if op1.Tag&0x1F != appSearchResEntry {
		t.Fatalf("expected SearchResultEntry, got 0x%X", op1.Tag&0x1F)
	}
	rr := bytes.NewReader(op1.Value)
	dnTLV, err := ber.BerReadTLV(rr)
	if err != nil {
		t.Fatalf("failed to read DN of RootDSE: %v", err)
	}
	if string(dnTLV.Value) != "" {
		t.Fatalf("expected RootDSE DN \"\", got %q", string(dnTLV.Value))
	}

	// Second message: SearchResultDone with success
	mid2, op2 := decodeLDAPMessageFromReader(t, r)
	if mid2 != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, mid2)
	}
	if op2.Tag&0x1F != appSearchDone {
		t.Fatalf("expected SearchResultDone, got 0x%X", op2.Tag&0x1F)
	}
	code, _, diag := decodeLDAPResult(t, op2)
	if code != rcSuccess || diag != "" {
		t.Fatalf("expected success done, got code %d diag %q", code, diag)
	}
}

/*
TestHandleSearch_SubSchemaEntry verifies a search on base=cn=subschema,
scope=baseObject returns the subschema entry.
*/
func TestHandleSearch_SubSchemaEntry(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	body := bytes.Buffer{}
	body.Write(ber.BerWrapString("cn=subschema"))
	body.Write(ber.BerWrapEnum(0))    // scope baseObject
	body.Write(ber.BerWrapEnum(0))    // deref
	body.Write(ber.BerWrapInteger(0)) // size
	body.Write(ber.BerWrapInteger(0)) // time
	body.Write(buildBoolTLV(false))

	// filter: any (use boolean -> filterAny)
	body.Write(ber.BerWrapTLV(ber.ClassUniversal|ber.PcPrimitive|ber.TagBoolean, []byte{0xFF}))

	const msgID = 43
	if err := s.handleSearch(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleSearch returned error: %v", err)
	}

	r := bytes.NewReader(conn.writeBuf.Bytes())
	mid1, op1 := decodeLDAPMessageFromReader(t, r)
	if mid1 != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, mid1)
	}
	if op1.Tag&0x1F != appSearchResEntry {
		t.Fatalf("expected SearchResultEntry, got 0x%X", op1.Tag&0x1F)
	}
	rr := bytes.NewReader(op1.Value)
	dnTLV, err := ber.BerReadTLV(rr)
	if err != nil {
		t.Fatalf("failed reading DN: %v", err)
	}
	if string(dnTLV.Value) != "cn=subschema" {
		t.Fatalf("expected DN cn=subschema, got %q", string(dnTLV.Value))
	}
	mid2, op2 := decodeLDAPMessageFromReader(t, r)
	if mid2 != msgID || op2.Tag&0x1F != appSearchDone {
		t.Fatalf("expected SearchResultDone, got mid %d tag 0x%X", mid2, op2.Tag&0x1F)
	}
	code, _, _ := decodeLDAPResult(t, op2)
	if code != rcSuccess {
		t.Fatalf("expected success, got %d", code)
	}
}

/*
TestHandleSearch_NoSuchBaseDN verifies that when baseDN doesn't exist,
handleSearch returns rcNoSuchObject with matchedDN equal to closest ancestor.
*/
func TestHandleSearch_NoSuchBaseDN(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	base := "ou=missing," + d.BaseDN

	body := bytes.Buffer{}
	body.Write(ber.BerWrapString(base))
	body.Write(ber.BerWrapEnum(2))    // subtree
	body.Write(ber.BerWrapEnum(0))    // deref
	body.Write(ber.BerWrapInteger(0)) // size
	body.Write(ber.BerWrapInteger(0)) // time
	body.Write(buildBoolTLV(false))
	body.Write(ber.BerWrapTLV(ber.ClassUniversal|ber.PcPrimitive|ber.TagBoolean, []byte{0xFF}))

	const msgID = 44
	if err := s.handleSearch(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleSearch returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != msgID {
		t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
	}
	code, matchedDN, diag := decodeLDAPResult(t, opTLV)
	if code != rcNoSuchObject || matchedDN != d.BaseDN || diag != "no such base DN" {
		t.Fatalf("unexpected result: code %d matchedDN %q diag %q", code, matchedDN, diag)
	}
}

/*
TestHandleSearch_SubtreeSizeLimitExceeded verifies that with a subtree search
and sizeLimit > 0, rcSizeLimitExceeded is returned once the limit is hit.
*/
func TestHandleSearch_SubtreeSizeLimitExceeded(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")

	// add a couple of extra entries to make sure >1 candidate
	d.Add(&directory.Entry{
		DN:     "uid=a,ou=users,dc=example,dc=com",
		Attrs:  map[string][]string{"uid": {"a"}},
		Parent: "ou=users,dc=example,dc=com",
	})
	d.Add(&directory.Entry{
		DN:     "uid=b,ou=users,dc=example,dc=com",
		Attrs:  map[string][]string{"uid": {"b"}},
		Parent: "ou=users,dc=example,dc=com",
	})

	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	body := bytes.Buffer{}
	body.Write(ber.BerWrapString(""))                                                           // empty base -> will be replaced with BaseDN for subtree
	body.Write(ber.BerWrapEnum(2))                                                              // scope=wholeSubtree
	body.Write(ber.BerWrapEnum(0))                                                              // deref
	body.Write(ber.BerWrapInteger(1))                                                           // sizeLimit=1
	body.Write(ber.BerWrapInteger(0))                                                           // timeLimit=0
	body.Write(buildBoolTLV(false))                                                             // typesOnly
	body.Write(ber.BerWrapTLV(ber.ClassUniversal|ber.PcPrimitive|ber.TagBoolean, []byte{0xFF})) // filterAny

	const msgID = 45
	if err := s.handleSearch(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleSearch returned error: %v", err)
	}

	r := bytes.NewReader(conn.writeBuf.Bytes())
	// First message: SearchResultEntry
	mid1, op1 := decodeLDAPMessageFromReader(t, r)
	if mid1 != msgID || op1.Tag&0x1F != appSearchResEntry {
		t.Fatalf("expected SearchResultEntry, got mid %d tag 0x%X", mid1, op1.Tag&0x1F)
	}
	// Second message: SearchResultDone with rcSizeLimitExceeded
	mid2, op2 := decodeLDAPMessageFromReader(t, r)
	if mid2 != msgID || op2.Tag&0x1F != appSearchDone {
		t.Fatalf("expected SearchResultDone, got mid %d tag 0x%X", mid2, op2.Tag&0x1F)
	}
	code, _, diag := decodeLDAPResult(t, op2)
	if code != rcSizeLimitExceeded || diag != "size limit exceeded" {
		t.Fatalf("expected sizeLimitExceeded, got code %d diag %q", code, diag)
	}
}

/*
TestHandleSearch_OneLevelEmptyBase returns root entry when base="" scope=1.
*/
func TestHandleSearch_OneLevelEmptyBase(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	body := bytes.Buffer{}
	body.Write(ber.BerWrapString(""))
	body.Write(ber.BerWrapEnum(1))    // oneLevel
	body.Write(ber.BerWrapEnum(0))    // deref
	body.Write(ber.BerWrapInteger(0)) // size
	body.Write(ber.BerWrapInteger(0)) // time
	body.Write(buildBoolTLV(false))
	body.Write(ber.BerWrapTLV(ber.ClassUniversal|ber.PcPrimitive|ber.TagBoolean, []byte{0xFF}))

	const msgID = 46
	if err := s.handleSearch(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleSearch returned error: %v", err)
	}
	r := bytes.NewReader(conn.writeBuf.Bytes())
	mid1, op1 := decodeLDAPMessageFromReader(t, r)
	if mid1 != msgID || op1.Tag&0x1F != appSearchResEntry {
		t.Fatalf("expected SearchResultEntry, got mid %d tag 0x%X", mid1, op1.Tag&0x1F)
	}
	rr := bytes.NewReader(op1.Value)
	dnTLV, err := ber.BerReadTLV(rr)
	if err != nil {
		t.Fatalf("failed reading DN: %v", err)
	}
	if string(dnTLV.Value) != d.BaseDN {
		t.Fatalf("expected base DN %q, got %q", d.BaseDN, string(dnTLV.Value))
	}
	mid2, op2 := decodeLDAPMessageFromReader(t, r)
	if mid2 != msgID || op2.Tag&0x1F != appSearchDone {
		t.Fatalf("expected SearchResultDone, got mid %d tag 0x%X", mid2, op2.Tag&0x1F)
	}
}

// -----------------------------------------------------------------------------
// handleLDAPMessage
// -----------------------------------------------------------------------------

/*
TestHandleLDAPMessage_BadMsgIDTagTriggersProtocolError verifies that when the
msgID TLV tag is wrong, handleLDAPMessage sends a protocol error with msgID=0.
*/
func TestHandleLDAPMessage_BadMsgIDTagTriggersProtocolError(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	var inner bytes.Buffer
	inner.Write(ber.BerWrapString("not-int"))      // bad msgID
	inner.Write(ber.BerWrapApp(appUnbindReq, nil)) // protocolOp

	if err := s.handleLDAPMessage(inner.Bytes()); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != 0 {
		t.Fatalf("expected msgID 0, got %d", gotMsgID)
	}
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcProtocolError || diag != "bad msg id" {
		t.Fatalf("expected bad msg id protocol error, got code %d diag %q", code, diag)
	}
}

/*
TestHandleLDAPMessage_UnbindClosesConnection verifies that UnbindRequest
closes the connection and returns io.EOF.
*/
func TestHandleLDAPMessage_UnbindClosesConnection(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	var inner bytes.Buffer
	inner.Write(ber.BerWrapInteger(5))
	inner.Write(ber.BerWrapApp(appUnbindReq, nil))

	err := s.handleLDAPMessage(inner.Bytes())
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
	if !conn.closed {
		t.Fatalf("expected connection closed on Unbind")
	}
}

/*
TestHandleLDAPMessage_UnexpectedClassReturnsProtocolError verifies that a
non-APPLICATION protocolOp causes rcProtocolError "unexpected class".
*/
func TestHandleLDAPMessage_UnexpectedClassReturnsProtocolError(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	var inner bytes.Buffer
	inner.Write(ber.BerWrapInteger(1))
	inner.Write(ber.BerWrapString("oops")) // UNIVERSAL class

	if err := s.handleLDAPMessage(inner.Bytes()); err != nil {
		t.Fatalf("handleLDAPMessage returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	gotMsgID, opTLV := decodeLDAPMessage(t, packet)
	if gotMsgID != 1 {
		t.Fatalf("expected msgID 1, got %d", gotMsgID)
	}
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcProtocolError || diag != "unexpected class" {
		t.Fatalf("expected unexpected class protocol error, got code %d diag %q", code, diag)
	}
	_ = opTLV
}

/*
TestHandleLDAPMessage_ModifyNotSupported verifies that ModifyRequest is
rejected with rcUnwillingToPerform and message.
*/
func TestHandleLDAPMessage_ModifyNotSupported(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	var inner bytes.Buffer
	inner.Write(ber.BerWrapInteger(2))
	inner.Write(ber.BerWrapApp(appModifyReq, nil))

	if err := s.handleLDAPMessage(inner.Bytes()); err != nil {
		t.Fatalf("handleLDAPMessage returned error: %v", err)
	}
	packet := conn.writeBuf.Bytes()
	_, opTLV := decodeLDAPMessage(t, packet)
	code, _, diag := decodeLDAPResult(t, opTLV)
	if code != rcUnwillingToPerform || diag != "modify not supported (read-only)" {
		t.Fatalf("unexpected modify response: code %d diag %q", code, diag)
	}
}

/*
TestHandleLDAPMessage_AbandonIgnored verifies that AbandonRequest produces no
response and returns nil error.
*/
func TestHandleLDAPMessage_AbandonIgnored(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	var inner bytes.Buffer
	inner.Write(ber.BerWrapInteger(9))
	inner.Write(ber.BerWrapApp(appAbandonReq, nil))

	if err := s.handleLDAPMessage(inner.Bytes()); err != nil {
		t.Fatalf("expected nil error for AbandonReq, got %v", err)
	}
	if conn.writeBuf.Len() != 0 {
		t.Fatalf("expected no response written for Abandon, got %d bytes", conn.writeBuf.Len())
	}
}

/*
TestHandleLDAPMessage_UnknownAppTagClosesConnection verifies that unknown
application tags cause connection close and io.EOF.
*/
func TestHandleLDAPMessage_UnknownAppTagClosesConnection(t *testing.T) {
	conn := &memConn{}
	s := &Session{Conn: conn}

	// 17 is not one of the known app tags and fits in the low 5 bits.
	unknownTag := byte(17)

	var inner bytes.Buffer
	inner.Write(ber.BerWrapInteger(10))
	inner.Write(ber.BerWrapApp(unknownTag, nil))

	err := s.handleLDAPMessage(inner.Bytes())
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
	if !conn.closed {
		t.Fatalf("expected connection closed for unknown appTag")
	}
}

// -----------------------------------------------------------------------------
// Serve
// -----------------------------------------------------------------------------

/*
TestServe_ReadsOneMessageAndExitsOnEOF verifies that Serve reads a single
LDAPMessage from the connection, dispatches it (Unbind), then EOF and exit.
*/
func TestServe_ReadsOneMessageAndExitsOnEOF(t *testing.T) {
	conn := &memConn{}

	var inner bytes.Buffer
	inner.Write(ber.BerWrapInteger(1))
	inner.Write(ber.BerWrapApp(appUnbindReq, nil))
	packet := ber.BerWrapSequence(inner.Bytes())
	conn.readBuf.Write(packet)

	s := &Session{Conn: conn}
	s.Serve()

	if !conn.closed {
		t.Fatalf("expected connection to be closed after Serve")
	}
}

// -----------------------------------------------------------------------------
// Filters – direct Match tests
// -----------------------------------------------------------------------------

/*
TestFilterPresent verifies filterPresent.Match is true only when the attribute
exists on the entry and false when it does not.
*/
func TestFilterPresent(t *testing.T) {
	e := &directory.Entry{
		Attrs: map[string][]string{
			"cn": {"foo"},
		},
	}

	// Attribute present -> should match.
	fpCN := filterPresent{Attr: "cn"}
	if !fpCN.Match(e) {
		t.Fatalf("expected present filter to match for cn")
	}

	// Attribute missing -> should NOT match.
	fpSN := filterPresent{Attr: "sn"}
	if fpSN.Match(e) {
		t.Fatalf("did not expect present filter on sn to match")
	}
}

/*
TestFilterEq verifies equality filter is case-insensitive and matches any
one of the attribute values.
*/
func TestFilterEq(t *testing.T) {
	e := &directory.Entry{
		Attrs: map[string][]string{
			"cn": {"John", "DOE"},
		},
	}

	// Match expected (case-insensitive)
	fDoe := filterEq{Attr: "cn", Value: "doe"}
	if !fDoe.Match(e) {
		t.Fatalf("expected equality filter to match for 'doe'")
	}

	// No match expected
	fSmith := filterEq{Attr: "cn", Value: "smith"}
	if fSmith.Match(e) {
		t.Fatalf("did not expect equality filter for 'smith'")
	}
}

/*
TestFilterAndOrNot verifies logical filters AND/OR/NOT compose correctly.
*/
func TestFilterAndOrNot(t *testing.T) {
	e := &directory.Entry{
		Attrs: map[string][]string{
			"cn": {"John"},
			"sn": {"Doe"},
		},
	}
	andF := filterAnd{Subs: []filter{
		filterEq{Attr: "cn", Value: "John"},
		filterEq{Attr: "sn", Value: "Doe"},
	}}
	if !andF.Match(e) {
		t.Fatalf("expected AND to match")
	}
	orF := filterOr{Subs: []filter{
		filterEq{Attr: "cn", Value: "X"},
		filterEq{Attr: "sn", Value: "Doe"},
	}}
	if !orF.Match(e) {
		t.Fatalf("expected OR to match")
	}
	notF := filterNot{Sub: filterEq{Attr: "sn", Value: "Smith"}}
	if !notF.Match(e) {
		t.Fatalf("expected NOT(!Smith) to match")
	}
}

/*
TestFilterSubstr_MatchAndNoMatch exercises substring filters with initial,
any, and final segments.
*/
func TestFilterSubstr_MatchAndNoMatch(t *testing.T) {
	val := "Johnathan Doe Jr"
	e := &directory.Entry{
		Attrs: map[string][]string{
			"cn": {val},
		},
	}
	init := "Jo"
	final := "Jr"
	f := filterSubstr{
		Attr:    "cn",
		Initial: &init,
		Anys:    []string{"nath", "n "},
		Final:   &final,
	}
	if !f.Match(e) {
		t.Fatalf("expected substring filter to match")
	}

	// Change final to something wrong
	wrongFinal := "Sr"
	f.Final = &wrongFinal
	if f.Match(e) {
		t.Fatalf("did not expect substring filter to match with wrong final")
	}
}

/*
TestFilterAnyAlwaysMatches verifies filterAny.Match always returns true.
*/
func TestFilterAnyAlwaysMatches(t *testing.T) {
	f := filterAny{}
	e := &directory.Entry{Attrs: map[string][]string{}}
	if !f.Match(e) {
		t.Fatalf("expected filterAny to always match")
	}
}

// -----------------------------------------------------------------------------
// parseFilter + encodeLengthAndValue
// -----------------------------------------------------------------------------

/*
TestParseFilter_Present verifies parsing of a present filter (attr=*).
*/
func TestParseFilter_Present(t *testing.T) {
	tlv := ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcPrimitive|7, []byte("cn"))
	f, err := parseFilter(tlv)
	if err != nil {
		t.Fatalf("parseFilter returned error: %v", err)
	}
	fp, ok := f.(filterPresent)
	if !ok {
		t.Fatalf("expected filterPresent, got %T", f)
	}
	e := &directory.Entry{Attrs: map[string][]string{"cn": {"x"}}}
	if !fp.Match(e) {
		t.Fatalf("expected present filter to match")
	}
}

/*
TestParseFilter_Equality verifies parsing of an equality filter and that it
matches correctly.
*/
func TestParseFilter_Equality(t *testing.T) {
	var inner bytes.Buffer
	inner.Write(ber.BerWrapString("cn"))
	inner.Write(ber.BerWrapString("Alice"))
	tlv := ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcConstructed|3, inner.Bytes())

	f, err := parseFilter(tlv)
	if err != nil {
		t.Fatalf("parseFilter returned error: %v", err)
	}
	fe, ok := f.(filterEq)
	if !ok {
		t.Fatalf("expected filterEq, got %T", f)
	}
	if fe.Attr != "cn" || fe.Value != "Alice" {
		t.Fatalf("unexpected filterEq fields: %+v", fe)
	}
	e := &directory.Entry{Attrs: map[string][]string{"cn": {"alice"}}}
	if !fe.Match(e) {
		t.Fatalf("expected equality filter to match")
	}
}

/*
TestParseFilter_AndOrNot verifies parsing of AND, OR, and NOT filter trees.
*/
func TestParseFilter_AndOrNot(t *testing.T) {
	// equality filter (cn=Alice)
	var eqInner bytes.Buffer
	eqInner.Write(ber.BerWrapString("cn"))
	eqInner.Write(ber.BerWrapString("Alice"))
	eqTLV := ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcConstructed|3, eqInner.Bytes())

	// AND(&) with two equalities
	andValue := bytes.Buffer{}
	andValue.Write(eqTLV)
	andValue.Write(eqTLV)
	andTLV := ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcConstructed|0, andValue.Bytes())

	f, err := parseFilter(andTLV)
	if err != nil {
		t.Fatalf("parseFilter returned error: %v", err)
	}
	andF, ok := f.(filterAnd)
	if !ok || len(andF.Subs) != 2 {
		t.Fatalf("expected filterAnd with 2 subs, got %#v", f)
	}

	// OR(|)
	orTLV := ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcConstructed|1, andValue.Bytes())
	of, err := parseFilter(orTLV)
	if err != nil {
		t.Fatalf("parseFilter OR error: %v", err)
	}
	if _, ok := of.(filterOr); !ok {
		t.Fatalf("expected filterOr, got %T", of)
	}

	// NOT(!)
	notTLV := ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcConstructed|2, eqTLV)
	nf, err := parseFilter(notTLV)
	if err != nil {
		t.Fatalf("parseFilter NOT error: %v", err)
	}
	if _, ok := nf.(filterNot); !ok {
		t.Fatalf("expected filterNot, got %T", nf)
	}
}

/*
TestParseFilter_Substring verifies parsing of substring filters and that
filterSubstr.Match works as expected.
*/
func TestParseFilter_Substring(t *testing.T) {
	// attr "cn"
	attrTLV := ber.BerWrapString("cn")

	// sequence of choices: initial="Al", any="ic", final="e"
	var choices bytes.Buffer
	choices.Write(ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcPrimitive|0, []byte("Al")))
	choices.Write(ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcPrimitive|1, []byte("i")))
	choices.Write(ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcPrimitive|2, []byte("e")))
	seq := ber.BerWrapSequence(choices.Bytes())

	var inner bytes.Buffer
	inner.Write(attrTLV)
	inner.Write(seq)

	tlv := ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcConstructed|4, inner.Bytes())
	f, err := parseFilter(tlv)
	if err != nil {
		t.Fatalf("parseFilter returned error: %v", err)
	}
	fs, ok := f.(filterSubstr)
	if !ok {
		t.Fatalf("expected filterSubstr, got %T", f)
	}
	e := &directory.Entry{
		Attrs: map[string][]string{"cn": {"Alice"}},
	}
	if !fs.Match(e) {
		t.Fatalf("expected substring filter to match 'Alice'")
	}
}

/*
TestParseFilter_SubstringErrors verifies incorrect substring forms trigger
errors: bad attr, bad sequence, bad choice class, unknown choice tag.
*/
func TestParseFilter_SubstringErrors(t *testing.T) {
	// bad substring attr tag
	{
		var inner bytes.Buffer
		inner.Write(ber.BerWrapInteger(1)) // bad attr TLV
		inner.Write(ber.BerWrapSequence(nil))
		tlv := ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcConstructed|4, inner.Bytes())
		if _, err := parseFilter(tlv); err == nil {
			t.Fatalf("expected error for bad substring attr")
		}
	}
	// bad substring sequence tag
	{
		var inner bytes.Buffer
		inner.Write(ber.BerWrapString("cn"))
		inner.Write(ber.BerWrapInteger(1)) // not a sequence
		tlv := ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcConstructed|4, inner.Bytes())
		if _, err := parseFilter(tlv); err == nil {
			t.Fatalf("expected error for bad substring seq")
		}
	}
	// bad choice class
	{
		var inner bytes.Buffer
		inner.Write(ber.BerWrapString("cn"))
		choices := bytes.Buffer{}
		choices.Write(ber.BerWrapTLV(ber.ClassUniversal|ber.PcPrimitive, []byte("bad"))) // wrong class
		inner.Write(ber.BerWrapSequence(choices.Bytes()))
		tlv := ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcConstructed|4, inner.Bytes())
		if _, err := parseFilter(tlv); err == nil {
			t.Fatalf("expected error for bad substring choice class")
		}
	}
	// unknown choice tag
	{
		var inner bytes.Buffer
		inner.Write(ber.BerWrapString("cn"))
		choices := bytes.Buffer{}
		choices.Write(ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcPrimitive|10, []byte("x"))) // ctag=10 unknown
		inner.Write(ber.BerWrapSequence(choices.Bytes()))
		tlv := ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcConstructed|4, inner.Bytes())
		if _, err := parseFilter(tlv); err == nil {
			t.Fatalf("expected error for unknown substring choice")
		}
	}
}

/*
TestParseFilter_EqualityErrors verifies parsing errors for equality filters:
bad attr TLV, bad value TLV.
*/
func TestParseFilter_EqualityErrors(t *testing.T) {
	// bad equality attr
	{
		var inner bytes.Buffer
		inner.Write(ber.BerWrapInteger(1))
		inner.Write(ber.BerWrapString("v"))
		tlv := ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcConstructed|3, inner.Bytes())
		if _, err := parseFilter(tlv); err == nil {
			t.Fatalf("expected bad equality attr error")
		}
	}
	// bad equality value
	{
		var inner bytes.Buffer
		inner.Write(ber.BerWrapString("cn"))
		inner.Write(ber.BerWrapInteger(1))
		tlv := ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcConstructed|3, inner.Bytes())
		if _, err := parseFilter(tlv); err == nil {
			t.Fatalf("expected bad equality value error")
		}
	}
}

/*
TestParseFilter_AnyFallback verifies that unrecognized tags fall back to
filterAny.
*/
func TestParseFilter_AnyFallback(t *testing.T) {
	tlv := ber.BerWrapTLV(ber.ClassUniversal|ber.PcPrimitive|ber.TagBoolean, []byte{0xFF})
	f, err := parseFilter(tlv)
	if err != nil {
		t.Fatalf("parseFilter returned error: %v", err)
	}
	if _, ok := f.(filterAny); !ok {
		t.Fatalf("expected filterAny fallback, got %T", f)
	}
	e := &directory.Entry{}
	if !f.Match(e) {
		t.Fatalf("filterAny should match everything")
	}
}

/*
TestEncodeLengthAndValue_RoundTrip verifies encodeLengthAndValue works for
both short and long-form lengths when combined into a TLV.
*/
func TestEncodeLengthAndValue_RoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte{1, 2, 3, 4, 5},           // short
		bytes.Repeat([]byte{0xAA}, 200), // long (>127)
	}
	for _, val := range cases {
		encoded := append([]byte{ber.ClassUniversal | ber.PcPrimitive | ber.TagOctetString}, encodeLengthAndValue(val)...)
		r := bytes.NewReader(encoded)
		tlv, err := ber.BerReadTLV(r)
		if err != nil {
			t.Fatalf("BerReadTLV error: %v", err)
		}
		if tlv.Length != len(val) {
			t.Fatalf("expected length %d, got %d", len(val), tlv.Length)
		}
		if !bytes.Equal(tlv.Value, val) {
			t.Fatalf("roundtrip mismatch for encodeLengthAndValue")
		}
	}
}

func TestHandleCompare_TrueAndFalse(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")

	userDN := "uid=jdoe,ou=users,dc=example,dc=com"
	d.Add(&directory.Entry{
		DN: userDN,
		Attrs: map[string][]string{
			"uid": {"jdoe"},
		},
		Parent: "ou=users,dc=example,dc=com",
	})
	store := &directory.DirStore{}
	store.Set(d)

	s := &Session{Conn: conn, Store: store}

	buildBody := func(attr, value string) []byte {
		var ava bytes.Buffer
		ava.Write(ber.BerWrapString(attr))
		ava.Write(ber.BerWrapString(value))

		body := bytes.Buffer{}
		body.Write(ber.BerWrapString(userDN))
		body.Write(ber.BerWrapSequence(ava.Bytes()))
		return body.Bytes()
	}

	// CompareTrue: uid=jdoe
	{
		const msgID = 100
		if err := s.handleCompare(msgID, buildBody("uid", "jdoe")); err != nil {
			t.Fatalf("handleCompare returned error: %v", err)
		}
		packet := conn.writeBuf.Bytes()
		gotMsgID, opTLV := decodeLDAPMessage(t, packet)
		if gotMsgID != msgID {
			t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
		}
		code, _, _ := decodeLDAPResult(t, opTLV)
		if code != rcCompareTrue {
			t.Fatalf("expected rcCompareTrue, got %d", code)
		}
	}

	// CompareFalse: uid=other
	{
		conn.writeBuf.Reset()
		const msgID = 101
		if err := s.handleCompare(msgID, buildBody("uid", "other")); err != nil {
			t.Fatalf("handleCompare returned error: %v", err)
		}
		packet := conn.writeBuf.Bytes()
		gotMsgID, opTLV := decodeLDAPMessage(t, packet)
		if gotMsgID != msgID {
			t.Fatalf("expected msgID %d, got %d", msgID, gotMsgID)
		}
		code, _, _ := decodeLDAPResult(t, opTLV)
		if code != rcCompareFalse {
			t.Fatalf("expected rcCompareFalse, got %d", code)
		}
	}
}

func TestHandleSearch_FilterEqualityOnUid(t *testing.T) {
	conn := &memConn{}
	d := directory.NewDirectory("dc=example,dc=com")

	userDN1 := "uid=jdoe,ou=users,dc=example,dc=com"
	userDN2 := "uid=other,ou=users,dc=example,dc=com"

	d.Add(&directory.Entry{
		DN: userDN1,
		Attrs: map[string][]string{
			"uid": {"jdoe"},
		},
		Parent: "ou=users,dc=example,dc=com",
	})
	d.Add(&directory.Entry{
		DN: userDN2,
		Attrs: map[string][]string{
			"uid": {"other"},
		},
		Parent: "ou=users,dc=example,dc=com",
	})
	store := &directory.DirStore{}
	store.Set(d)
	s := &Session{Conn: conn, Store: store}

	// Build equality filter (uid=jdoe) as the server expects (context-specific 3)
	var eqInner bytes.Buffer
	eqInner.Write(ber.BerWrapString("uid"))
	eqInner.Write(ber.BerWrapString("jdoe"))
	filterTLV := ber.BerWrapTLV(ber.ClassContextSpecific|ber.PcConstructed|3, eqInner.Bytes())

	body := bytes.Buffer{}
	body.Write(ber.BerWrapString(d.BaseDN)) // base
	body.Write(ber.BerWrapEnum(2))          // scope = wholeSubtree
	body.Write(ber.BerWrapEnum(0))          // deref
	body.Write(ber.BerWrapInteger(0))       // sizeLimit
	body.Write(ber.BerWrapInteger(0))       // timeLimit
	body.Write(buildBoolTLV(false))         // typesOnly=false
	body.Write(filterTLV)                   // filter (uid=jdoe)
	body.Write(ber.BerWrapSequence(nil))    // attrs: empty sequence -> "all"

	const msgID = 200
	if err := s.handleSearch(msgID, body.Bytes()); err != nil {
		t.Fatalf("handleSearch returned error: %v", err)
	}

	r := bytes.NewReader(conn.writeBuf.Bytes())

	// Expect exactly one SearchResultEntry with DN=userDN1, then SearchResultDone
	mid1, op1 := decodeLDAPMessageFromReader(t, r)
	if mid1 != msgID || op1.Tag&0x1F != appSearchResEntry {
		t.Fatalf("expected SearchResultEntry, got mid %d tag 0x%X", mid1, op1.Tag&0x1F)
	}
	rr := bytes.NewReader(op1.Value)
	dnTLV, err := ber.BerReadTLV(rr)
	if err != nil {
		t.Fatalf("failed reading DN: %v", err)
	}
	if string(dnTLV.Value) != userDN1 {
		t.Fatalf("expected DN %q, got %q", userDN1, string(dnTLV.Value))
	}

	// Done
	mid2, op2 := decodeLDAPMessageFromReader(t, r)
	if mid2 != msgID || op2.Tag&0x1F != appSearchDone {
		t.Fatalf("expected SearchResultDone, got mid %d tag 0x%X", mid2, op2.Tag&0x1F)
	}
	code, _, diag := decodeLDAPResult(t, op2)
	if code != rcSuccess || diag != "" {
		t.Fatalf("expected success, got code %d diag %q", code, diag)
	}

	// And nothing else
	if r.Len() != 0 {
		t.Fatalf("expected only one entry + done, but extra bytes remain (%d)", r.Len())
	}
}
