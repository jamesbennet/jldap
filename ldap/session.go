package ldap

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"jldap/ber"
	"jldap/directory"
)

// OID for the LDAP “StartTLS” extended operation. Used to recognize a StartTLS request.
const startTLSOID = "1.3.6.1.4.1.1466.20037"

/*
LDAP (Lightweight Directory Access Protocol) Application-level message types (LDAP protocol operations).
These values are the LDAP ASN.1 Application class tags. They identify what kind of operation is being encoded over the wire.
These are defined in RFC 4511.
*/
const (
	appBindReq        = 0
	appBindResp       = 1
	appUnbindReq      = 2
	appSearchReq      = 3
	appSearchResEntry = 4
	appSearchDone     = 5
	appCompareReq     = 14
	appCompareResp    = 15
	appModifyReq      = 6
	appModifyResp     = 7
	appAddReq         = 8
	appAddResp        = 9
	appDelReq         = 10
	appDelResp        = 11
	appModifyDNReq    = 12
	appModifyDNResp   = 13
	appAbandonReq     = 16
	appExtendedReq    = 23
	appExtendedResp   = 24
)

// LDAP (Lightweight Directory Access Protocol) result codes returned by servers in most responses, indicating success or specific LDAP errors.
const (
	rcSuccess                = 0
	rcOperationsError        = 1
	rcProtocolError          = 2
	rcTimeLimitExceeded      = 3
	rcSizeLimitExceeded      = 4
	rcAuthMethodNotSupported = 7
	rcNoSuchObject           = 32
	rcInvalidCredentials     = 49
	rcUnwillingToPerform     = 53
	rcCompareFalse           = 5
	rcCompareTrue            = 6
)

/*
Session struct represents one client connection/session.
*/
type Session struct {
	Conn      net.Conn             // The underlying network connection to the client.
	TlsConfig *tls.Config          // TLS configuration to use for StartTLS (server certs, etc.).
	TlsActive bool                 // Flag indicating if the connection is already wrapped with TLS.
	Dir       *directory.Directory // Pointer to the directory object.
	bindDN    string               // The DN (distinguished name) of the currently-bound user (empty if anonymous).
	Store     *directory.DirStore  // Handle to a DirStore, which provides access to actual entries.
}

/*
Serve is the main loop for a session, handling incoming LDAP messages from clients until error/EOF.
*/
func (s *Session) Serve() {
	// defer ... ensures the connection is closed when Serve returns, regardless of reason.
	defer func(conn net.Conn) {
		// It passes s.Conn into an anonymous function and logs any error from Close.
		err := conn.Close()
		if err != nil {
			log.Printf("%+v", err)
		}
	}(s.Conn)
	// Clears any existing deadline on the connection by setting it to zero time (no timeout).
	err := s.Conn.SetDeadline(time.Time{})
	if err != nil {
		log.Printf("%+v", err)
	}
	// Infinite loop: read one top-level BER TLV from the TCP stream.
	for {
		// BerReadTLVStream reads the next BER element from the network connection.
		tlv, err := ber.BerReadTLVStream(s.Conn)
		if err != nil {
			// if the error is just "EOF" that's fine, don't make noise in logs.
			if err.Error() != "EOF" {
				log.Printf("%+v", err)
			}
			return
		}
		// Top-level LDAP message must be a universal constructed SEQUENCE.
		// If not, protocol violation → bail out.
		if tlv.Tag != (ber.ClassUniversal | ber.PcConstructed | ber.TagSequence) {
			return
		}
		// Pass the contents of the sequence (tlv.Value) to handleLDAPMessage.
		if err := s.handleLDAPMessage(tlv.Value); err != nil {
			// if the error is just "EOF" that's fine, don't make noise in logs.
			if err.Error() != "EOF" {
				log.Printf("%+v", err)
			}
			return
		}
	}
}

/*
handleLDAPMessage parses and dispatches a single LDAP message.
msg is the BER value of the outer SEQUENCE (the LDAPMessage). We wrap it in a bytes.Reader to parse piece by piece.
*/
func (s *Session) handleLDAPMessage(msg []byte) error {
	r := bytes.NewReader(msg)
	// Read the first TLV inside the LDAPMessage, which should be messageID (an INTEGER).
	idTLV, err := ber.BerReadTLV(r)
	// If read fails or the tag doesn’t match “primitive integer”, log “bad msg id”.
	if err != nil || idTLV.Tag != (ber.ClassUniversal|ber.PcPrimitive|ber.TagInteger) {
		log.Printf("bad msg id: %+v", err)
		// Return a protocol error result (using writeLDAPResult) with message ID 0 (since we couldn’t parse it).
		// note: errOr just returns the error — small shim
		return errOr(s.writeLDAPResult(0, rcProtocolError, "", "bad msg id", appBindResp))
	}
	// Decode the messageID from the BER integer bytes into int.
	msgID := ber.BerDecodeInt(idTLV.Value)
	opTLV, err := ber.BerReadTLV(r)
	if err != nil {
		log.Printf("%+v", err)
		return err
	}
	// Read the next TLV, which is the protocolOp – one of the application-typed LDAP operations.
	// appTag – low 5 bits: application tag number.
	appTag := opTLV.Tag & 0x1F
	// appClass – class bits (top 2 bits), should be Application class.
	appClass := opTLV.Tag & 0xC0
	/*
		Looks ahead to see if there are controls after the protocolOp.
		If there are remaining bytes:
		* Save current position pos.
		* Attempt to read another TLV.
		* If this TLV is not a context-specific constructed tag 0 (which is where controls live), reset the reader back to pos.
		* If an error occurs reading, also reset.
		Note: actual controls are not processed here; this just tries not to “consume” them accidentally.
	*/
	if r.Len() > 0 {
		pos, err := r.Seek(0, io.SeekCurrent)
		if err != nil {
			log.Printf("%+v", err)
		}
		if next, err := ber.BerReadTLV(r); err == nil {
			if !((next.Tag&0xE0) == ber.ClassContextSpecific|ber.PcConstructed && (next.Tag&0x1F) == 0) {
				_, err = r.Seek(pos, io.SeekStart)
				if err != nil {
					log.Printf("%+v", err)
				}
			}
		} else {
			_, err = r.Seek(pos, io.SeekStart)
			if err != nil {
				log.Printf("%+v", err)
			}
		}
	}
	// Ensures the protocolOp is an application-class element. If not, respond with protocol error.
	if appClass != ber.ClassApplication {
		return s.writeLDAPResult(msgID, rcProtocolError, "", "unexpected class", appBindResp)
	}
	// appTag identifies which LDAP operation this is.
	switch appTag {
	// For Unbind, close connection and signal EOF to caller.
	case appUnbindReq:
		err = s.Conn.Close()
		if err != nil {
			log.Printf("%+v", err)
		}
		// TODO: We may want to return a protocolError here instead
		return io.EOF
	// For BindRequest: dispatch to handleBind, passing message ID and the body bytes.
	case appBindReq:
		return s.handleBind(msgID, opTLV.Value)
	// Search and Compare operations are handled similarly by their functions.
	case appSearchReq:
		return s.handleSearch(msgID, opTLV.Value)
	case appCompareReq:
		return s.handleCompare(msgID, opTLV.Value)
	// Modify/Add/Delete/ModifyDN – explicitly rejected as read-only with rcUnwillingToPerform.
	case appModifyReq:
		return s.writeLDAPResult(msgID, rcUnwillingToPerform, "", "modify not supported (read-only)", appModifyResp)
	case appAddReq:
		return s.writeLDAPResult(msgID, rcUnwillingToPerform, "", "Add not supported (read-only)", appAddResp)
	case appDelReq:
		return s.writeLDAPResult(msgID, rcUnwillingToPerform, "", "delete not supported (read-only)", appDelResp)
	case appModifyDNReq:
		return s.writeLDAPResult(msgID, rcUnwillingToPerform, "", "moddn not supported (read-only)", appModifyDNResp)
	// Abandon request: ignore (no response per RFC) and return nil.
	case appAbandonReq:
		return nil
	// Extended operations (e.g. StartTLS) go to handleExtended.
	case appExtendedReq:
		return s.handleExtended(msgID, opTLV.Value)
	// Any unknown appTag: close the connection and return EOF.
	default:
		err = s.Conn.Close()
		if err != nil {
			log.Printf("%+v", err)
		}
		// TODO: We may want to return a protocolError here instead
		return io.EOF
	}
}

func errOr(e error) error { return e }

// parse BindRequest and authenticate
func (s *Session) handleBind(msgID int, body []byte) error {
	// body is the BER contents for the BindRequest (without the outer app tag). Wrap in bytes.Reader for parsing.
	r := bytes.NewReader(body)
	ver, err := ber.BerReadTLV(r)
	// First field: version (INTEGER). If it fails or has wrong tag, respond with protocol error.
	if err != nil || ver.Tag != (ber.ClassUniversal|ber.PcPrimitive|ber.TagInteger) {
		log.Printf("bad bind version: %+v", err)
		return s.writeBindResult(msgID, rcProtocolError, "", "bad bind version")
	}
	// Decode the version and ensure it’s 3. If not 3 → protocol error with message “only LDAPv3 supported”.
	if ber.BerDecodeInt(ver.Value) != 3 {
		log.Printf("only LDAPv3 supported: %+v", err)
		return s.writeBindResult(msgID, rcProtocolError, "", "only LDAPv3 supported")
	}
	// Next field: bind DN (Octet String). Check tag; if invalid → protocol error. Convert to string and store as bindName.
	name, err := ber.BerReadTLV(r)
	if err != nil || name.Tag != (ber.ClassUniversal|ber.PcPrimitive|ber.TagOctetString) {
		log.Printf("bad bind name: %+v", err)
		return s.writeBindResult(msgID, rcProtocolError, "", "bad bind name")
	}
	bindName := string(name.Value)
	// Third field: authentication choice (context-specific). Could be simple or SASL. Require a context-specific tag; otherwise respond “auth method not supported”.
	auth, err := ber.BerReadTLV(r)
	if err != nil || (auth.Tag&0xC0) != ber.ClassContextSpecific {
		log.Printf("bad auth choice - only simple bind supported: %+v", err)
		return s.writeBindResult(msgID, rcAuthMethodNotSupported, "", "bad auth choice - only simple bind supported")
	}
	// If the low 5 bits (tag number) is 0 and it’s primitive, that’s “simple” bind.
	if (auth.Tag&0x1F) == 0 && (auth.Tag&0x20) == ber.PcPrimitive {
		// auth.Value contains the password bytes; convert to string.
		pass := string(auth.Value)
		// Anonymous bind: empty DN and empty password → accept and set bindDN to empty.
		if bindName == "" && pass == "" {
			s.bindDN = ""
			return s.writeBindResult(msgID, rcSuccess, "", "")
		}
		// Fetch directory snapshot/store (d).
		d := s.Store.Get()
		// Find entry with DN bindName.
		e := d.Get(bindName)
		// If not found → invalid credentials.
		if e == nil {
			return s.writeBindResult(msgID, rcInvalidCredentials, "", "no such DN")
		}
		// Look through all userpassword attribute values.
		for _, v := range e.Attrs["userpassword"] {
			// If any equals the provided password: Set bindDN to the DN and return success.
			if v == pass {
				s.bindDN = bindName
				return s.writeBindResult(msgID, rcSuccess, "", "")
			}
		}
		// If not found → invalid credentials.
		return s.writeBindResult(msgID, rcInvalidCredentials, "", "invalid credentials")
	}
	// Now handle SASL bind: tag number 3, constructed.
	if (auth.Tag&0x1F) == 3 && (auth.Tag&0x20) == ber.PcConstructed {
		// rr reads from the SASL sequence.
		rr := bytes.NewReader(auth.Value)
		// First element: mechanism name (OCTET STRING).
		mechTLV, err := ber.BerReadTLV(rr)
		// Fail → “auth method not supported”.
		if err != nil || mechTLV.Tag != (ber.ClassUniversal|ber.PcPrimitive|ber.TagOctetString) {
			log.Printf("bad sasl mechanism: %+v", err)
			return s.writeBindResult(msgID, rcAuthMethodNotSupported, "", "bad sasl mechanism")
		}
		// Convert mechanism to upper-case string.
		mech := strings.ToUpper(string(mechTLV.Value))
		// Optional second element: credentials (OCTET STRING). If present and properly tagged, store its value in creds.
		var creds []byte
		// If an error occurs, log it but continue (creds may be empty).
		if rr.Len() > 0 {
			cTLS, err := ber.BerReadTLV(rr)
			if err == nil && cTLS.Tag == (ber.ClassUniversal|ber.PcPrimitive|ber.TagOctetString) {
				creds = cTLS.Value
			}
			if err != nil {
				log.Printf("%+v", err)
			}
		}
		switch mech {
		/*
			SASL PLAIN
			When mechanism is “PLAIN”:
				PLAIN format: authzid\0authcid\0password.
				Split at NUL bytes into up to 3 parts.
				If not exactly 3 → blob malformed → invalid credentials.
				Extract authzid, authcid, pass.
		*/
		case "PLAIN":
			parts := bytes.SplitN(creds, []byte{0x00}, 3)
			if len(parts) != 3 {
				return s.writeBindResult(msgID, rcInvalidCredentials, "", "bad PLAIN blob")
			}
			authzid := string(parts[0])
			authcid := string(parts[1])
			pass := string(parts[2])
			d := s.Store.Get()
			var dn string
			// Find DN to use
			switch {
			// If the BindRequest name (bindName) is non-empty, use that DN.
			case bindName != "":
				dn = bindName
			// Else, if authcid looks like a DN (contains = and ,), use authcid as DN.
			case strings.Contains(authcid, "=") && strings.Contains(authcid, ","):
				dn = authcid
			// Else, try to map authcid as a uid
			default:
				// Lowercase authcid. Look up ByUID map to get DN. Then get the entry from ByDN and use its actual DN.
				if uDNLower, ok := d.ByUID[strings.ToLower(authcid)]; ok {
					if e := d.ByDN[uDNLower]; e != nil {
						dn = e.DN
					}
				}
			}
			// If no DN resolved → “unknown authcid”.
			if dn == "" {
				return s.writeBindResult(msgID, rcInvalidCredentials, "", "unknown authcid")
			}
			e := d.Get(dn)
			// If the DN doesn’t exist → “no such DN”.
			if e == nil {
				return s.writeBindResult(msgID, rcInvalidCredentials, "", "no such DN")
			}
			// Same password matching as simple bind. If no match → invalid credentials.
			pwVals := e.Attrs["userpassword"]
			ok := false
			for _, v := range pwVals {
				if v == pass {
					ok = true
					break
				}
			}
			if !ok {
				return s.writeBindResult(msgID, rcInvalidCredentials, "", "invalid credentials")
			}
			// authzid is ignored
			_ = authzid
			s.bindDN = dn
			// On success, set bindDN and respond with success.
			return s.writeBindResult(msgID, rcSuccess, "", "")
		// For EXTERNAL or any other SASL mechanisms: respond “auth method not supported”.
		case "EXTERNAL":
			return s.writeBindResult(msgID, rcAuthMethodNotSupported, "", "SASL EXTERNAL not supported")
		default:
			return s.writeBindResult(msgID, rcAuthMethodNotSupported, "", "unsupported SASL mechanism")
		}
	}
	return s.writeBindResult(msgID, rcAuthMethodNotSupported, "", "unsupported auth choice")
}

/*
writeBindResult sends a BindResponse.
*/
func (s *Session) writeBindResult(msgID, code int, matchedDN, diag string) error {
	/*
		Build the inner contents of a BindResponse:
			resultCode (ENUM).
			matchedDN (OCTET STRING).
			diagnosticMessage (OCTET STRING).
		BerWrapEnum, BerWrapString create BER TLVs for those values and write them to a buffer.
	*/
	inner := bytes.Buffer{}
	inner.Write(ber.BerWrapEnum(code))
	inner.Write(ber.BerWrapString(matchedDN))
	inner.Write(ber.BerWrapString(diag))
	// Wrap the inner bytes as an application-class BindResponse (appBindResp).
	resp := ber.BerWrapApp(appBindResp, inner.Bytes())
	// Then send it as a full LDAP message via writeLDAPMessage with no controls.
	return s.writeLDAPMessage(msgID, resp, nil)
}

/*
writeLDAPResult: generic LDAP result response. Same layout as BindResponse, but reusable for searchDone, compareResp, etc.
appRespTag specifies which application response type to encode.
*/
func (s *Session) writeLDAPResult(msgID, code int, matchedDN, diag string, appRespTag byte) error {
	inner := bytes.Buffer{}
	inner.Write(ber.BerWrapEnum(code))
	inner.Write(ber.BerWrapString(matchedDN))
	inner.Write(ber.BerWrapString(diag))
	resp := ber.BerWrapApp(appRespTag, inner.Bytes())
	return s.writeLDAPMessage(msgID, resp, nil)
}

/*
writeLDAPMessage: wrap protocolOp and send to client.
Constructs an LDAPMessage:
* messageID as INTEGER.
* protocolOp already encoded with application tag.
* Optional controls wrapped in context-specific [0], constructed.
* Wrap everything in a SEQUENCE.
Writes the resulting packet to s.Conn, and logs any write errors and returns the error.
*/
func (s *Session) writeLDAPMessage(msgID int, protocolOp []byte, controls []byte) error {
	var seq bytes.Buffer
	seq.Write(ber.BerWrapInteger(msgID))
	seq.Write(protocolOp)
	if controls != nil {
		seq.Write(ber.BerWrapCtx(0, controls, true))
	}
	packet := ber.BerWrapSequence(seq.Bytes())
	_, err := s.Conn.Write(packet)
	if err != nil {
		log.Printf("%+v", err)
	}
	return err
}

/*
handleExtended: extended operations (StartTLS).
The ExtendedRequest body is a sequence of tagged fields.
*/
func (s *Session) handleExtended(msgID int, body []byte) error {
	rr := bytes.NewReader(body)
	var reqName string
	// Reads TLVs until none remain:
	for rr.Len() > 0 {
		tlv, err := ber.BerReadTLV(rr)
		if err != nil {
			log.Printf("%+v", err)
			break
		}
		// If the tag is context-specific primitive 0, that’s the requestName (OID of the extended op).
		if (tlv.Tag&0xE0) == (ber.ClassContextSpecific|ber.PcPrimitive) && (tlv.Tag&0x1F) == 0 {
			//  Save reqName as string OID.
			reqName = string(tlv.Value)
		}
	}
	// Check if this is the StartTLS extended operation.
	if reqName == startTLSOID {
		// If TLS is already active, return operations error.
		if s.TlsActive {
			return s.writeLDAPResult(msgID, rcOperationsError, "", "TLS already active", appExtendedResp)
		}
		// If the server has no TLS configuration, refuse with “unwilling to perform”.
		if s.TlsConfig == nil {
			return s.writeLDAPResult(msgID, rcUnwillingToPerform, "", "no TLS configured", appExtendedResp)
		}
		// First send a successful ExtendedResponse indicating StartTLS is accepted.
		if err := s.writeLDAPResult(msgID, rcSuccess, "", "", appExtendedResp); err != nil {
			log.Printf("%+v", err)
			return err
		}
		// Wrap current connection in a TLS server-side tls.Conn using TlsConfig.
		tlsConn := tls.Server(s.Conn, s.TlsConfig)
		// Set a 10s deadline for the TLS handshake.
		_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
		// Perform TLS handshake; on error log and return error.
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("%+v", err)
			return err
		}
		// Clear deadline (time.Time{}).
		err := tlsConn.SetDeadline(time.Time{})
		if err != nil {
			log.Printf("%+v", err)
		}
		// Replace s.Conn with the TLS connection and set TlsActive = true.
		s.Conn = tlsConn
		// Done; further operations now go over TLS.
		s.TlsActive = true
		return nil
	}
	// For any other extended request name, return “extended op not supported”.
	return s.writeLDAPResult(msgID, rcUnwillingToPerform, "", "extended op not supported", appExtendedResp)
}

/*
handleSearch: parse search request and stream entries.
On error or wrong tag: protocol error.
*/
func (s *Session) handleSearch(msgID int, body []byte) error {
	// SearchRequest body is parsed from r.
	r := bytes.NewReader(body)
	// First field: baseObject (DN as octet string).
	base, err := ber.BerReadTLV(r)
	if err != nil || base.Tag != (ber.ClassUniversal|ber.PcPrimitive|ber.TagOctetString) {
		log.Printf("bad base: %+v", err)
		return s.writeLDAPResult(msgID, rcProtocolError, "", "bad base", appSearchDone)
	}
	// Convert to baseDN.
	baseDN := string(base.Value)
	// Second field: scope (ENUM).
	// Decode to scopeVal: 0 = baseObject, 1 = singleLevel, 2 = wholeSubtree.
	scope, err := ber.BerReadTLV(r)
	if err != nil || scope.Tag != (ber.ClassUniversal|ber.PcPrimitive|ber.TagEnum) {
		log.Printf("bad scope: %+v", err)
		return s.writeLDAPResult(msgID, rcProtocolError, "", "bad scope", appSearchDone)
	}
	// Third field: derefAliases (ENUM). The value is read and ignored (not used).
	scopeVal := ber.BerDecodeInt(scope.Value)
	if _, err := ber.BerReadTLV(r); err != nil {
		log.Printf("bad deref: %+v", err)
		return s.writeLDAPResult(msgID, rcProtocolError, "", "bad deref", appSearchDone)
	}
	// Fourth field: sizeLimit (INTEGER). Decode and ensure non-negative; negative treated as 0 (no limit).
	sizeTLV, err := ber.BerReadTLV(r)
	if err != nil || sizeTLV.Tag != (ber.ClassUniversal|ber.PcPrimitive|ber.TagInteger) {
		log.Printf("bad sizelimit: %+v", err)
		return s.writeLDAPResult(msgID, rcProtocolError, "", "bad sizelimit", appSearchDone)
	}
	sizeLimit := ber.BerDecodeInt(sizeTLV.Value)
	if sizeLimit < 0 {
		sizeLimit = 0
	}
	// Fifth: timeLimit in seconds. Decode, clamp to 0+. NOTE: timeLimit is currently parsed but NOT enforced
	timeTLV, err := ber.BerReadTLV(r)
	if err != nil || timeTLV.Tag != (ber.ClassUniversal|ber.PcPrimitive|ber.TagInteger) {
		log.Printf("bad timelimit%+v", err)
		return s.writeLDAPResult(msgID, rcProtocolError, "", "bad timelimit", appSearchDone)
	}
	timeLimitSec := ber.BerDecodeInt(timeTLV.Value)
	if timeLimitSec < 0 {
		timeLimitSec = 0
	}
	// Sixth: typesOnly (BOOLEAN). Booleans in BER are encoded as 0x00 (false) or non-zero (true).
	typesOnlyTLV, err := ber.BerReadTLV(r)
	if err != nil || typesOnlyTLV.Tag != (ber.ClassUniversal|ber.PcPrimitive|ber.TagBoolean) {
		log.Printf("bad typesonly %+v", err)
		return s.writeLDAPResult(msgID, rcProtocolError, "", "bad typesOnly", appSearchDone)
	}
	//  typesOnly indicates if attribute values should be omitted.
	typesOnly := len(typesOnlyTLV.Value) > 0 && typesOnlyTLV.Value[0] != 0x00
	// Seventh: filter (a complex BER structure). Read its TLV; no tag check here yet.
	fTLV, err := ber.BerReadTLV(r)
	if err != nil {
		log.Printf("bad filter: %+v", err)
		return s.writeLDAPResult(msgID, rcProtocolError, "", "bad filter", appSearchDone)
	}
	// Reconstruct the BER encoding of the filter (tag + length + value).
	// Call a custom parseFilter to turn it into some internal filter object. If filter cannot be parsed → protocol error.
	filter, err := parseFilter(append([]byte{fTLV.Tag}, encodeLengthAndValue(fTLV.Value)...))
	if err != nil {
		log.Printf("cannot parse filter: %+v", err)
		return s.writeLDAPResult(msgID, rcProtocolError, "", "cannot parse filter", appSearchDone)
	}
	// Eighth: attribute selection sequence. If present and is a SEQUENCE: Parse each attribute description (OCTET STRING), lowercase each, and append to attrsRequested.
	attrTLV, err := ber.BerReadTLV(r)
	var attrsRequested []string
	if err == nil && attrTLV.Tag == (ber.ClassUniversal|ber.PcConstructed|ber.TagSequence) {
		rr := bytes.NewReader(attrTLV.Value)
		for rr.Len() > 0 {
			a, err := ber.BerReadTLV(rr)
			if err != nil {
				log.Printf("%+v", err)
				break
			}
			if a.Tag == (ber.ClassUniversal | ber.PcPrimitive | ber.TagOctetString) {
				attrsRequested = append(attrsRequested, strings.ToLower(string(a.Value)))
			}
		}
	}
	if err != nil {
		log.Printf("%+v", err)
	}
	// Special attribute “1.1” means “no attributes” (per RFC). noAttrs is true if that is requested.
	noAttrs := contains(attrsRequested, "1.1")
	// Get the current directory snapshot (d).
	d := s.Store.Get()
	/*
		If baseDN is empty and scope is baseObject (0):
			This is a RootDSE search (server meta-info).
			Build a RootDSE entry via buildRootDSE. Send it via writeSearchEntry. Then send a SearchResultDone with success.
	*/
	if baseDN == "" {
		switch scopeVal {
		case 0:
			root := buildRootDSE(d, s.TlsConfig != nil, true)
			if err := s.writeSearchEntry(msgID, root, attrsRequested, typesOnly, noAttrs); err != nil {
				log.Printf("%+v", err)
				return err
			}
			return s.writeLDAPResult(msgID, rcSuccess, "", "", appSearchDone)
		// If scope is oneLevel (1) with empty base, return just the base DN entry.
		case 1:
			if e := d.Get(d.BaseDN); e != nil {
				if err := s.writeSearchEntry(msgID, e, attrsRequested, typesOnly, noAttrs); err != nil {
					log.Printf("%+v", err)
					return err
				}
			}
			return s.writeLDAPResult(msgID, rcSuccess, "", "", appSearchDone)
		// For subtree or other scopes with empty base, default baseDN to directory’s BaseDN.
		default:
			baseDN = d.BaseDN
		}
	}
	// Special case: base = cn=subschema, scope=baseObject. Return the subschema entry built by buildSubschemaEntry.
	if strings.EqualFold(baseDN, "cn=subschema") && scopeVal == 0 {
		ss := buildSubschemaEntry()
		if err := s.writeSearchEntry(msgID, ss, attrsRequested, typesOnly, noAttrs); err != nil {
			log.Printf("%+v", err)
			return err
		}
		return s.writeLDAPResult(msgID, rcSuccess, "", "", appSearchDone)
	}
	// If baseDN doesn’t exist: Send noSuchObject result with matchedDN set to the nearest existing ancestor DN, and return nil (no error).
	if d.Get(baseDN) == nil {
		err = s.writeLDAPResult(msgID, rcNoSuchObject, nearestExistingAncestor(d, baseDN), "no such base DN", appSearchDone)
		if err != nil {
			log.Printf("%+v", err)
		}
		return nil
	}
	// Candidate set based on scope. We build candidate entries to evaluate Scope baseObject: the base entry only, OneLevel: direct children of base, Subtree: all entries in the subtree under base.
	var candidates []*directory.Entry
	switch scopeVal {
	case 0:
		if e := d.Get(baseDN); e != nil {
			candidates = []*directory.Entry{e}
		}
	case 1:
		candidates = d.ChildrenOf(baseDN)
	default:
		candidates = d.Subtree(baseDN)
	}
	// Enforce time/size limits and apply filter
	// Record start time.
	started := time.Now()
	var deadline time.Time
	// If time limit given, calculate a deadline (absolute time).
	if timeLimitSec > 0 {
		deadline = started.Add(time.Duration(timeLimitSec) * time.Second)
	}
	sent := 0
	// Iterate through candidates. If time limit exceeded → send timeLimitExceeded and stop. If size limit reached → send sizeLimitExceeded and stop.
	for _, e := range candidates {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return s.writeLDAPResult(msgID, rcTimeLimitExceeded, "", "time limit exceeded", appSearchDone)
		}
		if sizeLimit > 0 && sent >= sizeLimit {
			return s.writeLDAPResult(msgID, rcSizeLimitExceeded, "", "size limit exceeded", appSearchDone)
		}
		// Copy the entry into ee: Shallow copy struct, then deep-copy the Attrs map and its slices. This ensures we don’t mutate the original directory entries when adding computed attrs.
		ee := *e
		ee.Attrs = make(map[string][]string, len(e.Attrs))
		for k, v := range e.Attrs {
			vv := make([]string, len(v))
			copy(vv, v)
			ee.Attrs[k] = vv
		}
		if mo := d.MemberOf(e.DN); len(mo) > 0 {
			ee.Attrs["memberof"] = mo
		}
		// Augment the entry with a computed memberof attribute listing groups that contain this DN.
		if filter.Match(&ee) {
			// If the filter matches this entry: Send it via writeSearchEntry, increment sent.
			if err := s.writeSearchEntry(msgID, &ee, attrsRequested, typesOnly, noAttrs); err != nil {
				log.Printf("%+v", err)
				return err
			}
			sent++
		}
	}
	// After processing all candidates successfully, send SearchResultDone with rcSuccess.
	return s.writeLDAPResult(msgID, rcSuccess, "", "", appSearchDone)
}

/*
writeSearchEntry: build and send SearchResultEntry.
*/
func (s *Session) writeSearchEntry(msgID int, e *directory.Entry, attrsRequested []string, typesOnly bool, noAttrs bool) error {
	// returnAll is True if client did not request “1.1” (noAttrs is false) AND either no specific attributes requested or * requested.
	returnAll := (!noAttrs) && (len(attrsRequested) == 0 || contains(attrsRequested, "*"))
	// wantMemberOf is True if we return all attrs or if client explicitly asked for “memberof”.
	wantMemberOf := returnAll || contains(attrsRequested, "memberof")
	var memberOfVals []string
	// If we need memberof, compute it here from the directory store.
	if wantMemberOf {
		d := s.Store.Get()
		memberOfVals = d.MemberOf(e.DN)
	}
	attrList := bytes.Buffer{}
	if !noAttrs {
		// If “no attributes” was not requested: Iterate over all attributes in the entry.
		for at, vals := range e.Attrs {
			// If not returning all, only include those explicitly requested.
			if !returnAll && !contains(attrsRequested, strings.ToLower(at)) {
				continue
			}
			// For each attribute, build a SEQUENCE containing the attribute type (name) as string, and a SET of its values (each wrapped as string).
			seq := bytes.Buffer{}
			seq.Write(ber.BerWrapString(at))
			setVals := bytes.Buffer{}
			// If typesOnly is true, omit the values (only descriptions).
			if !typesOnly {
				for _, v := range vals {
					setVals.Write(ber.BerWrapString(v))
				}
			}
			seq.Write(ber.BerWrapTLV(ber.ClassUniversal|ber.PcConstructed|ber.TagSet, setVals.Bytes()))
			// Append that SEQUENCE to attrList.
			attrList.Write(ber.BerWrapSequence(seq.Bytes()))
		}
	}
	// If attributes are allowed and memberof is desired and non-empty, add an attribute named MemberOf (note capital M/O), with values being each group DN.
	if !noAttrs && wantMemberOf && len(memberOfVals) > 0 {
		seq := bytes.Buffer{}
		seq.Write(ber.BerWrapString("MemberOf"))
		setVals := bytes.Buffer{}
		// Again, omit values when typesOnly is true.
		if !typesOnly {
			for _, v := range memberOfVals {
				setVals.Write(ber.BerWrapString(v))
			}
		}
		seq.Write(ber.BerWrapTLV(ber.ClassUniversal|ber.PcConstructed|ber.TagSet, setVals.Bytes()))
		attrList.Write(ber.BerWrapSequence(seq.Bytes()))
	}
	// Create the SearchResultEntry: a SEQUENCE of objectName (DN as string), and attributes (SEQUENCE of attribute SEQUENCEs).
	entrySeq := bytes.Buffer{}
	entrySeq.Write(ber.BerWrapString(e.DN))
	entrySeq.Write(ber.BerWrapSequence(attrList.Bytes()))
	// Wrap with app tag appSearchResEntry.
	resp := ber.BerWrapApp(appSearchResEntry, entrySeq.Bytes())
	// Send via writeLDAPMessage.
	return s.writeLDAPMessage(msgID, resp, nil)
}

// string lookup helper. Checks if slice xs contains s, case-insensitively.
func contains(xs []string, s string) bool {
	s = strings.ToLower(s)
	for _, x := range xs {
		if strings.ToLower(x) == s {
			return true
		}
	}
	return false
}

// LDAP Compare operation
func (s *Session) handleCompare(msgID int, body []byte) error {
	// Parse CompareRequest body from r.
	r := bytes.NewReader(body)
	// First field: entry DN (OCTET STRING). If malformed, protocol error.
	dnTLV, err := ber.BerReadTLV(r)
	if err != nil || dnTLV.Tag != (ber.ClassUniversal|ber.PcPrimitive|ber.TagOctetString) {
		log.Printf("bad compare DN: %+v", err)
		return s.writeLDAPResult(msgID, rcProtocolError, "", "bad compare DN", appCompareResp)
	}
	// Second field: a SEQUENCE containing AttributeValueAssertion.
	seqTLV, err := ber.BerReadTLV(r)
	if err != nil || seqTLV.Tag != (ber.ClassUniversal|ber.PcConstructed|ber.TagSequence) {
		log.Printf("bad compare AVA: %+v", err)
		return s.writeLDAPResult(msgID, rcProtocolError, "", "bad compare AVA", appCompareResp)
	}
	// Wrap its contents in a reader rr.
	rr := bytes.NewReader(seqTLV.Value)
	// Inside the AVA: AttributeDesc (OCTET STRING),AttributeDesc (OCTET STRING). If any tag or read fails, return protocol error.
	attrTLV, err := ber.BerReadTLV(rr)
	if err != nil || attrTLV.Tag != (ber.ClassUniversal|ber.PcPrimitive|ber.TagOctetString) {
		log.Printf("bad compare attr: %+v", err)
		return s.writeLDAPResult(msgID, rcProtocolError, "", "bad compare attr", appCompareResp)
	}
	valTLV, err := ber.BerReadTLV(rr)
	if err != nil || valTLV.Tag != (ber.ClassUniversal|ber.PcPrimitive|ber.TagOctetString) {
		log.Printf("bad compare value: %+v", err)
		return s.writeLDAPResult(msgID, rcProtocolError, "", "bad compare value", appCompareResp)
	}
	// Convert DN and value to strings (Attribute name normalized to lowercase).
	dn := string(dnTLV.Value)
	attr := strings.ToLower(string(attrTLV.Value))
	val := string(valTLV.Value)
	d := s.Store.Get()
	// Fetch directory entry; if not found, respond with noSuchObject.
	e := d.Get(dn)
	if e == nil {
		return s.writeLDAPResult(msgID, rcNoSuchObject, "", "no such DN", appCompareResp)
	}
	match := false
	// Look for case-insensitive match of value val among the attribute’s values.
	for _, v := range e.Attrs[attr] {
		if strings.EqualFold(v, val) {
			match = true
			break
		}
	}
	code := rcCompareFalse
	// If match found, result code is rcCompareTrue. Otherwise rcCompareFalse.
	if match {
		code = rcCompareTrue
	}
	// Send CompareResponse with appropriate code.
	return s.writeLDAPResult(msgID, code, "", "", appCompareResp)
}

/*
This creates attributes for the RootDSE (server metadata entry), with hardcoded objectclasses, vendor info, etc.
namingcontexts set to the directory’s base DN.
Set up empty lists for various capabilities.
*/
func buildRootDSE(d *directory.Directory, tlsEnabled bool, saslPLAIN bool) *directory.Entry {
	attrs := map[string][]string{
		"objectclass":             {"top", "extensibleObject", "rootDSE"},
		"namingcontexts":          {d.BaseDN},
		"supportedldapversion":    {"3"},
		"vendorname":              {"jldap"},
		"vendorversion":           {"0.1"},
		"subschemasubentry":       {"cn=subschema"},
		"supportedcontrol":        {},
		"supportedextension":      {},
		"supportedfeatures":       {},
		"supportedsaslmechanisms": {},
	}
	// Dynamically advertise: (1) StartTLS extension (by its OID) if TLS is configured, (2) SASL PLAIN mechanism if saslPLAIN is true.
	if tlsEnabled {
		attrs["supportedextension"] = append(attrs["supportedextension"], startTLSOID)
	}
	if saslPLAIN {
		attrs["supportedsaslmechanisms"] = append(attrs["supportedsaslmechanisms"], "PLAIN")
	}
	// Root DSE has an empty DN ("") per LDAP convention.
	return &directory.Entry{DN: "", Attrs: attrs}
}

// Returns a minimal subschema entry at DN cn=subschema. Attributes describing schema elements are empty slices (no real schema advertised).
func buildSubschemaEntry() *directory.Entry {
	return &directory.Entry{
		DN: "cn=subschema",
		Attrs: map[string][]string{
			"objectclass":     {"top", "subschema"},
			"cn":              {"subschema"},
			"attributetypes":  {},
			"objectclasses":   {},
			"ldapsyntaxes":    {},
			"matchingrules":   {},
			"matchingruleuse": {},
		},
	}
}

/*
nearestExistingAncestor: used for noSuchObject matchedDN in a noSuchObject LDAP resul
Given a DN, finds the closest ancestor DN that exists in the directory.
*/
func nearestExistingAncestor(d *directory.Directory, dn string) string {
	// Start with cur = dn (trimmed).
	cur := strings.TrimSpace(dn)
	// While cur not empty:
	for cur != "" {
		// If there’s an entry for cur, return it.
		if d.Get(cur) != nil {
			return cur
		}
		// Else strip off the leftmost RDN:
		i := strings.Index(cur, ",")
		// Find first ,
		if i < 0 {
			// If no comma, stop.
			break
		}
		// Set cur to substring after that comma (trimmed).
		cur = strings.TrimSpace(cur[i+1:])
	}
	// If no ancestor found, return empty string.
	return ""
}
