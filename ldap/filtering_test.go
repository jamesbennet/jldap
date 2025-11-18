package ldap

import (
	"bytes"
	"testing"

	"jldap/ber"
	"jldap/directory"
)

/*
stubFilter is a simple helper type used in tests; it implements the
filter interface and always returns the underlying bool when Match is called.
*/
type stubFilter bool

// Match returns the underlying boolean value of the stubFilter.
func (s stubFilter) Match(*directory.Entry) bool { return bool(s) }

/*
TestFilterPresentMatch verifies that filterPresent correctly matches
when an attribute is present (case-insensitive) and does not match
when the attribute is missing.
*/
func TestFilterPresentMatch(t *testing.T) {
	entry := &directory.Entry{
		Attrs: map[string][]string{
			"cn":   {"John Doe"},
			"mail": {"john@example.com"},
		},
	}

	f1 := filterPresent{Attr: "CN"} // case-insensitive
	if !f1.Match(entry) {
		t.Fatalf("expected filterPresent to match when attribute is present")
	}

	f2 := filterPresent{Attr: "sn"} // missing
	if f2.Match(entry) {
		t.Fatalf("expected filterPresent not to match when attribute is absent")
	}
}

/*
TestFilterEqMatch verifies that filterEq correctly matches entries
when at least one value equals (case-insensitive) and fails when
no value matches or the attribute is absent.
*/
func TestFilterEqMatch(t *testing.T) {
	entry := &directory.Entry{
		Attrs: map[string][]string{
			"cn":   {"John Doe", "JD"},
			"mail": {"john@example.com"},
		},
	}

	// Should match (case-insensitive, second value)
	f1 := filterEq{Attr: "CN", Value: "jd"}
	if !f1.Match(entry) {
		t.Fatalf("expected filterEq to match when one value is equal (case-insensitive)")
	}

	// Should not match (different value)
	f2 := filterEq{Attr: "cn", Value: "Jane"}
	if f2.Match(entry) {
		t.Fatalf("expected filterEq not to match when values differ")
	}

	// Should not match (attribute absent)
	f3 := filterEq{Attr: "sn", Value: "Doe"}
	if f3.Match(entry) {
		t.Fatalf("expected filterEq not to match when attribute is missing")
	}
}

/*
TestFilterAndMatch verifies that filterAnd returns true only when
all sub-filters match, returns false when any sub-filter fails,
and handles the edge case of zero sub-filters as true (vacuous truth).
*/
func TestFilterAndMatch(t *testing.T) {
	entry := &directory.Entry{Attrs: map[string][]string{}}

	// All true -> match
	fAllTrue := filterAnd{Subs: []filter{stubFilter(true), stubFilter(true)}}
	if !fAllTrue.Match(entry) {
		t.Fatalf("expected filterAnd with all true subs to match")
	}

	// One false -> no match
	fOneFalse := filterAnd{Subs: []filter{stubFilter(true), stubFilter(false)}}
	if fOneFalse.Match(entry) {
		t.Fatalf("expected filterAnd with a false sub to fail")
	}

	// No subs -> true (vacuous truth)
	fEmpty := filterAnd{Subs: nil}
	if !fEmpty.Match(entry) {
		t.Fatalf("expected filterAnd with no subs to match (vacuous truth)")
	}
}

/*
TestFilterOrMatch verifies that filterOr returns true when at least
one sub-filter matches, false when none match, and handles the edge
case of zero sub-filters as false.
*/
func TestFilterOrMatch(t *testing.T) {
	entry := &directory.Entry{Attrs: map[string][]string{}}

	// One true -> match
	fOneTrue := filterOr{Subs: []filter{stubFilter(false), stubFilter(true)}}
	if !fOneTrue.Match(entry) {
		t.Fatalf("expected filterOr with one true sub to match")
	}

	// All false -> no match
	fAllFalse := filterOr{Subs: []filter{stubFilter(false), stubFilter(false)}}
	if fAllFalse.Match(entry) {
		t.Fatalf("expected filterOr with all false subs to fail")
	}

	// No subs -> false
	fEmpty := filterOr{Subs: nil}
	if fEmpty.Match(entry) {
		t.Fatalf("expected filterOr with no subs to fail")
	}
}

/*
TestFilterNotMatch verifies that filterNot correctly negates
the result of its underlying sub-filter.
*/
func TestFilterNotMatch(t *testing.T) {
	entry := &directory.Entry{Attrs: map[string][]string{}}

	fTrue := filterNot{Sub: stubFilter(true)}
	if fTrue.Match(entry) {
		t.Fatalf("expected filterNot with true sub to return false")
	}

	fFalse := filterNot{Sub: stubFilter(false)}
	if !fFalse.Match(entry) {
		t.Fatalf("expected filterNot with false sub to return true")
	}
}

/*
TestFilterAnyMatch verifies that filterAny always returns true
regardless of the directory entry content.
*/
func TestFilterAnyMatch(t *testing.T) {
	entry := &directory.Entry{
		Attrs: map[string][]string{
			"cn": {"anything"},
		},
	}
	var f filter = filterAny{}
	if !f.Match(entry) {
		t.Fatalf("expected filterAny to always match")
	}
}

/*
TestFilterSubstrMatchBasic verifies that filterSubstr correctly
matches on initial, any, and final components, and behaves as expected
when attributes are missing or cases differ.
*/
func TestFilterSubstrMatchBasic(t *testing.T) {
	entry := &directory.Entry{
		Attrs: map[string][]string{
			"cn": {"AbCdEfGh", "fooBARbaz"},
		},
	}

	// initial only (case-insensitive, should match "AbCdEfGh")
	init := "ab"
	fInitial := filterSubstr{Attr: "CN", Initial: &init}
	if !fInitial.Match(entry) {
		t.Fatalf("expected substring filter with initial to match")
	}

	// final only (should match "fooBARbaz")
	final := "BAZ"
	fFinal := filterSubstr{Attr: "cn", Final: &final}
	if !fFinal.Match(entry) {
		t.Fatalf("expected substring filter with final to match")
	}

	// any only (should match "AbCdEfGh" via "cd" and "ef")
	fAny := filterSubstr{Attr: "cn", Anys: []string{"cD", "E"}}
	if !fAny.Match(entry) {
		t.Fatalf("expected substring filter with any segments to match")
	}

	// attribute missing -> false
	fMissing := filterSubstr{Attr: "sn", Initial: &init}
	if fMissing.Match(entry) {
		t.Fatalf("expected substring filter not to match when attribute is missing")
	}
}

/*
TestFilterSubstrMatchComplex verifies that filterSubstr correctly
handles a full combination of Initial + multiple Anys + Final,
including failure paths when segments are out of order.
*/
func TestFilterSubstrMatchComplex(t *testing.T) {
	entry := &directory.Entry{
		Attrs: map[string][]string{
			"cn": {"start-middle-foo-bar-end", "something else"},
		},
	}

	initial := "start"
	final := "END"
	anys := []string{"middle", "foo", "bar"}

	// Full pattern should match "start-middle-foo-bar-end"
	f := filterSubstr{
		Attr:    "cn",
		Initial: &initial,
		Anys:    anys,
		Final:   &final,
	}
	if !f.Match(entry) {
		t.Fatalf("expected complex substring filter to match")
	}

	// Reorder anys -> should not match (order enforced)
	badOrder := []string{"foo", "middle", "bar"}
	fBad := filterSubstr{
		Attr:    "cn",
		Initial: &initial,
		Anys:    badOrder,
		Final:   &final,
	}
	if fBad.Match(entry) {
		t.Fatalf("expected substring filter with wrong any order to fail")
	}
}

/*
TestEncodeLengthAndValueShortForm verifies that encodeLengthAndValue
uses BER short form for lengths < 128 and correctly appends the value.
*/
func TestEncodeLengthAndValueShortForm(t *testing.T) {
	val := []byte{0x01, 0x02, 0x03}
	out := encodeLengthAndValue(val)

	if len(out) != 1+len(val) {
		t.Fatalf("expected total length %d, got %d", 1+len(val), len(out))
	}
	if out[0] != byte(len(val)) {
		t.Fatalf("expected short-form length %d, got %d", len(val), out[0])
	}
	if !bytes.Equal(out[1:], val) {
		t.Fatalf("expected value bytes %v, got %v", val, out[1:])
	}
}

/*
TestEncodeLengthAndValueLongForm verifies that encodeLengthAndValue
uses BER long form for lengths >= 128 and encodes the length in
big-endian order before the value.
*/
func TestEncodeLengthAndValueLongForm(t *testing.T) {
	val := make([]byte, 130) // 0x82
	out := encodeLengthAndValue(val)

	if len(out) != 2+len(val) {
		t.Fatalf("expected total length %d, got %d", 2+len(val), len(out))
	}

	// First byte: 0x80 | 1 = 0x81 (one length octet follows)
	if out[0] != 0x81 {
		t.Fatalf("expected long-form length indicator 0x81, got 0x%X", out[0])
	}

	// Second byte: the actual length 130 (0x82)
	if out[1] != 130 {
		t.Fatalf("expected length byte 130, got %d", out[1])
	}

	if !bytes.Equal(out[2:], val) {
		t.Fatalf("expected value bytes of length %d, got %d", len(val), len(out[2:]))
	}
}

/*
helperBuildEqualityFilterTLV builds a BER-encoded equality filter
(attr=value) using the same tag conventions that parseFilter expects.
This is used throughout the tests to generate valid sub-filters.
*/
func helperBuildEqualityFilterTLV(attr, value string) []byte {
	attrVal := []byte(attr)
	valueVal := []byte(value)

	attrTag := byte(ber.ClassUniversal | ber.PcPrimitive | ber.TagOctetString)
	valTag := byte(ber.ClassUniversal | ber.PcPrimitive | ber.TagOctetString)

	attrTLV := append([]byte{attrTag}, encodeLengthAndValue(attrVal)...)
	valTLV := append([]byte{valTag}, encodeLengthAndValue(valueVal)...)

	inner := append(attrTLV, valTLV...)
	outerTag := byte(ber.ClassContextSpecific | ber.PcConstructed | 3)

	return append([]byte{outerTag}, encodeLengthAndValue(inner)...)
}

/*
helperBuildSubstringFilterTLV builds a BER-encoded substring filter
(attr=initial*any*...*final) with optional components, using the
tag conventions expected by parseFilter.
*/
func helperBuildSubstringFilterTLV(attr string, initial *string, anys []string, final *string) []byte {
	attrVal := []byte(attr)
	attrTag := byte(ber.ClassUniversal | ber.PcPrimitive | ber.TagOctetString)
	attrTLV := append([]byte{attrTag}, encodeLengthAndValue(attrVal)...)

	var seqValue []byte

	if initial != nil {
		tag := byte(ber.ClassContextSpecific | ber.PcPrimitive | 0)
		seqValue = append(seqValue, tag)
		seqValue = append(seqValue, encodeLengthAndValue([]byte(*initial))...)
	}

	for _, a := range anys {
		tag := byte(ber.ClassContextSpecific | ber.PcPrimitive | 1)
		seqValue = append(seqValue, tag)
		seqValue = append(seqValue, encodeLengthAndValue([]byte(a))...)
	}

	if final != nil {
		tag := byte(ber.ClassContextSpecific | ber.PcPrimitive | 2)
		seqValue = append(seqValue, tag)
		seqValue = append(seqValue, encodeLengthAndValue([]byte(*final))...)
	}

	seqTag := byte(ber.ClassUniversal | ber.PcConstructed | ber.TagSequence)
	seqTLV := append([]byte{seqTag}, encodeLengthAndValue(seqValue)...)

	inner := append(attrTLV, seqTLV...)
	outerTag := byte(ber.ClassContextSpecific | ber.PcConstructed | 4)
	return append([]byte{outerTag}, encodeLengthAndValue(inner)...)
}

/*
TestParseFilterEqualitySuccess verifies that parseFilter correctly
parses a valid BER-encoded equality filter into a filterEq instance.
*/
func TestParseFilterEqualitySuccess(t *testing.T) {
	b := helperBuildEqualityFilterTLV("cn", "John")

	f, err := parseFilter(b)
	if err != nil {
		t.Fatalf("unexpected error parsing equality filter: %v", err)
	}

	feq, ok := f.(filterEq)
	if !ok {
		t.Fatalf("expected filter type filterEq, got %T", f)
	}

	if feq.Attr != "cn" || feq.Value != "John" {
		t.Fatalf("unexpected filterEq content: %+v", feq)
	}
}

/*
TestParseFilterEqualityBadAttr verifies that parseFilter returns
an error when the attribute TLV in an equality filter has an
incorrect tag (non-primitive-octet-string).
*/
func TestParseFilterEqualityBadAttr(t *testing.T) {
	attrVal := []byte("cn")
	valueVal := []byte("John")

	// Wrong tag for attr: use constructed OCTET STRING instead of primitive.
	attrTag := byte(ber.ClassUniversal | ber.PcConstructed | ber.TagOctetString)
	valTag := byte(ber.ClassUniversal | ber.PcPrimitive | ber.TagOctetString)

	attrTLV := append([]byte{attrTag}, encodeLengthAndValue(attrVal)...)
	valTLV := append([]byte{valTag}, encodeLengthAndValue(valueVal)...)

	inner := append(attrTLV, valTLV...)
	outerTag := byte(ber.ClassContextSpecific | ber.PcConstructed | 3)
	b := append([]byte{outerTag}, encodeLengthAndValue(inner)...)

	f, err := parseFilter(b)
	if err == nil || f != nil {
		t.Fatalf("expected error for bad equality attr tag, got filter=%T, err=%v", f, err)
	}
}

/*
TestParseFilterEqualityBadValue verifies that parseFilter returns
an error when the value TLV in an equality filter has an incorrect
tag (non-primitive-octet-string).
*/
func TestParseFilterEqualityBadValue(t *testing.T) {
	attrVal := []byte("cn")
	valueVal := []byte("John")

	attrTag := byte(ber.ClassUniversal | ber.PcPrimitive | ber.TagOctetString)
	// Wrong tag for value: use constructed OCTET STRING instead of primitive.
	valTag := byte(ber.ClassUniversal | ber.PcConstructed | ber.TagOctetString)

	attrTLV := append([]byte{attrTag}, encodeLengthAndValue(attrVal)...)
	valTLV := append([]byte{valTag}, encodeLengthAndValue(valueVal)...)

	inner := append(attrTLV, valTLV...)
	outerTag := byte(ber.ClassContextSpecific | ber.PcConstructed | 3)
	b := append([]byte{outerTag}, encodeLengthAndValue(inner)...)

	f, err := parseFilter(b)
	if err == nil || f != nil {
		t.Fatalf("expected error for bad equality value tag, got filter=%T, err=%v", f, err)
	}
}

/*
TestParseFilterSubstringSuccess verifies that parseFilter correctly
parses a valid BER-encoded substring filter into a filterSubstr and
that the resulting filter matches an appropriate entry.
*/
func TestParseFilterSubstringSuccess(t *testing.T) {
	init := "start"
	anys := []string{"mid", "foo"}
	final := "END"

	b := helperBuildSubstringFilterTLV("cn", &init, anys, &final)

	f, err := parseFilter(b)
	if err != nil {
		t.Fatalf("unexpected error parsing substring filter: %v", err)
	}

	fs, ok := f.(filterSubstr)
	if !ok {
		t.Fatalf("expected filter type filterSubstr, got %T", f)
	}

	if fs.Attr != "cn" {
		t.Fatalf("unexpected filterSubstr Attr: %s", fs.Attr)
	}

	entry := &directory.Entry{
		Attrs: map[string][]string{
			"cn": {"start-mid-foo-END"},
		},
	}

	if !fs.Match(entry) {
		t.Fatalf("expected parsed substring filter to match entry")
	}
}

/*
TestParseFilterSubstringBadAttr verifies that parseFilter detects
and errors when the substring filter's attribute TLV has the wrong
tag (non-octet-string).
*/
func TestParseFilterSubstringBadAttr(t *testing.T) {
	init := "x"

	// attr TLV with wrong tag (constructed instead of primitive)
	attrVal := []byte("cn")
	attrTag := byte(ber.ClassUniversal | ber.PcConstructed | ber.TagOctetString)
	attrTLV := append([]byte{attrTag}, encodeLengthAndValue(attrVal)...)

	// proper initial choice
	initTag := byte(ber.ClassContextSpecific | ber.PcPrimitive | 0)
	initTLV := append([]byte{initTag}, encodeLengthAndValue([]byte(init))...)

	seqTag := byte(ber.ClassUniversal | ber.PcConstructed | ber.TagSequence)
	seqTLV := append([]byte{seqTag}, encodeLengthAndValue(initTLV)...)

	inner := append(attrTLV, seqTLV...)
	outerTag := byte(ber.ClassContextSpecific | ber.PcConstructed | 4)
	b := append([]byte{outerTag}, encodeLengthAndValue(inner)...)

	f, err := parseFilter(b)
	if err == nil || f != nil {
		t.Fatalf("expected error for bad substring attr tag, got filter=%T, err=%v", f, err)
	}
}

/*
TestParseFilterSubstringBadSeq verifies that parseFilter detects
and errors when the substring filter's second TLV is not a SEQUENCE
(as required by the LDAP substring filter encoding).
*/
func TestParseFilterSubstringBadSeq(t *testing.T) {
	attrVal := []byte("cn")
	attrTag := byte(ber.ClassUniversal | ber.PcPrimitive | ber.TagOctetString)
	attrTLV := append([]byte{attrTag}, encodeLengthAndValue(attrVal)...)

	// Wrong second TLV: use OCTET STRING instead of SEQUENCE.
	seqVal := []byte("not-a-sequence")
	seqTagWrong := byte(ber.ClassUniversal | ber.PcPrimitive | ber.TagOctetString)
	seqTLVWrong := append([]byte{seqTagWrong}, encodeLengthAndValue(seqVal)...)

	inner := append(attrTLV, seqTLVWrong...)
	outerTag := byte(ber.ClassContextSpecific | ber.PcConstructed | 4)
	b := append([]byte{outerTag}, encodeLengthAndValue(inner)...)

	f, err := parseFilter(b)
	if err == nil || f != nil {
		t.Fatalf("expected error for bad substring sequence, got filter=%T, err=%v", f, err)
	}
}

/*
TestParseFilterSubstringBadChoiceClass verifies that parseFilter
detects and errors when a substring choice inside the sequence has
the wrong class (must be context-specific primitive).
*/
func TestParseFilterSubstringBadChoiceClass(t *testing.T) {
	attrVal := []byte("cn")
	attrTag := byte(ber.ClassUniversal | ber.PcPrimitive | ber.TagOctetString)
	attrTLV := append([]byte{attrTag}, encodeLengthAndValue(attrVal)...)

	// Inside the sequence, use a UNIVERSAL OCTET STRING instead of
	// CONTEXT-SPECIFIC primitive tag, which should trigger the
	// "bad substring choice class" path.
	badChoiceVal := []byte("x")
	badChoiceTag := byte(ber.ClassUniversal | ber.PcPrimitive | ber.TagOctetString)
	badChoiceTLV := append([]byte{badChoiceTag}, encodeLengthAndValue(badChoiceVal)...)

	seqTag := byte(ber.ClassUniversal | ber.PcConstructed | ber.TagSequence)
	seqTLV := append([]byte{seqTag}, encodeLengthAndValue(badChoiceTLV)...)

	inner := append(attrTLV, seqTLV...)
	outerTag := byte(ber.ClassContextSpecific | ber.PcConstructed | 4)
	b := append([]byte{outerTag}, encodeLengthAndValue(inner)...)

	f, err := parseFilter(b)
	if err == nil || f != nil {
		t.Fatalf("expected error for bad substring choice class, got filter=%T, err=%v", f, err)
	}
}

/*
TestParseFilterSubstringUnknownChoice verifies that parseFilter detects and errors when a substring choice has an
unknown context-specific tag number (not 0, 1, or 2).
*/
func TestParseFilterSubstringUnknownChoice(t *testing.T) {
	attrVal := []byte("cn")
	attrTag := byte(ber.ClassUniversal | ber.PcPrimitive | ber.TagOctetString)
	attrTLV := append([]byte{attrTag}, encodeLengthAndValue(attrVal)...)

	// Unknown choice: CONTEXT-SPECIFIC primitive tag with tag number 5.
	unknownChoiceVal := []byte("x")
	unknownChoiceTag := byte(ber.ClassContextSpecific | ber.PcPrimitive | 5)
	unknownChoiceTLV := append([]byte{unknownChoiceTag}, encodeLengthAndValue(unknownChoiceVal)...)

	seqTag := byte(ber.ClassUniversal | ber.PcConstructed | ber.TagSequence)
	seqTLV := append([]byte{seqTag}, encodeLengthAndValue(unknownChoiceTLV)...)

	inner := append(attrTLV, seqTLV...)
	outerTag := byte(ber.ClassContextSpecific | ber.PcConstructed | 4)
	b := append([]byte{outerTag}, encodeLengthAndValue(inner)...)

	f, err := parseFilter(b)
	if err == nil || f != nil {
		t.Fatalf("expected error for unknown substring choice, got filter=%T, err=%v", f, err)
	}
}

/*
TestParseFilterPresentSuccess verifies that parseFilter correctly
parses a BER-encoded present filter (attr=*) into a filterPresent.
*/
func TestParseFilterPresentSuccess(t *testing.T) {
	val := []byte("cn") // attribute name
	tag := byte(ber.ClassContextSpecific | ber.PcPrimitive | 7)
	b := append([]byte{tag}, encodeLengthAndValue(val)...)

	f, err := parseFilter(b)
	if err != nil {
		t.Fatalf("unexpected error parsing present filter: %v", err)
	}

	fp, ok := f.(filterPresent)
	if !ok {
		t.Fatalf("expected filter type filterPresent, got %T", f)
	}

	if fp.Attr != "cn" {
		t.Fatalf("unexpected filterPresent Attr: %s", fp.Attr)
	}
}

/*
TestParseFilterAndOrNotSuccess verifies that parseFilter correctly
parses BER-encoded AND, OR, and NOT filters wrapping equality filters,
and that the resulting composite filters behave as expected when
matching entries.
*/
func TestParseFilterAndOrNotSuccess(t *testing.T) {
	// Build two equality subfilters.
	eq1 := helperBuildEqualityFilterTLV("cn", "John")
	eq2 := helperBuildEqualityFilterTLV("sn", "Doe")

	// AND: (&(cn=John)(sn=Doe))
	andInner := append(eq1, eq2...)
	andTag := byte(ber.ClassContextSpecific | ber.PcConstructed | 0)
	andBytes := append([]byte{andTag}, encodeLengthAndValue(andInner)...)

	fAnd, err := parseFilter(andBytes)
	if err != nil {
		t.Fatalf("unexpected error parsing AND filter: %v", err)
	}
	fa, ok := fAnd.(filterAnd)
	if !ok || len(fa.Subs) != 2 {
		t.Fatalf("expected filterAnd with 2 subs, got %+v (type %T)", fAnd, fAnd)
	}

	entryMatch := &directory.Entry{
		Attrs: map[string][]string{
			"cn": {"John"},
			"sn": {"Doe"},
		},
	}
	entryOnlyCN := &directory.Entry{
		Attrs: map[string][]string{
			"cn": {"John"},
		},
	}

	if !fAnd.Match(entryMatch) {
		t.Fatalf("expected AND filter to match when both conditions are true")
	}
	if fAnd.Match(entryOnlyCN) {
		t.Fatalf("expected AND filter not to match when one condition is missing")
	}

	// OR: (|(cn=John)(sn=Doe))
	orInner := append(eq1, eq2...)
	orTag := byte(ber.ClassContextSpecific | ber.PcConstructed | 1)
	orBytes := append([]byte{orTag}, encodeLengthAndValue(orInner)...)

	fOr, err := parseFilter(orBytes)
	if err != nil {
		t.Fatalf("unexpected error parsing OR filter: %v", err)
	}

	if !fOr.Match(entryMatch) {
		t.Fatalf("expected OR filter to match when both conditions are true")
	}
	if !fOr.Match(entryOnlyCN) {
		t.Fatalf("expected OR filter to match when one condition is true")
	}

	// NOT: (!(cn=John))
	notInner := eq1
	notTag := byte(ber.ClassContextSpecific | ber.PcConstructed | 2)
	notBytes := append([]byte{notTag}, encodeLengthAndValue(notInner)...)

	fNot, err := parseFilter(notBytes)
	if err != nil {
		t.Fatalf("unexpected error parsing NOT filter: %v", err)
	}

	// Entry where (cn=John) is true -> NOT must be false.
	if fNot.Match(entryMatch) {
		t.Fatalf("expected NOT filter not to match when equality is true")
	}

	// Entry where (cn=John) is false -> NOT must be true.
	entryNotEq := &directory.Entry{
		Attrs: map[string][]string{
			"cn": {"Jane"},
		},
	}
	if !fNot.Match(entryNotEq) {
		t.Fatalf("expected NOT filter to match when equality is false")
	}
}

/*
TestParseFilterFallbackToAny verifies that when parseFilter receives
an unrecognized context-specific tag, it falls back to the
filterAny implementation, which matches all entries.
*/
func TestParseFilterFallbackToAny(t *testing.T) {
	// Use a random context-specific primitive tag number that is
	// not handled (e.g., tag = 5).
	tag := byte(ber.ClassContextSpecific | ber.PcPrimitive | 5)
	val := []byte("ignored")
	b := append([]byte{tag}, encodeLengthAndValue(val)...)

	f, err := parseFilter(b)
	if err != nil {
		t.Fatalf("did not expect error for unknown tag; should fall back to filterAny: %v", err)
	}

	entry := &directory.Entry{Attrs: map[string][]string{}}
	if !f.Match(entry) {
		t.Fatalf("expected fallback filterAny to match")
	}
}

/*
TestParseFilterTopLevelError verifies that parseFilter properly
returns an error when the top-level BER TLV cannot be read, such
as when an empty byte slice is provided.
*/
func TestParseFilterTopLevelError(t *testing.T) {
	// Empty input should cause BerReadTLV to fail.
	_, err := parseFilter(nil)
	if err == nil {
		t.Fatalf("expected error for empty BER input")
	}
}
