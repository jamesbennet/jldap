package ldap

import (
	"bytes"
	"errors"
	"log"
	"strings"

	"jldap/ber"
	"jldap/directory"
)

/*
The filter interface is anything that can evaluate whether a directory entry matches some condition.
It takes a pointer to an entry and returns true if it matches the filter.
Everything else in this file is different implementations of this interface, plus parsing logic.
*/
type filter interface{ Match(*directory.Entry) bool }

// Represents an LDAP “present” filter: checks whether an attribute is present. Attr is the attribute name to test (e.g. "cn").
type filterPresent struct{ Attr string }

func (f filterPresent) Match(e *directory.Entry) bool {
	// convert the attribute name to lowercase to do case-insensitive lookups in the entry’s attributes map.
	// we ignore the value, just check if the key exists.
	_, ok := e.Attrs[strings.ToLower(f.Attr)]
	// true if the attribute exists; false otherwise.
	return ok
}

// equality (attr=value) filter: attribute must equal value (case insensitive here).
type filterEq struct{ Attr, Value string }

func (f filterEq) Match(e *directory.Entry) bool {
	// Get all values for the attribute Attr, case-insensitive key.
	vals := e.Attrs[strings.ToLower(f.Attr)]
	// Loop over all attribute values.
	for _, v := range vals {
		// Case-insensitive comparison of each value against f.Value. If any value matches, return true.
		if strings.EqualFold(v, f.Value) {
			return true
		}
	}
	// After the loop, if none match, return false.
	return false
}

// logical AND filter. Represents a conjunction: all sub-filters must match. Subs is the slice of child filters.
type filterAnd struct{ Subs []filter }

func (f filterAnd) Match(e *directory.Entry) bool {
	// Iterates over each sub-filter s.
	for _, s := range f.Subs {
		// If any s.Match(e) returns false, the whole AND fails and returns false immediately.
		if !s.Match(e) {
			return false
		}
	}
	// If the loop completes, all sub-filters matched, so returns true.
	return true
}

// logical OR filter: Represents a disjunction: at least one sub-filter must match.
type filterOr struct{ Subs []filter }

// Match Loops through Subs. As soon as one sub-filter matches, returns true. If none match, returns false.
func (f filterOr) Match(e *directory.Entry) bool {
	for _, s := range f.Subs {
		if s.Match(e) {
			return true
		}
	}
	return false
}

// logical NOT filter: Represents logical negation of one child filter.
type filterNot struct{ Sub filter }

// Match Calls Sub.Match(e) and returns its logical negation.
func (f filterNot) Match(e *directory.Entry) bool { return !f.Sub.Match(e) }

/*
filterSubstr Represents a substring LDAP filter: (attr=init*any*any*final)
Pointers for Initial and Final let you distinguish “not provided” vs “empty string”.
*/
type filterSubstr struct {
	Attr    string   // Attribute name.
	Initial *string  // Optional starting substring (prefix).
	Anys    []string // Zero or more middle segments that must appear in order.
	Final   *string  // Optional ending substring (suffix).
}

func (f filterSubstr) Match(e *directory.Entry) bool {
	// Get all values of the attribute (case-insensitive key).
	vals := e.Attrs[strings.ToLower(f.Attr)]
	if len(vals) == 0 {
		// If there are no values, the filter can’t match → false.
		return false
	}
	// Prepare a lowercase version of Initial.
	// If Initial is nil, initLower stays empty and is effectively ignored later.
	initLower := ""
	if f.Initial != nil {
		initLower = strings.ToLower(*f.Initial)
	}
	// Same for Final: lowercase suffix if present.
	finalLower := ""
	if f.Final != nil {
		finalLower = strings.ToLower(*f.Final)
	}
	// Create a new slice anysLower. Convert all “any” segments to lowercase so you can do case-insensitive matching.
	anysLower := make([]string, len(f.Anys))
	for i, s := range f.Anys {
		anysLower[i] = strings.ToLower(s)
	}
	// Loop over each value v of the attribute.
	for _, v := range vals {
		// lv is v lowercased.
		lv := strings.ToLower(v)
		// i is the current index in lv where matching continues.
		i := 0
		if f.Initial != nil {
			// If an initial substring is required, Check that lv starts with initLower. If not, skip this value (continue). If yes, set i to just after the prefix, so subsequent segments must appear after the initial part.
			if !strings.HasPrefix(lv, initLower) {
				continue
			}
			i = len(initLower)
		}
		// Assume this value is OK until proven otherwise
		ok := true
		// For each “any” segment seg: search for seg in lv starting from index i.
		for _, seg := range anysLower {
			idx := strings.Index(lv[i:], seg)
			// If idx < 0, segment not found → set ok = false and break.
			if idx < 0 {
				ok = false
				break
			}
			// Otherwise, advance i to just after the found segment (i += idx + len(seg)), ensuring order of segments is respected.
			i += idx + len(seg)
		}
		// If any “any” segment wasn’t found in order, skip this value and move on to the next.
		if !ok {
			continue
		}
		// If a final substring is required and lv does NOT end with finalLower, skip this value.
		if f.Final != nil && !strings.HasSuffix(lv, finalLower) {
			continue
		}
		// If we reach here for a value, it satisfies initial, any segments, and final (if provided). Return true.
		return true
	}
	// If no values matched, return false.
	return false
}

// wildcard “always match” filter - Empty struct: no data. Represents a filter that matches everything.
type filterAny struct{}

// Match ignores its argument and always returns true.
func (filterAny) Match(*directory.Entry) bool { return true }

/*
parseFilter is the main BER → filter parser.
It takes a BER-encoded LDAP filter in bytes, and recursively builds a filter tree.
*/
func parseFilter(b []byte) (filter, error) {
	// Wrap it in a bytes.Reader for sequential reading.
	r := bytes.NewReader(b)
	// BerReadTLV reads one BER TLV (Tag, Length, Value) from the reader.
	tlv, err := ber.BerReadTLV(r)
	// If the TLV can’t be read, log the error and return it.
	if err != nil {
		log.Printf("%+v", err)
		return nil, err
	}
	// Extract useful fields from the BER tag byte. This is standard BER tag structure: | class (2 bits) | P/C (1 bit) | tag number (5 bits) |.
	// cls - top two bits: the BER class (e.g. universal, application, context-specific).
	cls := tlv.Tag & 0xC0
	// cons – bit 5: constructed vs primitive.
	cons := tlv.Tag & 0x20
	// tag – low 5 bits: the tag number.
	tag := tlv.Tag & 0x1F
	// Now a series of if blocks interpret the tag as specific LDAP filter types.
	// If class is context-specific, constructed, and tag number is 0: In LDAP filter encoding, this usually means “AND (&) filter”.
	if cls == ber.ClassContextSpecific && cons == ber.PcConstructed && tag == 0 {
		var subs []filter
		// tlv.Value is the encoded sequence of sub-filters. rr is a reader over that inner value.
		rr := bytes.NewReader(tlv.Value)
		for rr.Len() > 0 {
			/*
				*While there’s data left in rr:
					*Read each sub-TLV corresponding to a sub-filter.
					*Rebuild minimal BER encoding for this sub-filter:
						* []byte{subTLV.Tag} – prepend the tag.
						* encodeLengthAndValue(subTLV.Value) – compute length bytes + value.
					*Recursively call parseFilter to parse the sub-filter.
					* Append the resulting filter to subs.
			*/
			subTLV, err := ber.BerReadTLV(rr)
			if err != nil {
				log.Printf("%+v", err)
				return nil, err
			}
			sf, err := parseFilter(append([]byte{subTLV.Tag}, encodeLengthAndValue(subTLV.Value)...))
			if err != nil {
				log.Printf("%+v", err)
				return nil, err
			}
			subs = append(subs, sf)
		}
		// After reading all child filters, return a filterAnd containing them.
		return filterAnd{Subs: subs}, nil
	}
	// OR filter (|) - Same idea as the AND case, but tag 1 means OR filter. Reads child TLVs and recursively parses them into filters.
	if cls == ber.ClassContextSpecific && cons == ber.PcConstructed && tag == 1 {
		var subs []filter
		rr := bytes.NewReader(tlv.Value)
		for rr.Len() > 0 {
			subTLV, err := ber.BerReadTLV(rr)
			if err != nil {
				log.Printf("%+v", err)
				return nil, err
			}
			sf, err := parseFilter(append([]byte{subTLV.Tag}, encodeLengthAndValue(subTLV.Value)...))
			if err != nil {
				log.Printf("%+v", err)
				return nil, err
			}
			subs = append(subs, sf)
		}
		return filterOr{Subs: subs}, nil
	}
	// Tag 2 with constructed context-specific class means a NOT filter (!). The value contains exactly one sub-filter.
	if cls == ber.ClassContextSpecific && cons == ber.PcConstructed && tag == 2 {
		// Read that sub-TLV, re-encode minimal BER, parse recursively, then wrap in filterNot.
		rr := bytes.NewReader(tlv.Value)
		subTLV, err := ber.BerReadTLV(rr)
		if err != nil {
			log.Printf("%+v", err)
			return nil, err
		}
		sf, err := parseFilter(append([]byte{subTLV.Tag}, encodeLengthAndValue(subTLV.Value)...))
		if err != nil {
			log.Printf("%+v", err)
			return nil, err
		}
		return filterNot{Sub: sf}, nil
	}
	// Tag 3 means equality filter (attr=value)
	if cls == ber.ClassContextSpecific && cons == ber.PcConstructed && tag == 3 {
		// tlv.Value contains two octet strings: attribute description and assertion value.
		rr := bytes.NewReader(tlv.Value)
		// a – the attribute TLV.
		a, err := ber.BerReadTLV(rr)
		// Check that a.Tag is a primitive universal OCTET STRING (ClassUniversal | PcPrimitive | TagOctetString), otherwise log and error.
		if err != nil || a.Tag != (ber.ClassUniversal|ber.PcPrimitive|ber.TagOctetString) {
			log.Printf("bad equality attr: %+v", err)
			return nil, errors.New("bad equality attr")
		}
		// Read the value TLV and similarly ensure it’s an octet string.
		val, err := ber.BerReadTLV(rr)
		if err != nil || val.Tag != (ber.ClassUniversal|ber.PcPrimitive|ber.TagOctetString) {
			log.Printf("bad equality value: %+v", err)
			return nil, errors.New("bad equality value")
		}
		// Construct a filterEq with Attr: decoded string from a.Value, Value: decoded string from val.Value.
		return filterEq{Attr: string(a.Value), Value: string(val.Value)}, nil
	}
	// Tag 4 means substring filter (attr=foo*bar*baz)
	if cls == ber.ClassContextSpecific && cons == ber.PcConstructed && tag == 4 {
		rr := bytes.NewReader(tlv.Value)
		// First inner TLV is the attribute description at. Again, must be an octet string.
		at, err := ber.BerReadTLV(rr)
		if err != nil || at.Tag != (ber.ClassUniversal|ber.PcPrimitive|ber.TagOctetString) {
			log.Printf("bad substring attr: %+v", err)
			return nil, errors.New("bad substring attr")
		}
		// The second TLV is a SEQUENCE of substring specifications. Check it is universal, constructed, tag Sequence.
		subTLV, err := ber.BerReadTLV(rr)
		if err != nil || subTLV.Tag != (ber.ClassUniversal|ber.PcConstructed|ber.TagSequence) {
			log.Printf("bad substring seq: %+v", err)
			return nil, errors.New("bad substring seq")
		}
		// reader over the contents of the sequence.
		rr2 := bytes.NewReader(subTLV.Value)
		// Prepare variables for the three substring types: initial (0), any (1), final (2).
		var initial *string
		var anys []string
		var final *string
		// Iterate over all child TLVs inside the sequence.
		for rr2.Len() > 0 {
			// ch is each choice (initial/any/final).
			ch, err := ber.BerReadTLV(rr2)
			if err != nil {
				log.Printf("%+v", err)
				return nil, err
			}
			// check high bits: must be context-specific and primitive.
			if (ch.Tag & 0xE0) != ber.ClassContextSpecific|ber.PcPrimitive {
				log.Printf("bad substring choice class")
				return nil, errors.New("bad substring choice class")
			}
			// low 5 bits give the choice number:
			ctag := ch.Tag & 0x1F
			switch ctag {
			// ctag == 0: initial substring → convert to string and assign to initial.
			case 0:
				s := string(ch.Value)
				initial = &s
			// ctag == 1: any substring → append to anys.
			case 1:
				anys = append(anys, string(ch.Value))
			// ctag == 2: final substring → convert to string and assign to final.
			case 2:
				s := string(ch.Value)
				final = &s
			// If an unknown choice tag appears, log and return error.
			default:
				log.Printf("unknown substring choice")
				return nil, errors.New("unknown substring choice")
			}
		}
		// Build and return a filterSubstr with attribute name from at.Value, initial, anys, final as parsed.
		return filterSubstr{
			Attr:    string(at.Value),
			Initial: initial,
			Anys:    anys,
			Final:   final,
		}, nil
	}
	// Tag 7 with primitive context-specific class is a “present” filter (attr=*)
	if cls == ber.ClassContextSpecific && cons == ber.PcPrimitive && tag == 7 {
		// tlv.Value contains the attribute description as octets. Convert to string and return filterPresent.
		return filterPresent{Attr: string(tlv.Value)}, nil
	}
	// Fallback – match everything - If none of the recognized filter types matched, return filterAny{} which matches any entry. Acts as a default “no restriction” filter.
	// NOTE: I did this for compatibility, but we may want to refactor this in the future, as if a client thinks it is sending a restrictive filter but mis-encodes it, we may return more entries than expected instead of failing.
	return filterAny{}, nil
}

/*
encodeLengthAndValue is a BER length encoding helper to produce BER length field + value bytes (L and val).
TODO: move to ber package
*/
func encodeLengthAndValue(val []byte) []byte {
	var b bytes.Buffer
	// L – the length of val.
	L := len(val)
	// If length is less than 128 (0x80): BER “short form” length: one byte giving the length.
	if L < 0x80 {
		b.WriteByte(byte(L))
	} else {
		// Otherwise, use “long form” length.
		// tmp is a temporary array to store length bytes in reverse order.
		var tmp [8]byte
		n := 0
		for x := L; x > 0; x >>= 8 {
			// Take the least-significant byte of L each iteration (x & 0xFF). Store it in tmp[n]. Shift x right by 8 bits until x is 0. n is the number of bytes used.
			tmp[n] = byte(x & 0xFF)
			n++
		}
		// For BER long form, First byte: high bit set (0x80) plus the number of following length bytes (n).
		b.WriteByte(0x80 | byte(n))
		for i := n - 1; i >= 0; i-- {
			// Write the actual length bytes in big-endian order: The loop reverses the order from tmp (which stored them little-endian).
			b.WriteByte(tmp[i])
		}
	}
	// After writing the length, write the value bytes themselves.
	b.Write(val)
	// Finally, return the combined []byte.
	return b.Bytes()
}
