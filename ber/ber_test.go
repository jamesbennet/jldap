package ber

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"testing"
)

// --- berEncodeInteger / BerWrapInteger / BerWrapEnum ---

/*
TestBerEncodeInteger_PositiveValues verifies that berEncodeInteger encodes
various non-negative integers into the correct BER INTEGER content bytes.

It checks:
- 0 is encoded as a single 0x00.
- Small positives fit in one byte.
- The largest 7-bit value (127) does not need padding.
- 128 is encoded with a leading 0x00 to avoid being interpreted as negative.
- Larger values (256, 0x123456) are encoded as minimal big-endian byte sequences.
This ensures correct minimal-length, big-endian integer content encoding.
*/
func TestBerEncodeInteger_PositiveValues(t *testing.T) {
	tests := []struct {
		name string
		v    int
		want []byte
	}{
		{
			name: "zero",
			v:    0,
			// 0 is encoded as single 0x00
			want: []byte{0x00},
		},
		{
			name: "small positive",
			v:    5,
			want: []byte{0x05},
		},
		{
			name: "max 7-bit (127)",
			v:    127,
			want: []byte{0x7F},
		},
		{
			name: "128 requires leading zero to avoid negative sign",
			v:    128,
			// 0x80 with sign bit set -> must be padded with 0x00
			want: []byte{0x00, 0x80},
		},
		{
			name: "256",
			v:    256,
			// big endian 0x0100
			want: []byte{0x01, 0x00},
		},
		{
			name: "big number",
			v:    0x123456,
			want: []byte{0x12, 0x34, 0x56},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := berEncodeInteger(tt.v)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("berEncodeInteger(%d) = % X, want % X", tt.v, got, tt.want)
			}
		})
	}
}

/*
TestBerWrapInteger_Encoding verifies that BerWrapInteger produces a complete
TLV-encoded INTEGER:

- Tag is the universal primitive INTEGER tag (0x02).
- Length is correctly encoded in short form.
- Value is the BER-encoded integer content (using berEncodeInteger).

It covers:
- 0, 5 as simple single-byte values.
- 128 which requires a leading 0x00 in the value.
- 300 (0x012C) as a multibyte big-endian value.
*/
func TestBerWrapInteger_Encoding(t *testing.T) {
	tests := []struct {
		name string
		v    int
		want []byte
	}{
		{
			name: "INTEGER 5",
			v:    5,
			// Tag: 0x02 (Universal, Primitive, INTEGER)
			// Value: 0x05
			// Length: 1
			want: []byte{0x02, 0x01, 0x05},
		},
		{
			name: "INTEGER 0",
			v:    0,
			want: []byte{0x02, 0x01, 0x00},
		},
		{
			name: "INTEGER 128 (needs leading zero in value)",
			v:    128,
			// value: 00 80
			want: []byte{0x02, 0x02, 0x00, 0x80},
		},
		{
			name: "INTEGER 300 (0x012C)",
			v:    300,
			// value: 0x01 0x2C
			want: []byte{0x02, 0x02, 0x01, 0x2C},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := BerWrapInteger(tt.v)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("BerWrapInteger(%d) = % X, want % X", tt.v, got, tt.want)
			}
		})
	}
}

/*
TestBerWrapEnum_Encoding verifies that BerWrapEnum uses the ENUMERATED tag
(0x0A) and encodes the enum value exactly like an INTEGER content, with
correct short-form length and value bytes.
*/
func TestBerWrapEnum_Encoding(t *testing.T) {
	// ENUM value 3
	got := BerWrapEnum(3)
	// Tag: 0x0A (Universal, Primitive, ENUMERATED)
	// Length: 1
	// Value: 0x03
	want := []byte{0x0A, 0x01, 0x03}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BerWrapEnum(3) = % X, want % X", got, want)
	}
}

// --- OCTET STRING / STRING / SEQUENCE / APP / CTX ---

/*
TestBerWrapOctetAndString verifies the OCTET STRING wrappers:

  - berWrapOctet encodes an arbitrary []byte with universal primitive
    OCTET STRING tag (0x04) and short-form length.
  - BerWrapString wraps a Go string by converting it to []byte and then
    encoding as an OCTET STRING.

Both tests check tag, length, and value layout.
*/
func TestBerWrapOctetAndString(t *testing.T) {
	octets := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	gotOctet := berWrapOctet(octets)
	wantOctet := append([]byte{0x04, byte(len(octets))}, octets...)
	if !reflect.DeepEqual(gotOctet, wantOctet) {
		t.Fatalf("berWrapOctet() = % X, want % X", gotOctet, wantOctet)
	}

	str := "Hi"
	gotStr := BerWrapString(str)
	wantStr := []byte{0x04, 0x02, 'H', 'i'}
	if !reflect.DeepEqual(gotStr, wantStr) {
		t.Fatalf("BerWrapString() = % X, want % X", gotStr, wantStr)
	}
}

/*
TestBerWrapSequence verifies that BerWrapSequence wraps pre-encoded inner TLVs
inside a SEQUENCE:

- Tag is universal constructed SEQUENCE (0x30).
- Length is the length of the inner payload.
- Value is the exact inner TLVs passed in.
*/
func TestBerWrapSequence(t *testing.T) {
	inner := BerWrapInteger(5) // 02 01 05
	got := BerWrapSequence(inner)
	// Tag: 0x30 (Universal, Constructed, SEQUENCE)
	// Length: 3
	// Value: 02 01 05
	want := []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BerWrapSequence() = % X, want % X", got, want)
	}
}

/*
TestBerWrapApp verifies that BerWrapApp correctly builds an APPLICATION-class
constructed tag and wraps the provided inner contents:

- Tag = ClassApplication | PcConstructed | tagNumber.
- Length = len(inner).
- Value = inner.
*/
func TestBerWrapApp(t *testing.T) {
	inner := BerWrapInteger(42) // 02 01 2A
	got := BerWrapApp(0x01, inner)
	// Tag: classApplication(0x40) | pcConstructed(0x20) | tag(0x01) = 0x61
	// Length: len(inner) = 3
	want := append([]byte{0x61, 0x03}, inner...)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BerWrapApp() = % X, want % X", got, want)
	}
}

/*
TestBerWrapCtx_PrimitiveAndConstructed verifies that BerWrapCtx correctly
constructs context-specific tags for both primitive and constructed forms:

- For primitive: tag byte = ClassContextSpecific | PcPrimitive | tagNumber.
- For constructed: tag byte = ClassContextSpecific | PcConstructed | tagNumber.
- Length is the length of the inner payload; value is the inner bytes.
*/
func TestBerWrapCtx_PrimitiveAndConstructed(t *testing.T) {
	inner := BerWrapInteger(7) // 02 01 07

	t.Run("primitive", func(t *testing.T) {
		got := BerWrapCtx(1, inner, false)
		// Tag: classContextSpecific(0x80) | pcPrimitive(0x00) | tag(1) = 0x81
		want := append([]byte{0x81, byte(len(inner))}, inner...)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("BerWrapCtx primitive = % X, want % X", got, want)
		}
	})

	t.Run("constructed", func(t *testing.T) {
		got := BerWrapCtx(1, inner, true)
		// Tag: classContextSpecific(0x80) | pcConstructed(0x20) | tag(1) = 0xA1
		want := append([]byte{0xA1, byte(len(inner))}, inner...)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("BerWrapCtx constructed = % X, want % X", got, want)
		}
	})
}

// --- BerDecodeInt ---

/*
TestBerDecodeInt verifies that BerDecodeInt correctly interprets byte slices
as big-endian unsigned integers.

It checks:
- Single-byte values (0, 1, 127).
- Values with a leading 0x00 (128).
- Multi-byte big-endian values (256, 0x123456).

This ensures the decode helper matches the encoding expectations.
*/
func TestBerDecodeInt(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int
	}{
		{"zero", []byte{0x00}, 0},
		{"one", []byte{0x01}, 1},
		{"127", []byte{0x7F}, 127},
		{"128", []byte{0x00, 0x80}, 128},
		{"256", []byte{0x01, 0x00}, 256},
		{"0x123456", []byte{0x12, 0x34, 0x56}, 0x123456},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := BerDecodeInt(tt.in)
			if got != tt.want {
				t.Fatalf("BerDecodeInt(% X) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// --- berWriteTLV + BerWrapTLV (short/long form length) ---

/*
TestBerWrapTLV_ShortFormLength verifies that BerWrapTLV produces a correct
short-form length encoding when the value length is < 128:

- Tag is what we pass in.
- Length is 1 byte, equal to len(value).
- Value bytes follow as-is.
*/
func TestBerWrapTLV_ShortFormLength(t *testing.T) {
	val := []byte{0xAA, 0xBB, 0xCC}
	got := BerWrapTLV(0x10, val)
	// Tag: 0x10, Length: 3, Value: AA BB CC
	want := append([]byte{0x10, 0x03}, val...)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BerWrapTLV short = % X, want % X", got, want)
	}
}

/*
TestBerWrapTLV_LongFormLength_OneByte verifies long-form length encoding with
a single length octet (length 128):

- Length header should be 0x81 0x80.
- Tag is as passed in.
- Total encoded length and value content should match expectations.
*/
func TestBerWrapTLV_LongFormLength_OneByte(t *testing.T) {
	// length = 128 -> long form with 1 length octet: 0x81 0x80
	val := make([]byte, 128)
	for i := range val {
		val[i] = 0xAA
	}
	got := BerWrapTLV(0x04, val)

	if got[0] != 0x04 {
		t.Fatalf("tag = 0x%X, want 0x04", got[0])
	}
	if got[1] != 0x81 || got[2] != 0x80 {
		t.Fatalf("length header = % X, want 81 80", got[1:3])
	}
	if len(got) != 1+1+1+len(val) {
		t.Fatalf("total length = %d, want %d", len(got), 3+len(val))
	}
	if !reflect.DeepEqual(got[3:], val) {
		t.Fatalf("value mismatch")
	}
}

/*
TestBerWrapTLV_LongFormLength_TwoBytes verifies long-form length encoding with
two length octets (length 300 = 0x012C):

- Length header should be 0x82 0x01 0x2C.
- Tag and total encoded size should match.
- Value bytes should be preserved exactly.
*/
func TestBerWrapTLV_LongFormLength_TwoBytes(t *testing.T) {
	// length = 300 (0x012C) -> 0x82 0x01 0x2C
	val := make([]byte, 300)
	for i := range val {
		val[i] = byte(i & 0xFF)
	}
	got := BerWrapTLV(0x04, val)

	if got[0] != 0x04 {
		t.Fatalf("tag = 0x%X, want 0x04", got[0])
	}
	if got[1] != 0x82 || got[2] != 0x01 || got[3] != 0x2C {
		t.Fatalf("length header = % X, want 82 01 2C", got[1:4])
	}
	if len(got) != 1+1+2+len(val) {
		t.Fatalf("total length = %d, want %d", len(got), 4+len(val))
	}
	if !reflect.DeepEqual(got[4:], val) {
		t.Fatalf("value mismatch")
	}
}

// --- BerReadTLV (bytes.Reader) ---

/*
TestBerReadTLV_ShortFormRoundTrip verifies that BerReadTLV can correctly parse
a short-form length TLV created by BerWrapInteger:

- Tag (INTEGER), length, and value should match what was encoded.
- Specifically tests tag 0x02, length 1, and value 0x2A (42).
*/
func TestBerReadTLV_ShortFormRoundTrip(t *testing.T) {
	orig := BerWrapInteger(42) // 02 01 2A
	r := bytes.NewReader(orig)

	tlv, err := BerReadTLV(r)
	if err != nil {
		t.Fatalf("BerReadTLV returned error: %v", err)
	}
	if tlv.Tag != 0x02 {
		t.Fatalf("Tag = 0x%X, want 0x02", tlv.Tag)
	}
	if tlv.Length != 1 {
		t.Fatalf("Length = %d, want 1", tlv.Length)
	}
	if !reflect.DeepEqual(tlv.Value, []byte{0x2A}) {
		t.Fatalf("Value = % X, want 2A", tlv.Value)
	}
}

/*
TestBerReadTLV_LongFormRoundTrip_OneByteLength verifies that BerReadTLV can
parse a TLV whose length is encoded in long-form using one extra length byte
(length 128). It checks that:

- Tag is correct.
- Decoded Length equals len(value).
- Value bytes match exactly.
*/
func TestBerReadTLV_LongFormRoundTrip_OneByteLength(t *testing.T) {
	val := make([]byte, 128)
	for i := range val {
		val[i] = byte(0x30 + (i % 10))
	}
	encoded := BerWrapTLV(0x04, val) // OCTET STRING with long-form len
	r := bytes.NewReader(encoded)

	tlv, err := BerReadTLV(r)
	if err != nil {
		t.Fatalf("BerReadTLV error: %v", err)
	}
	if tlv.Tag != 0x04 {
		t.Fatalf("Tag = 0x%X, want 0x04", tlv.Tag)
	}
	if tlv.Length != len(val) {
		t.Fatalf("Length = %d, want %d", tlv.Length, len(val))
	}
	if !reflect.DeepEqual(tlv.Value, val) {
		t.Fatalf("Value mismatch")
	}
}

/*
TestBerReadTLV_LongFormRoundTrip_TwoByteLength verifies that BerReadTLV can
parse a TLV whose length is encoded with two length bytes (e.g. 300):

- Tag must match.
- Length must be decoded correctly from long-form header.
- Value must match exactly.
*/
func TestBerReadTLV_LongFormRoundTrip_TwoByteLength(t *testing.T) {
	val := make([]byte, 300)
	for i := range val {
		val[i] = byte(i)
	}
	encoded := BerWrapTLV(0x04, val)
	r := bytes.NewReader(encoded)

	tlv, err := BerReadTLV(r)
	if err != nil {
		t.Fatalf("BerReadTLV error: %v", err)
	}
	if tlv.Tag != 0x04 {
		t.Fatalf("Tag = 0x%X, want 0x04", tlv.Tag)
	}
	if tlv.Length != len(val) {
		t.Fatalf("Length = %d, want %d", tlv.Length, len(val))
	}
	if !reflect.DeepEqual(tlv.Value, val) {
		t.Fatalf("Value mismatch")
	}
}

/*
TestBerReadTLV_Errors verifies the error paths in BerReadTLV using a
bytes.Reader:

It covers:
- EOF when reading the tag byte.
- EOF when reading the length byte.
- Indefinite length (0x80) which is explicitly unsupported.
- EOF while reading additional long-form length bytes.
- EOF while reading the value bytes; confirms:
  - Returned TLV still has Tag, Length, and a zero-padded Value slice.
  - Error is io.ErrUnexpectedEOF.
*/
func TestBerReadTLV_Errors(t *testing.T) {
	t.Run("EOF on tag", func(t *testing.T) {
		r := bytes.NewReader(nil)
		_, err := BerReadTLV(r)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("EOF on length byte", func(t *testing.T) {
		// Tag present, length missing
		r := bytes.NewReader([]byte{0x02})
		_, err := BerReadTLV(r)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("indefinite length not supported", func(t *testing.T) {
		r := bytes.NewReader([]byte{0x02, 0x80})
		_, err := BerReadTLV(r)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if err.Error() != "indefinite length not supported" {
			t.Fatalf("error = %q, want %q", err.Error(), "indefinite length not supported")
		}
	})

	t.Run("EOF in long-form length bytes", func(t *testing.T) {
		// Tag + long-form indicator 0x81 but missing the following length byte
		r := bytes.NewReader([]byte{0x04, 0x81})
		_, err := BerReadTLV(r)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("EOF in value bytes", func(t *testing.T) {
		// Tag, length=2, but only 1 value byte present
		r := bytes.NewReader([]byte{0x04, 0x02, 0xAA})
		tlv, err := BerReadTLV(r)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if tlv.Tag != 0x04 {
			t.Fatalf("Tag = 0x%X, want 0x04", tlv.Tag)
		}
		if tlv.Length != 2 {
			t.Fatalf("Length = %d, want 2", tlv.Length)
		}
		if len(tlv.Value) != 2 {
			t.Fatalf("Value length = %d, want 2", len(tlv.Value))
		}
		// First byte should be the value we had; second is zero-filled
		if !reflect.DeepEqual(tlv.Value, []byte{0xAA, 0x00}) {
			t.Fatalf("Value = % X, want AA 00", tlv.Value)
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
		}
	})
}

// --- BerReadTLVStream (io.Reader) ---

/*
TestBerReadTLVStream_ShortFormRoundTrip verifies that BerReadTLVStream can
decode a short-form TLV produced by BerWrapString:

- Tag is OCTET STRING (0x04).
- Length matches the string length.
- Value is the original "hello" bytes.
*/
func TestBerReadTLVStream_ShortFormRoundTrip(t *testing.T) {
	encoded := BerWrapString("hello") // 04 05 68 65 6C 6C 6F
	r := bytes.NewReader(encoded)

	tlv, err := BerReadTLVStream(r)
	if err != nil {
		t.Fatalf("BerReadTLVStream error: %v", err)
	}
	if tlv.Tag != 0x04 {
		t.Fatalf("Tag = 0x%X, want 0x04", tlv.Tag)
	}
	if tlv.Length != 5 {
		t.Fatalf("Length = %d, want 5", tlv.Length)
	}
	if !reflect.DeepEqual(tlv.Value, []byte("hello")) {
		t.Fatalf("Value = %q, want %q", tlv.Value, "hello")
	}
}

/*
TestBerReadTLVStream_LongFormRoundTrip verifies that BerReadTLVStream can
decode a long-form-length TLV (length 200) produced via BerWrapTLV:

- Tag is preserved.
- Length is decoded correctly.
- Value matches the original byte sequence.
*/
func TestBerReadTLVStream_LongFormRoundTrip(t *testing.T) {
	val := make([]byte, 200)
	for i := range val {
		val[i] = byte(i + 1)
	}
	encoded := BerWrapTLV(0x04, val)
	r := bytes.NewReader(encoded)

	tlv, err := BerReadTLVStream(r)
	if err != nil {
		t.Fatalf("BerReadTLVStream error: %v", err)
	}
	if tlv.Tag != 0x04 {
		t.Fatalf("Tag = 0x%X, want 0x04", tlv.Tag)
	}
	if tlv.Length != len(val) {
		t.Fatalf("Length = %d, want %d", tlv.Length, len(val))
	}
	if !reflect.DeepEqual(tlv.Value, val) {
		t.Fatalf("Value mismatch")
	}
}

/*
TestBerReadTLVStream_Errors verifies the error handling paths in
BerReadTLVStream when reading from a generic io.Reader:

- EOF when reading the tag.
- EOF when reading the length byte.
- Indefinite length (0x80) is rejected with a specific error.
- EOF while reading long-form length bytes.
- EOF while reading value bytes; returns io.ErrUnexpectedEOF.
*/
func TestBerReadTLVStream_Errors(t *testing.T) {
	t.Run("EOF on tag", func(t *testing.T) {
		r := bytes.NewReader(nil)
		_, err := BerReadTLVStream(r)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("EOF on length byte", func(t *testing.T) {
		r := bytes.NewReader([]byte{0x02})
		_, err := BerReadTLVStream(r)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("indefinite length not supported", func(t *testing.T) {
		r := bytes.NewReader([]byte{0x02, 0x80})
		_, err := BerReadTLVStream(r)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if err.Error() != "indefinite length not supported" {
			t.Fatalf("error = %q, want %q", err.Error(), "indefinite length not supported")
		}
	})

	t.Run("EOF in long-form length bytes", func(t *testing.T) {
		r := bytes.NewReader([]byte{0x04, 0x81})
		_, err := BerReadTLVStream(r)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("EOF in value bytes", func(t *testing.T) {
		r := bytes.NewReader([]byte{0x04, 0x02, 0xAA})
		_, err := BerReadTLVStream(r)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
		}
	})
}

/*
TestBerIntegerRoundTrip performs end-to-end tests for INTEGER values:

For a range of non-negative integers:
- Encode them with BerWrapInteger.
- Decode the TLV using both BerReadTLV (bytes.Reader) and BerReadTLVStream (io.Reader).
- Check the tag is the INTEGER tag.
- Decode the value content with BerDecodeInt and ensure the original integer is recovered.

This validates the combined behavior of:
berEncodeInteger + BerWrapInteger + BerReadTLV/BerReadTLVStream + BerDecodeInt.
*/
func TestBerIntegerRoundTrip(t *testing.T) {
	values := []int{
		0,
		1,
		5,
		127,
		128,
		256,
		0x123456,
	}

	for _, v := range values {
		v := v
		t.Run("bytes.Reader_"+strconv.Itoa(v), func(t *testing.T) {
			encoded := BerWrapInteger(v)

			r := bytes.NewReader(encoded)
			tlv, err := BerReadTLV(r)
			if err != nil {
				t.Fatalf("BerReadTLV error: %v", err)
			}

			if tlv.Tag != ClassUniversal|PcPrimitive|TagInteger {
				t.Fatalf("Tag = 0x%X, want 0x%X", tlv.Tag, ClassUniversal|PcPrimitive|TagInteger)
			}

			decoded := BerDecodeInt(tlv.Value)
			if decoded != v {
				t.Fatalf("roundtrip: got %d, want %d", decoded, v)
			}
		})

		t.Run("stream_"+strconv.Itoa(v), func(t *testing.T) {
			encoded := BerWrapInteger(v)

			r := bytes.NewReader(encoded)
			tlv, err := BerReadTLVStream(r)
			if err != nil {
				t.Fatalf("BerReadTLVStream error: %v", err)
			}

			if tlv.Tag != ClassUniversal|PcPrimitive|TagInteger {
				t.Fatalf("Tag = 0x%X, want 0x%X", tlv.Tag, ClassUniversal|PcPrimitive|TagInteger)
			}

			decoded := BerDecodeInt(tlv.Value)
			if decoded != v {
				t.Fatalf("roundtrip: got %d, want %d", decoded, v)
			}
		})
	}
}

/*
TestZeroLengthTLVs verifies handling of TLVs with zero-length values in
several scenarios:

  - BerWrapTLV with a nil/empty value produces a TLV with length 0, and
    BerReadTLV can read it correctly.
  - BerReadTLVStream correctly reads a zero-length SEQUENCE.
  - Helper wrappers (BerWrapSequence, BerWrapApp, BerWrapCtx) correctly
    encode zero-length inner content with a length byte of 0x00.

This ensures correct behavior for empty content values.
*/
func TestZeroLengthTLVs(t *testing.T) {
	t.Run("BerWrapTLV_zero_length", func(t *testing.T) {
		tag := byte(0x04)
		encoded := BerWrapTLV(tag, nil) // or []byte{}

		if len(encoded) != 2 {
			t.Fatalf("encoded length = %d, want 2", len(encoded))
		}
		if encoded[0] != tag {
			t.Fatalf("tag = 0x%X, want 0x%X", encoded[0], tag)
		}
		if encoded[1] != 0x00 {
			t.Fatalf("length byte = 0x%X, want 0x00", encoded[1])
		}

		// bytes.Reader version
		r := bytes.NewReader(encoded)
		tlv, err := BerReadTLV(r)
		if err != nil {
			t.Fatalf("BerReadTLV error: %v", err)
		}
		if tlv.Tag != tag {
			t.Fatalf("Tag = 0x%X, want 0x%X", tlv.Tag, tag)
		}
		if tlv.Length != 0 {
			t.Fatalf("Length = %d, want 0", tlv.Length)
		}
		if len(tlv.Value) != 0 {
			t.Fatalf("Value length = %d, want 0", len(tlv.Value))
		}
	})

	t.Run("BerReadTLVStream_zero_length", func(t *testing.T) {
		tag := byte(0x30) // SEQUENCE, but zero-length
		encoded := BerWrapTLV(tag, []byte{})

		r := bytes.NewReader(encoded)
		tlv, err := BerReadTLVStream(r)
		if err != nil {
			t.Fatalf("BerReadTLVStream error: %v", err)
		}
		if tlv.Tag != tag {
			t.Fatalf("Tag = 0x%X, want 0x%X", tlv.Tag, tag)
		}
		if tlv.Length != 0 {
			t.Fatalf("Length = %d, want 0", tlv.Length)
		}
		if len(tlv.Value) != 0 {
			t.Fatalf("Value length = %d, want 0", len(tlv.Value))
		}
	})

	t.Run("ZeroLengthSequenceAndCtxHelpers", func(t *testing.T) {
		seq := BerWrapSequence([]byte{})
		if !reflect.DeepEqual(seq, []byte{ClassUniversal | PcConstructed | TagSequence, 0x00}) {
			t.Fatalf("empty sequence = % X, want 30 00", seq)
		}

		app := BerWrapApp(0x01, []byte{})
		if len(app) != 2 || app[1] != 0x00 {
			t.Fatalf("empty app TLV = % X, want [tag, 00]", app)
		}

		ctxPrim := BerWrapCtx(0, []byte{}, false)
		if len(ctxPrim) != 2 || ctxPrim[1] != 0x00 {
			t.Fatalf("empty ctx primitive TLV = % X, want [tag, 00]", ctxPrim)
		}

		ctxConstr := BerWrapCtx(0, []byte{}, true)
		if len(ctxConstr) != 2 || ctxConstr[1] != 0x00 {
			t.Fatalf("empty ctx constructed TLV = % X, want [tag, 00]", ctxConstr)
		}
	})
}

// TestBerWrapCtx_AllowsTagsInRange verifies that BerWrapCtx accepts tag
// numbers in the valid single-byte BER context-specific range [0,30] and
// does not panic when used with tags in that range.
func TestBerWrapCtx_AllowsTagsInRange(t *testing.T) {
	cases := []int{0, 1, 15, 30}

	for _, tag := range cases {
		tag := tag
		t.Run(fmt.Sprintf("tag_%d", tag), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("BerWrapCtx(%d, ...) panicked unexpectedly: %v", tag, r)
				}
			}()

			_ = BerWrapCtx(tag, []byte{0x01, 0x01, 0x00}, true)
		})
	}
}

// TestBerWrapCtx_PanicsOnTagTooLarge ensures that BerWrapCtx rejects
// invalid context-specific tag numbers ≥ 31 (which require multibyte tag
// encoding in BER) by panicking, preventing silent generation of invalid
// tag bytes.
func TestBerWrapCtx_PanicsOnTagTooLarge(t *testing.T) {
	cases := []int{31, 32, 100}

	for _, tag := range cases {
		tag := tag
		t.Run("tag_too_large", func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("expected panic for BerWrapCtx(%d,...), but got none", tag)
				}
			}()
			_ = BerWrapCtx(tag, []byte{0x01, 0x01, 0x00}, false)
		})
	}
}

// TestBerWrapCtx_PanicsOnNegativeTag verifies that BerWrapCtx panics when
// given a negative tag value, which is invalid in BER and must not be
// silently accepted.
func TestBerWrapCtx_PanicsOnNegativeTag(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic for BerWrapCtx(-1,...), but got none")
		}
	}()
	_ = BerWrapCtx(-1, []byte{0x01, 0x01, 0x00}, false)
}
