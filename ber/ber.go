package ber

import (
	"bytes"
	"errors"
	"io"
	"log"
)

const (
	ClassUniversal       = 0x00
	ClassApplication     = 0x40
	ClassContextSpecific = 0x80
	PcPrimitive          = 0x00
	PcConstructed        = 0x20
	TagBoolean           = 0x01
	TagInteger           = 0x02
	TagOctetString       = 0x04
	TagEnum              = 0x0A
	TagSequence          = 0x10
	TagSet               = 0x11
)

/*
The BerTLV struct models a BER-TLV element (Basic Encoding Rules — Tag, Length, Value), commonly used in smart cards, EMV, ASN.1, etc.
*/
type BerTLV struct {
	// Tag is a field of the struct. Its type is byte, which is an alias for uint8.
	// Using byte implies you are dealing only with single-byte tags (simple TLVs).
	// In BER-TLV encoding, the Tag identifies what kind of data the element contains.
	Tag byte
	// Length is an int indicating the number of bytes in the Value field.
	// Using int simplifies working with slices, but a BER length field on the wire may need special parsing (short vs long form).
	Length int
	// Value holds the raw bytes associated with the tag.
	// Using []byte means the struct can store arbitrary binary data. BER-TLV's “V” (Value) field can contain anything — numbers, strings, nested TLVs, etc.
	Value []byte
}

/*
The BerReadTLV function takes one argument: r, a pointer to bytes.Reader, which is a reader over a byte slice.
It returns two things: (1) a berTLV value (a struct with fields like Tag, Length, Value), and (2), an error, if something went wrong while reading.
*/
func BerReadTLV(r *bytes.Reader) (BerTLV, error) {
	// t is a BerTLV struct that will be filled with Tag, Length, and Value and then returned.
	var t BerTLV
	// We read a single byte from the reader r, and stores the byte in id and any error in err.
	// In BER TLV, this first byte represent the tag. This implementation assumes a single-byte tag (not handling multi-byte tag numbers).
	id, err := r.ReadByte()
	// If reading that byte failed (EOF, I/O error, etc.), we can’t parse anything without at least one tag byte, so it logs the error, and returns the (still mostly-empty) t and the error.
	if err != nil {
		log.Printf("%+v", err)
		return t, err
	}
	// We store the tag byte in the Tag field of t.
	t.Tag = id
	// We read the next byte from the stream, which is the first length byte, and store it in lb (length byte).
	lb, err := r.ReadByte()
	// Same pattern: if reading the length byte fails, log and return.
	if err != nil {
		log.Printf("%+v", err)
		return t, err
	}
	// Checks if the most significant bit (MSB) of the length byte lb is 0.
	// lb & 0x80 isolates the MSB (0x80 == 10000000b).
	if lb&0x80 == 0 {
		// In BER, when MSB = 0, the remaining 7 bits directly give the length, so we just set Length to the value of lb itself.
		t.Length = int(lb)
	} else {
		// In BER, when MSB = 1, the remaining 7 bits tell you how many following bytes encode the length.
		// We mask off the MSB with 0x7F (01111111b). Now n is the number of subsequent bytes that encode the length.
		n := int(lb & 0x7F)
		if n == 0 {
			// In BER, lb == 0x80 (MSB=1, rest 0) is indefinite length.
			// That means the content length is not specified upfront; it ends with a special terminator (0x00 0x00).
			// This code explicitly does not support that. So, if n == 0, it logs and returns an error.
			log.Printf("indefinite length not supported")
			return t, errors.New("indefinite length not supported")
		}
		// We allocate a byte slice of size n, which will hold the n bytes that encode the length value.
		lenBytes := make([]byte, n)
		// We will read exactly n bytes from r into lenBytes.
		// io.ReadFull either will fill the buffer completely, or returns an error (e.g. EOF before n bytes).
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			// If there’s an error, log it and return.
			log.Printf("%+v", err)
			return t, err
		}
		L := 0
		// This loop converts the n length bytes from big-endian bytes into an integer L.
		for _, b := range lenBytes {
			// This means shift current L left by 8 bits (multiply by 256), then add the new byte.
			L = (L << 8) | int(b)
		}
		// Once we have correctly computed the length, store the computed length into t.Length.
		t.Length = L
	}
	// We allocate a byte slice for the value (V) part of the TLV, of size t.Length.
	// NOTE: If an attacker sends a TLV with a massive length field (e.g. 0x84 FF FF FF FF), t.Length might become huge and make will try to allocate that much memory, which can kill the process.
	t.Value = make([]byte, t.Length)
	// We read exactly t.Length bytes from the reader into t.Value.
	// We again use io.ReadFull to ensure we either get all bytes or an error.
	_, err = io.ReadFull(r, t.Value)
	if err != nil {
		// If reading the value failed, log the error.
		// Notice: it does not return early here. It just logs and continues - the error will still be returned by the function on the next line.
		log.Printf("%+v", err)
	}
	// Returns the parsed berTLV struct t and the err from reading the value.
	// If everything worked, err will be nil. While, if value reading failed, you get a partially-filled t and a non-nil err.
	return t, err
}

/*
The BerReadTLVStream function takes one argument, an io.Reader, allowing it to read from any streaming source (file, network, buffer, etc.).
It returns two things: (1) a berTLV struct that holds Tag, Length, Value, and (2) an error.
*/
func BerReadTLVStream(rd io.Reader) (BerTLV, error) {
	// The berTLV struct t is zero-initialized (Tag = 0, Length = 0, Value = nil, etc.). It will be filled in as we parse the TLV.
	var t BerTLV
	// Declare a fixed-size array named id that can hold exactly 1 byte. This will be used to read the tag byte.
	var id [1]byte
	// We call io.ReadFull to read exactly 1 byte from rd into id.
	// id[:] converts the array to a slice []byte.
	// ReadFull guarantees either it fills the buffer (1 byte) or returns an error.
	// We don't care about the number of bytes read (1), but immediately check if there was an error.
	if _, err := io.ReadFull(rd, id[:]); err != nil {
		// If reading the tag failed, log the error, and return t (still mostly empty/zero), and the error.
		// if the error is just "EOF" that's fine, don't make noise in logs.
		if err.Error() != "EOF" {
			log.Printf("%+v", err)
		}
		return t, err
	}
	// At this point, reading the tag succeeded.
	// The single byte we read is in id[0].
	// We assign that byte to the Tag field of t, so t.Tag now holds the BER tag.
	t.Tag = id[0]
	// Declare another 1-byte array lb (“length byte”). This will hold the first length byte from the stream.
	var lb [1]byte
	// Reads one byte from rd into lb.
	// If it fails, log the error, and return t (with Tag set but Length/Value not fully set) and the error
	if _, err := io.ReadFull(rd, lb[:]); err != nil {
		log.Printf("%+v", err)
		return t, err
	}
	// Now we interpret that length byte according to BER rules.
	// We check the most significant bit (MSB) of the length byte.
	if lb[0]&0x80 == 0 {
		// If MSB is 0, the remaining 7 bits are the length directly. The length is just the value of the byte, so we assign that to t.Length.
		// However, strictly in BER you’d mask off the MSB (lb[0] & 0x7F), but since MSB is known to be 0 here, int(lb[0]) is fine.
		t.Length = int(lb[0])
	} else {
		// If MSB is 1, the remaining 7 bits tell how many length bytes follow.
		// For long form, the lower 7 bits specify how many subsequent bytes encode the length.
		// lb[0] & 0x7F masks off the MSB, leaving just those 7 bits.
		// We Convert that to int and store as n: the count of length bytes to read next.
		n := int(lb[0] & 0x7F)
		if n == 0 {
			// In BER, n == 0 with MSB set (0x80) is “indefinite length” (you read content until an end-of-content marker).
			// This code explicitly refuses to handle indefinite-length encoding. So, we log that indefinite length isn’t supported.
			// We return an error, along with whatever t has so far.
			log.Printf("indefinite length not supported")
			return t, errors.New("indefinite length not supported")
		}
		// We allocate a slice lenBytes of length n bytes. These bytes will hold the long-form length field.
		lenBytes := make([]byte, n)
		// We read exactly n bytes from rd into lenBytes. If the read fails, log the error then return t and the error.
		if _, err := io.ReadFull(rd, lenBytes); err != nil {
			log.Printf("%+v", err)
			return t, err
		}
		// We declare an integer L initialized to 0. This will be used to accumulate the length value decoded from lenBytes.
		L := 0
		// Loop over each byte b in lenBytes.
		// For each byte,L = (L << 8) shifts the current value left by 8 bits (multiply by 256), making room for the next byte.
		// | int(b) adds the new byte to the low 8 bits.
		// This treats lenBytes as a big-endian integer.
		// So L becomes the decoded length.
		for _, b := range lenBytes {
			L = (L << 8) | int(b)
		}
		// After the loop, L is the full length. So, we assign L to t.Length.
		t.Length = L
	}
	// At this point, we’ve read (1) The Tag (t.Tag), (2) The Length (t.Length). Next, we read the Value.
	// We allocate a byte slice t.Value with length t.Length. This will hold the raw value bytes of the TLV.
	// NOTE: If an attacker sends a TLV with a massive length field (e.g. 0x84 FF FF FF FF), t.Length might become huge and make will try to allocate that much memory, which can kill the process.
	t.Value = make([]byte, t.Length)
	// We read exactly t.Length bytes from rd into t.Value.
	// If not enough bytes are available or another error occurs,log the error, and return t and the error.
	if _, err := io.ReadFull(rd, t.Value); err != nil {
		log.Printf("%+v", err)
		return t, err
	}
	// If everything succeeded, return the fully populated berTLV (t) and nil error.
	return t, nil
}

/*
The berWriteTLV function implements BER (Basic Encoding Rules) TLV (Tag-Length-Value) encoding, where:
T = tag (1 byte here)
L = length in BER format (short or long form)
V = value (raw byte slice)
It writes a BER-encoded TLV element into a bytes.Buffer
It takes (1) an output buffer w, (2) a TLV tag called tag, (3) a byte slice val, representing the value.
*/
func berWriteTLV(w *bytes.Buffer, tag byte, val []byte) {
	// Writes the tag byte into the buffer.
	w.WriteByte(tag)
	// Computes the length of the value (number of bytes to encode).
	L := len(val)
	// Checks whether the length fits in the short form of BER length encoding.
	// Length < 128 (0x80) → short form, Length ≥ 128 → long form.
	if L < 0x80 {
		// If the length is < 128, BER short-form length encoding applies, so we write the length as a single byte.
		w.WriteByte(byte(L))
	} else {
		// If length ≥ 128, use the long form.
		// tmp is a temporary array to accumulate length bytes. Max length encodable here = 8 bytes (more than enough for most practical cases).
		var tmp [8]byte
		// n will count how many bytes are needed to represent the length.
		n := 0
		// Loops through the length value, extracting its bytes.
		// On each iteration, shift x right by 8 bits. Continue until x becomes 0.
		// This is converting integer L → big-endian byte sequence.
		for x := L; x > 0; x >>= 8 {
			// Stores the least significant byte of x into the temporary array.
			tmp[n] = byte(x & 0xFF)
			// Increments the counter of length bytes.
			n++
		}
		// Writes the long-form length header byte.
		// High bit 1 (0x80) means long-form length.
		w.WriteByte(0x80 | byte(n))
		// Length bytes were collected LSB-first, so now they need to be written in big-endian order.
		for i := n - 1; i >= 0; i-- {
			// They are  little-endian order in tmp, so this writes each length byte in reverse order (MSB first), so it's big-endian
			err := w.WriteByte(tmp[i])
			if err != nil {
				// Log any error
				log.Printf("%+v", err)
			}
		}
	}
	// Writes the actual value bytes (the V in TLV).
	_, err := w.Write(val)
	if err != nil {
		// Log any error
		log.Printf("%+v", err)
	}
}

/*
The BerWrapTLV function takes (1) a tag (one byte), and (2) a val (a byte slice)
It returns a byte slice representing the encoded TLV structure.
“TLV” stands for Tag-Length-Value, a common binary encoding scheme.
This function is a wrapper (essentially a convenience function around berWriteTLV), that creates a buffer, writes a Tag-Length-Value encoding into it, and returns the resulting bytes.
*/
func BerWrapTLV(tag byte, val []byte) []byte {
	// Create a bytes.Buffer named b. This is a growable byte buffer that implements io.Writer.
	// It will be used to build the TLV encoding in memory.
	var b bytes.Buffer
	// Calls berWriteTLV, passing:
	// (1) &b → a pointer to the buffer so it can be written into.
	// (2) tag → the TLV tag byte
	// (3) val → the TLV value bytes
	// berWriteTLV writes the tag, the length of val, and the actual val content, into the buffer.
	berWriteTLV(&b, tag, val)
	// Returns the raw byte slice containing everything written to the buffer.
	// b.Bytes() copies the internal buffer’s contents into a []byte. This is the final TLV-wrapped output.
	return b.Bytes()
}

/*
The berEncodeInteger function takes am int and returns a []byte containing its BER-encoded integer.
It BER-encodes a signed integer using the minimal number of bytes while obeying ASN.1 BER rules:
(1) Extracts integer bytes big-endian.
(2) Removes unnecessary leading zeros.
(3) Adds a leading 0x00 if the high bit would otherwise make the integer look negative.
(4) Returns the precise, minimal slice from tmp.
NOTE: This function effectively only works for non-negative integers (v >= 0), it does not handle negative ints.
The comments about “signed” and sign handling are correct in the padding context (ensuring a positive value doesn’t look negative), but the function does not encode negative numbers at all.
This is as for a negative v, x >>= 8 is an arithmetic right shift (sign-extended). Meaning x will never become 0 (it becomes -1), so the loop never ends.
*/
func berEncodeInteger(v int) []byte {
	// Note: this encoder only supports non-negative values. Negative ints would
	// otherwise cause an infinite loop due to arithmetic right-shift.
	if v < 0 {
		log.Printf("berEncodeInteger: negative values not supported")
		return nil
	}
	// Creates a temporary fixed size 9-byte array.
	// A signed 64-bit integer (8 bytes) may require one extra leading 0x00 to ensure the sign bit is correct in BER encoding.
	// So worst case: 8 bytes + 1 leading pad byte = 9 bytes.
	var tmp [9]byte
	// n will count how many bytes of the integer will be used.
	n := 0
	// We copy v into x, to avoid modifying v as the code shifts bytes out of x.
	x := v
	// The loop extracts the least significant byte first using x & 0xFF.
	// It stores each extracted byte in tmp, starting from the rightmost slot (tmp[8]) and moving leftward.
	// After storing, it increments n (number of bytes stored), then shifts the integer right by 8 bits, moving the next byte into place.
	// When the remaining value becomes zero, we stop.
	// Result: You end up with the minimal number of bytes needed to represent the integer’s value.
	for {
		tmp[8-n] = byte(x & 0xFF)
		n++
		x >>= 8
		if x == 0 {
			break
		}
	}
	// A BER integer must avoid having its most significant bit interpreted as a sign bit.
	// tmp[9-n] is the first actual byte of the encoded integer.
	// If this byte has its top bit set (0x80), BER would interpret the value as negative. If the original integer wasn't negative, that’s wrong.
	// The encoded integer would look negative unless we pad it. So, BER requires adding a leading 0x00 to prevent confusion with the sign bit.
	if tmp[9-n]&0x80 != 0 {
		// If a pad byte is needed, write 0 one slot before the first byte.
		tmp[9-n-1] = 0
		// Increase n because the encoded integer now has one more byte.
		n++
		// Return a slice of only the valid bytes.
		return tmp[9-n:]
	}
	// If the MSB is not set, just return the byte slice without padding.
	return tmp[9-n:]
}

/**
All these helpers follow the same pattern:
(1) Create a bytes.Buffer.
(2)  Call a generic berWriteTLV(writer, tagByte, valueBytes) helper, with:
(2.1) A calculated tag byte (class + primitive/constructed + specific tag).
(2.2) The raw value bytes (sometimes produced by another encoder like berEncodeInteger).
(3)  Return buffer.Bytes() as the final TLV-encoded result.
*/

/*
The BerWrapInteger function takes a single parameter v of type int, and returns its BER-encoded TLV (Tag-Length-Value) form as a slice of bytes.
*/
func BerWrapInteger(v int) []byte {
	// b is a growable in-memory buffer that implements io.Writer (and more). We write the encoded BER data into this buffer.
	var b bytes.Buffer
	// The address of the buffer b is a pointer, so berWriteTLV can write into it.
	// The bitwise OR (|) combines constants that represent the BER class (universal type), this is a primitive (not constructed) type, and the specific universal tag number for INTEGER.
	// Together they form the tag byte for a BER INTEGER.
	// berEncodeInteger  encodes the raw integer v into the BER-compliant byte representation of an integer value (no tag/length, just the content).
	// Overall: berWriteTLV writes T: the combined tag (classUniversal|pcPrimitive|tagInteger), L: the length of the encoded integer, V: the bytes from berEncodeInteger(v), into the buffer b.
	berWriteTLV(&b, ClassUniversal|PcPrimitive|TagInteger, berEncodeInteger(v))
	// Returns the contents of the buffer as a []byte. This is the full BER encoding of the INTEGER (T + L + V).
	return b.Bytes()
}

/*
The BerWrapEnum function is very similar to the berWrapInteger function, but v an integer representing an enum value.
This indicates this is an ENUMERATED type in BER (which is encoded similarly to INTEGER but with a different tag).
The enum value is still encoded as an integer value.
*/
func BerWrapEnum(v int) []byte {
	var b bytes.Buffer
	berWriteTLV(&b, ClassUniversal|PcPrimitive|TagEnum, berEncodeInteger(v))
	return b.Bytes()
}

/*
The berWrapOctet function is very similar to the berWrapInteger function, except the parameter s is a raw byte slice, the content of the octet string.
The raw bytes are already the value (no extra encoding needed like integer has), so they go straight to berWriteTLV
It returns a BER-encoded TLV for an OCTET STRING.
*/
func berWrapOctet(s []byte) []byte {
	var b bytes.Buffer
	berWriteTLV(&b, ClassUniversal|PcPrimitive|TagOctetString, s)
	return b.Bytes()
}

// The BerWrapString function just a convenience which takes a Go string, says encode this Go string as a BER OCTET STRING, and returns BER encoding as []byte.
func BerWrapString(s string) []byte { return berWrapOctet([]byte(s)) }

// The BerWrapSequence function is very similar to the berWrapOctet function. It takes the already-encoded contents that will go inside the sequence (often concatenated TLVs), and returns the TLV for the SEQUENCE that wraps inner.
func BerWrapSequence(inner []byte) []byte {
	var b bytes.Buffer
	// This is a constructed type (SEQUENCE contains nested elements).
	berWriteTLV(&b, ClassUniversal|PcConstructed|TagSequence, inner)
	return b.Bytes()
}

// The BerWrapApp function is an application-specific wrapper. It takes the specific application tag number (so you can have APPLICATION [0], [1], etc.). The encoded contents to go inside the application tag.
func BerWrapApp(tag byte, inner []byte) []byte {
	var b bytes.Buffer
	// The BER class is application-specific (not universal),it’s a constructed type (contains inner TLVs), and the tag number is passed in, bitwise OR’d with the class/pc bits to form the final tag byte.
	berWriteTLV(&b, ClassApplication|PcConstructed|tag, inner)
	return b.Bytes()
}

/*
The BerWrapCtx function creates a context-specific BER tag, of the form [context tag number]  Length  Value
It builds the tag byte manually by setting:
(1) Bits 7–6: classContextSpecific
(2) Bit 5: pcConstructed or pcPrimitive
(3) Bits 4–0: the tag number (converted from the tag argument)
Then it wraps everything using berWriteTLV.
It takes: (1) the context-specific tag number, e.g., [0], [1], etc. (2) an inner []byte – the encoded bytes that will form the value part of this TLV, and (3) a bool called constructed  – whether the resulting TLV should use the constructed bit (true) or primitive bit (false).
It returns a []byte – the complete BER TLV encoding.
*/
func BerWrapCtx(tag int, inner []byte, constructed bool) []byte {
	/*
		In BER, single-byte tags use the low 5 bits for the tag number; context-specific tags ≥ 31 require multi-byte tag encoding.
		As we don’t mask the tag to 5 bits (tag & 0x1f). For tag >= 32, we will overwrite the class/PC bits and produce an invalid tag.
	*/
	if tag < 0 || tag > 30 {
		panic("BerWrapCtx: tag must be in [0,30] for single-byte context-specific")
	}
	// Create an empty bytes.Buffer named b. This will hold the resulting TLV (Tag + Length + Value).
	var b bytes.Buffer
	// Declares a variable tt of type byte, and initialize it with classContextSpecific, which is a constant representing BER class = context-specific (10xx xxxx in ASN.1). This starts forming the tag byte.
	tt := byte(ClassContextSpecific)
	// Determines whether to mark the tag as constructed or primitive.
	// pcConstructed sets the appropriate bit (bit 6). pcPrimitive keeps bit 6 = 0.
	// A bitwise OR merges these flags with the base tag.
	// If constructed == true, then the TLV is a constructed type (contains nested TLVs). If constructed == false, it's primitive (value is raw data).
	if constructed {
		tt |= PcConstructed
	} else {
		tt |= PcPrimitive
	}
	// Adds the tag number (low 5 bits) to the tag byte.
	// This OR operation combines: (1) class = context-specific, (2) primitive/constructed bit, (3) tag number
	// Note: This supports only single-byte context tags (tag < 31), which is common in practical BER encodings.
	tt |= byte(tag)
	// Writes the full TLV to buffer b.
	// &b is a pointer to the buffer so the function can write into it. tt is the complete tag byte you just built, and inner is the raw value bytes.
	// berWriteTLV will produce: T = tt, L = encoded length of inner, V = the inner bytes
	berWriteTLV(&b, tt, inner)
	// Extracts the underlying []byte from the buffer, and returns the complete TLV encoding.
	return b.Bytes()
}

/*
The BerDecodeInt function takes one parameter b, a slice of bytes, and returns an int.
It decodes a BER-encoded (big-endian) integer. This is a generic unsigned big-endian conversion.
This function interprets a byte slice as a big-endian unsigned integer and returns the numeric value by shifting and appending each byte.
NOTE: For positive BER INTEGER contents, it works fine. It does not interpret the two’s complement sign for negative values, nor enforce BER minimal-length rules.
So it can onl decode the content octets of a non-negative BER INTEGER (or any unsigned big-endian integer).
*/
func BerDecodeInt(b []byte) int {
	// Initialize an integer variable x to zero. This variable will accumulate the decoded value.
	x := 0
	// iterates through each byte in the slice b. The loop processes the bytes from left to right.
	// The index is ignored. by is the byte value at each iteration.
	for _, by := range b {
		// This is the key decoding step.
		// Shifts the existing accumulated value 8 bits to the left (Equivalent to multiplying by 256.).
		// Then, Bitwise-ORs the lowest 8 bits with the next byte.
		// Together, this appends each new byte to the least significant end of x. This treats the byte slice as a big-endian integer.
		x = (x << 8) | int(by)
	}
	// Returns the decoded integer.
	return x
}
