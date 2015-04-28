package detectcoll

import (
	"crypto/rand"
	"crypto/subtle"
	"testing"
)

func TestSHA1(t *testing.T) {
	var h Hash = NewSHA1()

	var ret []byte

	ret = h.Sum(nil)
	if subtle.ConstantTimeCompare(ret, []byte{0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09}) != 1 {
		t.Errorf("Empty hash incorrect: %x", ret)
	}

	// h.Reset()
	h.Write([]byte("abc"))
	ret = h.Sum(nil)
	if subtle.ConstantTimeCompare(ret, []byte{0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D}) != 1 {
		t.Errorf("Hash('abc') incorrect: %x", ret)
	}

}

func TestUnprocess(t *testing.T) {

	// Create a random message block
	dataBuf := make([]byte, 64)
	if _, err := rand.Read(dataBuf); err != nil {
		t.Fatal(err)
	}
	mb := create_sha1_mb(dataBuf)

	// Verbatim copy of SHA1.process_mb()
	var i int
	var a, b, c, d, e uint32 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0

	iv := [5]uint32{a, b, c, d, e}
	working_states := make([]sha1_ihv, 80)

	chug := func(f, k, m uint32) {
		a, b, c, d, e = e, a, b, c, d
		c = rotl32(c, 30)
		a += rotl32(b, 5) + f + k + m
	}

	for ; i < 20; i++ {
		f := (b & c) | ((^b) & d)
		chug(f, sha1_rc1, mb[i])
		working_states[i] = [5]uint32{a, b, c, d, e}
	}

	for ; i < 40; i++ {
		f := b ^ c ^ d
		chug(f, sha1_rc2, mb[i])
		working_states[i] = [5]uint32{a, b, c, d, e}
	}

	for ; i < 60; i++ {
		f := (b & c) | (b & d) | (c & d)
		chug(f, sha1_rc3, mb[i])
		working_states[i] = [5]uint32{a, b, c, d, e}
	}

	for ; i < 80; i++ {
		f := b ^ c ^ d
		chug(f, sha1_rc4, mb[i])
		working_states[i] = [5]uint32{a, b, c, d, e}
	}

	// Not really the ihv, since we didn't add the IV
	ihv := [5]uint32{a, b, c, d, e}

	recovered_iv := unprocess_sha1_block(77, mb, &working_states[77])
	recovered_ihv := process_sha1_block(3, mb, &working_states[2])

	if !compare_sha1_ihv(recovered_iv, iv) {
		t.Errorf("Unprocess failed, orig=%x recovered=%x", iv, recovered_iv)
	}

	if !compare_sha1_ihv(recovered_ihv, ihv) {
		t.Errorf("Reprocess failed, orig=%x recovered=%x", ihv, recovered_ihv)
	}
}

func TestSHA1Collisions(t *testing.T) {
	// Still working on this test case...
}
