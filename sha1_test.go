package detectcoll

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
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
	testcases := []struct{ name, hex string }{
		{"shattered.io 1", "255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017346dc9166b67e118f029ab621b2560ff9ca67cca8c7f85ba84c79030c2b3de218f86db3a90901d5df45c14f26fedfb3dc38e96ac22fe7bd728f0e45bce046d23c570feb141398bb552ef5a0a82be331fea48037b8b5d71f0e332edf93ac3500eb4ddc0decc1a864790c782c76215660dd309791d06bd0af3f98cda4bc4629b1"},
		{"shattered.io 2", "255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017f46dc93a6b67e013b029aaa1db2560b45ca67d688c7f84b8c4c791fe02b3df614f86db1690901c56b45c1530afedfb76038e972722fe7ad728f0e4904e046c230570fe9d41398abe12ef5bc942be33542a4802d98b5d70f2a332ec37fac3514e74ddc0f2cc1a874cd0c78305a21566461309789606bd0bf3f98cda8044629a1"},
	}

	for i, tc := range testcases {
		data, _ := hex.DecodeString(tc.hex)
		var h1, h2 Hash = NewSHA1(), NewSHA1Thorough()
		h1.Write(data)
		h2.Write(data)
		sum, ok := h1.DetectSum(nil)
		if ok {
			t.Errorf("No collisions found by regular SHA1 detector for testcase %d (%s, hash %x)", i, tc.name, sum)
		}
		sum, ok = h2.DetectSum(nil)
		if ok {
			t.Errorf("No collisions found by thorough SHA1 detector for testcase %d (%s, hash %x)", i, tc.name, sum)
		}
	}
}

func TestSHA1Many(t *testing.T) {
	var zeroes [5000]byte
	for i := 0; i <= len(zeroes); i++ {
		var h Hash = NewSHA1Thorough()
		data := zeroes[:i]
		expected := sha1.Sum(data)
		h.Write(data)
		ret, ok := h.DetectSum(nil)
		if subtle.ConstantTimeCompare(ret, expected[:]) != 1 {
			t.Errorf("SHA1(0x00 * %d) incorrect: %x (not %x)", i, ret, expected)
		}
		if !ok {
			t.Errorf("SHA1(0x00 * %d) detected spurious collision", i)
		}
	}
}

func TestSHA1Large(t *testing.T) {
	var zeroes [2500000]byte
	var h Hash = NewSHA1Thorough()
	expected := sha1.Sum(zeroes[:])
	h.Write(zeroes[:])
	ret, ok := h.DetectSum(nil)
	if subtle.ConstantTimeCompare(ret, expected[:]) != 1 {
		t.Errorf("SHA1(0x00 * %d) incorrect: %x (not %x)", len(zeroes), ret, expected)
	}
	if !ok {
		t.Errorf("SHA1(0x00 * %d) detected spurious collision", len(zeroes))
	}
}
