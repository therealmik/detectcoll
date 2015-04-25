package detectcoll

import (
	"crypto/subtle"
	"encoding/hex"
	"hash"
	"testing"
)

func TestMD5(t *testing.T) {
	var h hash.Hash = NewMD5()

	var ret []byte

	ret = h.Sum(nil)
	expected, _ := hex.DecodeString("d41d8cd98f00b204e9800998ecf8427e")
	if subtle.ConstantTimeCompare(ret, expected) != 1 {
		t.Errorf("Empty hash incorrect: %x (not %x)", ret, expected)
	}

	// h.Reset()
	h.Write([]byte("abc"))
	expected, _ = hex.DecodeString("900150983cd24fb0d6963f7d28e17f72")
	ret = h.Sum(nil)
	if subtle.ConstantTimeCompare(ret, expected) != 1 {
		t.Errorf("Hash('abc') incorrect: %x (not %x)", ret, expected)
	}
}
