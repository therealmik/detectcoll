package sha1

import "github.com/therealmik/detectcoll"
import "crypto"
import "hash"

func New() hash.Hash {
	return detectcoll.NewSHA1()
}

func init() {
	crypto.RegisterHash(crypto.SHA1, New)
}
