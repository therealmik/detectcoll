package md5

import "github.com/therealmik/detectcoll"
import "crypto"
import "hash"

func New() hash.Hash {
	return detectcoll.NewMD5()
}

func init() {
	crypto.RegisterHash(crypto.MD5, New)
}
