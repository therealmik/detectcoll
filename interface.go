package detectcoll

import "hash"

type Hash interface {
	hash.Hash
	DetectSum([]byte) ([]byte, bool)
}
