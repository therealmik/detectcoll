package detectcoll

func rotl32(i uint32, n uint) uint32 {
	return (i << n) | (i >> (32 - n))
}

func rotr32(i uint32, n uint) uint32 {
	return (i >> n) | (i << (32 - n))
}
