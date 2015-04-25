package detectcoll

const (
	sha1_rc1 uint32 = 1518500249
	sha1_rc2 uint32 = 1859775393
	sha1_rc3 uint32 = 2400959708
	sha1_rc4 uint32 = 3395469782
)

type sha1_ihv [5]uint32

type SHA1 struct {
	ml  uint64
	ihv sha1_ihv
	buf []byte
}

type sha1_mb [80]uint32

func rotl32(i uint32, n uint) uint32 {
	return (i << n) | (i >> (32 - n))
}

func append_u32be(ret []byte, n uint32) []byte {
	ret = append(ret, byte(n>>24))
	ret = append(ret, byte(n>>16))
	ret = append(ret, byte(n>>8))
	ret = append(ret, byte(n))
	return ret
}

func NewSHA1() *SHA1 {
	return &SHA1{
		ml:  0,
		ihv: [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0},
	}
}

func (s *SHA1) Reset() {
	*s = *(NewSHA1())
}

func (s *SHA1) Size() int {
	return 20
}

func (s *SHA1) BlockSize() int {
	return 64
}

func (s *SHA1) Sum(ret []byte) []byte {
	t := *s // Copy s

	var padding []byte

	if len(t.buf) <= 56 {
		padding = make([]byte, 64)
	} else {
		padding = make([]byte, 128)
	}

	copy(padding, t.buf)
	padding[len(t.buf)] = 0x80

	padding[len(padding)-8] = byte(t.ml >> 56)
	padding[len(padding)-7] = byte(t.ml >> 48)
	padding[len(padding)-6] = byte(t.ml >> 40)
	padding[len(padding)-5] = byte(t.ml >> 32)
	padding[len(padding)-4] = byte(t.ml >> 24)
	padding[len(padding)-3] = byte(t.ml >> 16)
	padding[len(padding)-2] = byte(t.ml >> 8)
	padding[len(padding)-1] = byte(t.ml)

	for i := 0; i < len(padding); i += 64 {
		mb := create_sha1_mb(padding[i : i+64])
		t.process_mb(mb)
	}

	for i := 0; i < 5; i++ {
		ret = append_u32be(ret, t.ihv[i])
	}

	return ret
}

func (s *SHA1) Write(b []byte) (n int, err error) {
	s.ml += uint64(len(b)) * 8
	s.buf = append(s.buf, b...)

	for len(s.buf) >= 64 {
		mb := create_sha1_mb(s.buf[0:64])
		s.process_mb(mb)
		s.buf = s.buf[64:]
	}

	return len(b), nil
}

func create_sha1_mb(data []byte) *sha1_mb {
	var mb sha1_mb

	if len(data) != 64 {
		panic("Can only create message blocks from 64-byte data chunks")
	}

	for i := uint(0); i < 64; i++ {
		var shift uint = 24 - ((i % 4) * 8)
		mb[i/4] |= (uint32(data[i]) << shift)
	}

	for i := 16; i < 80; i++ {
		mb[i] = rotl32(mb[i-3]^mb[i-8]^mb[i-14]^mb[i-16], 1)
	}

	return &mb
}

func (s *SHA1) process_mb(mb *sha1_mb) {
	var i int
	a := s.ihv[0]
	b := s.ihv[1]
	c := s.ihv[2]
	d := s.ihv[3]
	e := s.ihv[4]

	chug := func(f, k uint32) {
		temp := rotl32(a, 5) + f + e + k + mb[i]
		e = d
		d = c
		c = rotl32(b, 30)
		b = a
		a = temp
	}

	for ; i < 20; i++ {
		f := (b & c) | ((^b) & d)
		chug(f, sha1_rc1)
	}

	for ; i < 40; i++ {
		f := b ^ c ^ d
		chug(f, sha1_rc2)
	}

	for ; i < 60; i++ {
		f := (b & c) | (b & d) | (c & d)
		chug(f, sha1_rc3)
	}

	for ; i < 80; i++ {
		f := b ^ c ^ d
		chug(f, sha1_rc4)
	}

	s.ihv[0] += a
	s.ihv[1] += b
	s.ihv[2] += c
	s.ihv[3] += d
	s.ihv[4] += e
}
