package detectcoll

import "log"

const (
	sha1_rc1 uint32 = 0x5A827999
	sha1_rc2 uint32 = 0x6ED9EBA1
	sha1_rc3 uint32 = 0x8F1BBCDC
	sha1_rc4 uint32 = 0xCA62C1D6
)

type sha1_ihv [5]uint32

type SHA1 struct {
	ml         uint64
	ihv        sha1_ihv
	buf        []byte
	collisions bool
}

type sha1_mb [80]uint32

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

func (s *SHA1) DetectSum(ret []byte) ([]byte, bool) {
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

	return ret, s.collisions
}

func (s *SHA1) Sum(ret []byte) []byte {
	ret, detected := s.DetectSum(ret)
	if detected {
		log.Printf("Detected collision in hash %x", ret)
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
	var a, b, c, d, e uint32 = s.ihv[0], s.ihv[1], s.ihv[2], s.ihv[3], s.ihv[4]
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

	s.ihv[0] += a
	s.ihv[1] += b
	s.ihv[2] += c
	s.ihv[3] += d
	s.ihv[4] += e

	s.detect_collisions(mb, working_states)
}

func compare_sha1_ihv(ihv1, ihv2 sha1_ihv) bool {
	result := (ihv1[0] ^ ihv2[0]) | (ihv1[1] ^ ihv2[1]) | (ihv1[2] ^ ihv2[2]) | (ihv1[3] ^ ihv2[3]) | (ihv1[4] ^ ihv2[4])
	return result == 0
}

func (s *SHA1) detect_collisions(orig_message_block *sha1_mb, working_states []sha1_ihv) {
	for _, dv := range sha1_dvs {
		mb := dv.disturb(orig_message_block)
		ihv := reapply_sha1(dv.K+13, &mb, working_states)
		if compare_sha1_ihv(ihv, s.ihv) {
			s.collisions = true
		}
	}
}

func reapply_sha1(round int, message_block *sha1_mb, working_states []sha1_ihv) sha1_ihv {
	working_state := &working_states[round]
	x := unprocess_sha1_block(round, message_block, working_state)
	y := process_sha1_block(round+1, message_block, working_state)

	return sha1_ihv{x[0] + y[0], x[1] + y[1], x[2] + y[2], x[3] + y[3], x[4] + y[4]}
}

func process_sha1_block(round int, message_block *sha1_mb, working_state *sha1_ihv) sha1_ihv {
	var i int = round
	a, b, c, d, e := working_state[0], working_state[1], working_state[2], working_state[3], working_state[4]

	chug := func(f, k, m uint32) {
		a, b, c, d, e = e, a, b, c, d
		c = rotl32(c, 30)
		a += rotl32(b, 5) + f + k + m
	}

	for ; i < 20; i++ {
		f := (b & c) | ((^b) & d)
		chug(f, sha1_rc1, message_block[i])
	}

	for ; i < 40; i++ {
		f := b ^ c ^ d
		chug(f, sha1_rc2, message_block[i])
	}

	for ; i < 60; i++ {
		f := (b & c) | (b & d) | (c & d)
		chug(f, sha1_rc3, message_block[i])
	}

	for ; i < 80; i++ {
		f := b ^ c ^ d
		chug(f, sha1_rc4, message_block[i])
	}

	return sha1_ihv{a, b, c, d, e}
}

func unprocess_sha1_block(round int, message_block *sha1_mb, working_state *sha1_ihv) sha1_ihv {
	var i int = round
	a, b, c, d, e := working_state[0], working_state[1], working_state[2], working_state[3], working_state[4]

	spew := func(f, k, m uint32) {
		a -= rotl32(b, 5) + f + k + m
		c = rotr32(c, 30)
		e, a, b, c, d = a, b, c, d, e
	}

	for ; i >= 60; i-- {
		f := b ^ c ^ d
		spew(f, sha1_rc4, message_block[i])
	}

	for ; i >= 40; i-- {
		f := (b & c) | (b & d) | (c & d)
		spew(f, sha1_rc3, message_block[i])
	}

	for ; i >= 20; i-- {
		f := b ^ c ^ d
		spew(f, sha1_rc2, message_block[i])
	}

	for ; i >= 0; i-- {
		f := (b & c) | ((^b) & d)
		spew(f, sha1_rc1, message_block[i])
	}

	return sha1_ihv{a, b, c, d, e}
}
