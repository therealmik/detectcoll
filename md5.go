package detectcoll

var (
	md5_shifts [64]uint = [64]uint{
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
	}

	md5_constants [64]uint32 = [64]uint32{
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
	}
)

type md5_ihv [4]uint32 // An IV/IHV/working state
type md5_mb [16]uint32 // A message block (input data converted to u32le)

type MD5 struct {
	ml  uint64  // message length (in bits)
	ihv md5_ihv // IHV (or IV if no blocks have been processed)
	buf []byte  // Left-over data from a previous Write()
}

type md5_delta struct {
	round int     // Which round do we apply these changes at
	mb    md5_mb  // Change to the message block
	ws    md5_ihv // Change to the working state
}

func append_u32le(ret []byte, n uint32) []byte {
	// Append an integer as 4 bytes in little-endian byte order
	ret = append(ret, byte(n))
	ret = append(ret, byte(n>>8))
	ret = append(ret, byte(n>>16))
	ret = append(ret, byte(n>>24))
	return ret
}

func NewMD5() *MD5 {
	// Return a new MD5 collision-detecting hash object
	return &MD5{
		ml:  0,
		ihv: [4]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476},
	}
}

func (s *MD5) Reset() {
	// Reset the hash object back to new
	*s = *(NewMD5())
}

func (s *MD5) Size() int {
	// How many bytes Sum() returns
	return 16
}

func (s *MD5) BlockSize() int {
	// The blocksize of the hash
	return 64
}

func (s *MD5) Sum(ret []byte) []byte {
	// Append the hash output of all data written so far to ret and
	// return that.  This doesn't modify the state of the hash object.

	t := *s // Copy s

	var padding []byte

	if len(t.buf) <= 56 {
		padding = make([]byte, 64)
	} else {
		padding = make([]byte, 128)
	}

	copy(padding, t.buf)
	padding[len(t.buf)] = 0x80

	padding[len(padding)-1] = byte(t.ml >> 56)
	padding[len(padding)-2] = byte(t.ml >> 48)
	padding[len(padding)-3] = byte(t.ml >> 40)
	padding[len(padding)-4] = byte(t.ml >> 32)
	padding[len(padding)-5] = byte(t.ml >> 24)
	padding[len(padding)-6] = byte(t.ml >> 16)
	padding[len(padding)-7] = byte(t.ml >> 8)
	padding[len(padding)-8] = byte(t.ml)

	for i := 0; i < len(padding); i += 64 {
		mb := create_md5_mb(padding[i : i+64])
		t.process_mb(mb)
	}

	for i := 0; i < 4; i++ {
		ret = append_u32le(ret, t.ihv[i])
	}

	return ret
}

func (s *MD5) Write(b []byte) (n int, err error) {
	// MD5_Update() but in Go ;)
	s.ml += uint64(len(b)) * 8
	s.buf = append(s.buf, b...)

	for len(s.buf) >= 64 {
		mb := create_md5_mb(s.buf[0:64])
		s.process_mb(mb)
		s.buf = s.buf[64:]
	}

	return len(b), nil
}

func create_md5_mb(data []byte) *md5_mb {
	// Take 64 bytes worth of data, and convert into 32-bit big-endian integers
	var mb md5_mb

	if len(data) != 64 {
		panic("Can only create message blocks from 64-byte data chunks")
	}

	for i := uint(0); i < 64; i++ {
		var shift uint = (i % 4) * 8
		mb[i/4] |= (uint32(data[i]) << shift)
	}

	return &mb
}

func (s *MD5) process_mb(mb *md5_mb) {
	var i int
	var ws [64]md5_ihv

	a := s.ihv[0]
	b := s.ihv[1]
	c := s.ihv[2]
	d := s.ihv[3]

	for ; i < 16; i++ {
		f := (b & c) | ((^b) & d)
		m := mb[i]

		b, c, d, a = b+rotl32((a+f+md5_constants[i]+m), md5_shifts[i]), b, c, d
		ws[i] = md5_ihv{a, b, c, d}
	}

	for ; i < 32; i++ {
		f := (d & b) | ((^d) & c)
		m := mb[((5*i)+1)%16]

		b, c, d, a = b+rotl32((a+f+md5_constants[i]+m), md5_shifts[i]), b, c, d
		ws[i] = md5_ihv{a, b, c, d}
	}

	for ; i < 48; i++ {
		f := b ^ c ^ d
		m := mb[((3*i)+5)%16]

		b, c, d, a = b+rotl32((a+f+md5_constants[i]+m), md5_shifts[i]), b, c, d
		ws[i] = md5_ihv{a, b, c, d}
	}

	for ; i < 64; i++ {
		f := c ^ (b | (^d))
		m := mb[(7*i)%16]

		b, c, d, a = b+rotl32((a+f+md5_constants[i]+m), md5_shifts[i]), b, c, d
		ws[i] = md5_ihv{a, b, c, d}
	}

	s.ihv[0] += a
	s.ihv[1] += b
	s.ihv[2] += c
	s.ihv[3] += d
}

func unprocess_mb(delta *md5_delta, mb md5_mb, ws md5_ihv) md5_ihv {
	i := delta.round

	for i := 0; i < 16; i++ {
		mb[i] += delta.mb[i]
	}

	a := ws[0] + delta.ws[0]
	b := ws[1] + delta.ws[1]
	c := ws[2] + delta.ws[2]
	d := ws[3] + delta.ws[3]

	for ; i >= 48; i-- {
		a, b, c, d = b, c, d, a
		f := c ^ (b | (^d))
		m := mb[(7*i)%16]

		a -= b
		a = rotl32(a, 32-md5_shifts[i])
		a -= f + m + md5_constants[i]
	}

	for ; i >= 32; i-- {
		a, b, c, d = b, c, d, a
		f := b ^ c ^ d
		m := mb[((3*i)+5)%16]

		a -= b
		a = rotl32(a, 32-md5_shifts[i])
		a -= f + m + md5_constants[i]
	}

	for ; i >= 16; i-- {
		a, b, c, d = b, c, d, a
		f := (d & b) | ((^d) & c)
		m := mb[((5*i)+1)%16]

		a -= b
		a = rotl32(a, 32-md5_shifts[i])
		a -= f + m + md5_constants[i]
	}

	for ; i >= 0; i-- {
		a, b, c, d = b, c, d, a
		f := (b & c) | ((^b) & d)
		m := mb[i]

		a -= b
		a = rotl32(a, 32-md5_shifts[i])
		a -= f + m + md5_constants[i]
	}

	return md5_ihv{a, b, c, d}
}
