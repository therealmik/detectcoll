package detectcoll

/* This is taken more-or-less copy & paste from libdetectcoll-0.2 by Marc Stevens */
/**************************************************************************\
|
|    Copyright (C) 2012 CWI
|
|    Contact:
|    Marc Stevens
|    Cryptology Group
|    Centrum Wiskunde & Informatica
|    P.O. Box 94079, 1090 GB Amsterdam, Netherlands
|
|  Permission is hereby granted, free of charge, to any person obtaining a copy
|  of this software and associated documentation files (the "Software"), to deal
|  in the Software without restriction, including without limitation the rights
|  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
|  copies of the Software, and to permit persons to whom the Software is
|  furnished to do so, subject to the following conditions:
|
|  The above copyright notice and this permission notice shall be included in
|  all copies or substantial portions of the Software.
|
|  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
|  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
|  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
|  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
|  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
|  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
|  THE SOFTWARE.
|
\**************************************************************************/

var MD5_DELTA []md5_delta = []md5_delta{
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 1 << 31, 0, 0, 0, 0, 0, 0, 1 << 15, 0, 0, 1 << 31, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 1 << 8, 0, 1 << 31, 0, 0, 0, 0, 0, 0, 1 << 15, 0, 0, 1 << 31, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 0, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 1, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 2, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 3, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 4, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 5, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 6, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 7, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 8, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 9, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 10, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 11, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 12, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 13, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 14, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 15, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 16, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 17, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 18, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 19, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 20, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 21, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 22, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 23, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 24, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 25, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 26, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 27, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 28, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 29, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 30, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 31, 0, 0, 0, 0}, round: 44, negate: false, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 1 << 10, 0, 0, 0, 0, 1 << 31, 0, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 1 << 31, 0, 0, 0, 0, 0, 0, 0}, round: 44, negate: false, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 1 << 8, 0, 0, 1 << 31, 0, 0, 0, 0, 0, 1 << 31}, round: 37, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 1 << 31, 0, 0, 0, 0, 0, 0, 1 << 27, 0, 0, 1 << 31, 0, 0, 0}, round: 37, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 1 << 20, 0, 0, 1 << 31, 0, 0, 0, 0, 0, 1 << 31, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 1 << 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, round: 37, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 1 << 10, 0, 0, 0, 0, 0, 1 << 21, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 1 << 10, 0, 0, 0, 0, 0, 1 << 31, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 1 << 31, 0, 0, 1 << 31, 0, 0, 0, 0, 0, 0, 0}, round: 44, negate: false, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 1 << 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 31, 0}, round: 37, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 1 << 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, round: 44, negate: false, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 1 << 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, round: 44, negate: false, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 31, 0}, round: 44, negate: false, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 1 << 25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 1 << 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 1 << 25, 0, 0, 0, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 21, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 16, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 1 << 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 1 << 8, 0, 0, 0, 0, 0, 0, 0, 0, 0}, round: 50, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 27, 0, 0, 0, 0, 0, 0}, round: 50, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 1 << 10, 0, 0, 0, 1 << 27, 0, 0, 0, 0, 0, 0}, round: 37, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 1 << 31, 0, 0, 0, 0, 0, 1 << 31, 0, 0, 0, 0}, round: 44, negate: false, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 1 << 31, 0, 0, 1 << 21, 0, 0, 0, 0}, round: 44, negate: true, zero: true, msb: true},
	md5_delta{message_block: [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 1 << 25, 0, 0, 0, 0, 1 << 31, 0, 0}, round: 44, negate: true, zero: true, msb: true},
}
