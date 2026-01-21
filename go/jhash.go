package main

// original code http://burtleburtle.net/bob/c/lookup3.c
// https://github.com/MstrVLT/lookup3/blob/master/lookup3.go

func rot(x, k uint32) uint32 {
	return (((x) << (k)) | ((x) >> (32 - (k))))
}

func mix(a, b, c uint32) (uint32, uint32, uint32) {

	a -= c
	a ^= rot(c, 4)
	c += b

	b -= a
	b ^= rot(a, 6)
	a += c

	c -= b
	c ^= rot(b, 8)
	b += a

	a -= c
	a ^= rot(c, 16)
	c += b

	b -= a
	b ^= rot(a, 19)
	a += c

	c -= b
	c ^= rot(b, 4)
	b += a

	return a, b, c
}

func final(a, b, c uint32) (uint32, uint32, uint32) {

	c ^= b
	c -= rot(b, 14)

	a ^= c
	a -= rot(c, 11)

	b ^= a
	b -= rot(a, 25)

	c ^= b
	c -= rot(b, 16)

	a ^= c
	a -= rot(c, 4)

	b ^= a
	b -= rot(a, 14)

	c ^= b
	c -= rot(b, 24)

	return a, b, c
}

func hashlittle(k []uint8, initval uint32) uint32 {

	var a, b, c uint32

	/* Set up the internal state */
	a = 0xdeadbeef + uint32(len(k)) + initval
	b = 0xdeadbeef + uint32(len(k)) + initval
	c = 0xdeadbeef + uint32(len(k)) + initval

	/*--------------- all but the last block: affect some 32 bits of (a,b,c) */

	for len(k) >= 12 {
		a += uint32(k[0])
		a += uint32(k[1]) << 8
		a += uint32(k[2]) << 16
		a += uint32(k[3]) << 24
		b += uint32(k[4])
		b += uint32(k[5]) << 8
		b += uint32(k[6]) << 16
		b += uint32(k[7]) << 24
		c += uint32(k[8])
		c += uint32(k[9]) << 8
		c += uint32(k[10]) << 16
		c += uint32(k[11]) << 24
		a, b, c = mix(a, b, c)
		k = k[12:]
	}

	/*-------------------------------- last block: affect all 32 bits of (c) */
	switch len(k) {
	case 11:
		c += uint32(k[10]) << 16
		fallthrough
	case 10:
		c += uint32(k[9]) << 8
		fallthrough
	case 9:
		c += uint32(k[8])
		fallthrough
	case 8:
		b += uint32(k[7]) << 24
		fallthrough
	case 7:
		b += uint32(k[6]) << 16
		fallthrough
	case 6:
		b += uint32(k[5]) << 8
		fallthrough
	case 5:
		b += uint32(k[4])
		fallthrough
	case 4:
		a += uint32(k[3]) << 24
		fallthrough
	case 3:
		a += uint32(k[2]) << 16
		fallthrough
	case 2:
		a += uint32(k[1]) << 8
		fallthrough
	case 1:
		a += uint32(k[0])
	case 0:
		return c
	}
	a, b, c = final(a, b, c)
	return c
}
