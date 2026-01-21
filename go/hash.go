package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"hash/crc32"
)

func castagnoliSSE42(crc uint32, p []byte) uint32

func Crc32CUpdate(crc uint32, p []byte) uint32 {
	return castagnoliSSE42(crc, p)
}

func Int32ToBytes(i uint32) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, i)

	return buf.Bytes()
}

func Int64ToBytes(i uint64) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, i)

	return buf.Bytes()
}

func HashAdd(hash uint32, data uint32) uint32 {
	b := Int32ToBytes(data)
	h1 := Crc32CUpdate(hash, b)

	return h1
}

func HashFinish(hash uint64, final uint64) uint32 {
	b := Int64ToBytes(final)

	/* The finishing multiplier 0x805204f3 has been experimentally
	 * derived to pass the testsuite hash tests. */

	hash = uint64(Crc32CUpdate(uint32(hash), b) * 0x805204f3)
	return uint32(hash ^ uint64(uint32(hash)>>16)) /* Increase entropy in LSBs. */
}

func HashBytes(data []byte, basis uint32) uint32 {
	var hash uint32
	orig_n := len(data)
	hash = basis
	l := len(data)

	for l >= 4 {
		hash = Crc32CUpdate(hash, data[:4])
		data = data[4:]
		l -= 4
	}

	if l > 0 {
		b := make([]byte, 4)
		copy(b, data)
		hash = Crc32CUpdate(hash, b)
	}

	return HashFinish(uint64(hash), uint64(orig_n))
}

///////////////////////////////////

func VerifyCrc() {
	//////////////////////////
	// non-inverted version
	expected := 0xc4451272
	var hash_data uint32 = 6
	var crc uint32

	crc = 0
	b := Int32ToBytes(hash_data)
	crc = Crc32CUpdate(crc, b)
	fmt.Printf("SSE4.2 CRC  : 0x%x, expected=0x%x \n", crc, expected)

	////////////////////////////////
	// standard reflected version
	// https://www.sunshine2k.de/coding/javascript/crc/crc_js.html

	table := crc32.MakeTable(crc32.Castagnoli)
	expected = 0x12FD1978
	b = []byte{6, 6, 6, 6} // byteorder free
	crc = crc32.Checksum(b, table)
	fmt.Printf("Standard CRC: 0x%x, expected=0x%x \n", crc, expected)
}

func VerifyHashByte() {
	expected := 0xa89a73bf
	var hash_data []byte = []byte{6}
	var hash uint32

	hash = 0
	hash = HashBytes(hash_data, hash)
	fmt.Printf("Byte Hash   : 0x%x, expected=0x%x \n", hash, expected)
}

func VerifyHashBytes() {
	expected := 0x5271e49c
	var hash uint32
	buf := make([]byte, DEFAULT_HASH_DATA_SIZE)

	// srcip ^ dstip
	ip := uint32(0xc25814ac)
	ip ^= 0x1aea14ac
	copy(buf[16:], Int32ToBytes(ip))

	// protocol
	var protocol []byte = []byte{6}

	hash = 0
	hash = HashBytes(protocol, hash)
	fmt.Printf("Port Hash   : 0x%x, expected=0x%x\n", hash, 0xa89a73bf)

	// sport ^ dposrt
	port := uint16(0x3ace)
	port ^= 0x5000

	buf[32] = byte(port)
	buf[33] = byte(port >> 8)

	hash = HashBytes(buf, hash)
	fmt.Printf("Bytes Hash  : 0x%x, expected=0x%x \n", hash, expected)
}

func VerifyMHash4Bytes() {
	expected := 0xf4c0ec39
	l := 4
	buf := make([]byte, l)
	buf = []byte{0, 1, 2, 3}

	//buf = bytes.Repeat([]byte{1}, l)

	mur := NewMurmur32()
	mur.Write(buf)
	hash := mur.Sum32()

	fmt.Printf("Bytes MHash : 0x%x, expected=0x%x, len=%d \n", hash, expected, len(buf))
}

func VerifyMhashBytes() {
	expected := 0x805eab91
	var hash uint32
	buf := make([]byte, DEFAULT_HASH_DATA_SIZE)

	// srcip ^ dstip
	ip := uint32(0xc25814ac)
	ip ^= 0x1aea14ac
	copy(buf[16:], Int32ToBytes(ip))

	// sport ^ dposrt
	port := uint16(0x3ace)
	port ^= 0x5000

	buf[32] = byte(port)
	buf[33] = byte(port >> 8)

	mur := NewMurmur32()
	mur.Write(buf)
	hash = mur.Sum32()
	fmt.Printf("Bytes MHash : 0x%x, expected=0x%x, len=%d \n", hash, expected, len(buf))
}

func VerifyJHash4Bytes() {
	expected := 0xe4cf1d42
	l := 4
	buf := make([]byte, l)

	//buf = bytes.Repeat([]byte{1}, l)
	buf = []byte{0, 1, 2, 3}

	hash := hashlittle(buf, 0)
	fmt.Printf("Bytes JHash : 0x%x, expected=0x%x, len=%d \n", hash, expected, len(buf))
}

func VerifyJhashBytes() {
	expected := 0x3adcbda7
	var hash uint32
	buf := make([]byte, DEFAULT_HASH_DATA_SIZE)

	// srcip ^ dstip
	ip := uint32(0xc25814ac)
	ip ^= 0x1aea14ac
	copy(buf[16:], Int32ToBytes(ip))

	// sport ^ dposrt
	port := uint16(0x3ace)
	port ^= 0x5000

	buf[32] = byte(port)
	buf[33] = byte(port >> 8)

	hash = hashlittle(buf, 0)
	fmt.Printf("Bytes JHash : 0x%x, expected=0x%x, len=%d \n", hash, expected, len(buf))
}
