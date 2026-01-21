package main

const (
	MH_FLAG_FALLBACK     = 0x0001
	MH_DEST_FLAG_DISABLE = 0x0001
)

type MaglevDestSetup struct {
	Offset uint32
	Kkip   uint32
	Perm   uint32
	Turns  int
}

type MaglevDest struct {
	GroudId    uint32
	DestId     uint32
	Flags      uint32
	Weight     uint32
	LastWeight uint32
	Data       interface{}
}

type MaglevLookup struct {
	MaglevDest
}

type MaglevState struct {
	RefCnt     uint32
	Lookup     []*MaglevLookup
	LookupSize uint32
	DestSetup  []*MaglevDest
	Gcd        int
	Rshift     int
}

type MaglevHashService struct {
	RefCnt       uint32
	Flags        uint32
	TableSize    uint32
	Destinations []*MaglevDest
	State        *MaglevState
}

/*
// should be 36 bytes
type HashVal struct {
	TunIp [4]uint32
	PktIp [4]uint32
	Port  uint16
}
*/

const (
	DEFAULT_TAB_SIZE_IDX   = 5
	DEFAULT_HASH_DATA_SIZE = 36
)

var tab_size_primes = []uint32{11, 251, 509, 1021, 2039, 4093, 8191, 16381, 32749, 65521, 131071}

func hash1(data []byte) uint32 {
	return HashBytes(data, 0)
}

func hash2(data uint8, len uint32) uint32 {

	return 0
}

func getHashTableSize(idx int) uint32 {

	l := len(tab_size_primes)

	if idx > l {
		idx = 5
	}

	return tab_size_primes[idx]
}

func MaglevBuild(group *Group) {

}
