package main

type Buckets struct {
	Weigth   uint16
	BucketId uint32
}

type Group struct {
	GroupId    uint32
	Buckets    []*Buckets
	NumBuckets uint32

	SelectMode uint32
	HashAlg    uint32
	HashBasis  uint32
	HashMask   uint32
	HashMap    []*Buckets
	Service    *MaglevHashService
}
