// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// castagnoliSSE42 updates the (non-inverted) crc with the given buffer.
//
// func castagnoliSSE42(crc uint32, p []byte) uint32
TEXT ·castagnoliSSE42(SB), NOSPLIT, $0
	MOVL crc+0(FP), AX    // CRC value
	MOVQ p+8(FP), SI      // data pointer
	MOVQ p_len+16(FP), CX // len(p)

	// If there are fewer than 8 bytes to process, skip alignment.
	CMPQ CX, $8
	JL   less_than_8

	MOVQ SI, BX
	ANDQ $7, BX
	JZ   aligned

	// Process the first few bytes to 8-byte align the input.

	// BX = 8 - BX. We need to process this many bytes to align.
	SUBQ $1, BX
	XORQ $7, BX

	BTQ $0, BX
	JNC align_2

	CRC32B (SI), AX
	DECQ   CX
	INCQ   SI

align_2:
	BTQ $1, BX
	JNC align_4

	CRC32W (SI), AX

	SUBQ $2, CX
	ADDQ $2, SI

align_4:
	BTQ $2, BX
	JNC aligned

	CRC32L (SI), AX

	SUBQ $4, CX
	ADDQ $4, SI

aligned:
	// The input is now 8-byte aligned and we can process 8-byte chunks.
	CMPQ CX, $8
	JL   less_than_8

	CRC32Q (SI), AX
	ADDQ   $8, SI
	SUBQ   $8, CX
	JMP    aligned

less_than_8:
	// We may have some bytes left over; process 4 bytes, then 2, then 1.
	BTQ $2, CX
	JNC less_than_4

	CRC32L (SI), AX
	ADDQ   $4, SI

less_than_4:
	BTQ $1, CX
	JNC less_than_2

	CRC32W (SI), AX
	ADDQ   $2, SI

less_than_2:
	BTQ $0, CX
	JNC done

	CRC32B (SI), AX

done:
	MOVL AX, ret+32(FP)
	RET

