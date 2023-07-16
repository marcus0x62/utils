/* -*- Mode: Go;
 *
 * reverser.go -- A basic threaded RC4 decryption tool.
 *
 * This is a more-or-less direct translation of a C utility I wrote during a CTF, which in turn was a
 * C translation of the decryption routine I was looking at in IDA Pro with some brute forcing and
 * parallelization code bolted on.
 *
 * The included nested-loop structure is built around an example 11-byte key where some bytes are known
 * and some aren't, and where there are value constraints on the unknown bytes; this can be modified as
 * needed.  The loop for the first unknown byte is used to create goroutines to parallelize the key
 * search.
 *
 * Copyright 2023 Marcus Butler
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package main

import (
	"fmt"
	"os"
)

func main() {
	decrypt := make(chan string)
	enc := []uint8{
		0xa6, 0xcb, 0x8d, 0xc9, 0x70, 0x96, 0xd1, 0x71, 0x6f,
		0x97, 0x66, 0xa7, 0x9d, 0xa6, 0x24, 0x61, 0xd6, 0xea,
		0x5e, 0x82, 0xeb, 0xdb, 0x1e, 0x22, 0xa5, 0x4f, 0xf6,
		0x02, 0x86, 0x97, 0x1c, 0x6c, 0x01, 0xb8, 0x00}

	var month uint8

	for month = 1; month < 12; month++ {
		go func() {
			// We need a private copy of these data structures per goroutine
			stab := make([]uint8, 256)
			dec := make([]uint8, len(enc))
			key := []uint8{0x62, 0x30, 0x30, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			keylen := len(key)

			// Capture the month before the next goroutine starts
			key[4] = 0x35 + month

			var i, j int
			var byte1, byte2 uint8
			var day, hour, vhigh, vlow, debug, lang uint8

			for day = 1; day < 31; day++ {
				key[5] = 0x29 + day
				for hour = 0; hour < 24; hour++ {
					key[6] = 0x40 + hour
					for vhigh = 5; vhigh < 12; vhigh++ {
						key[7] = 0x73 + vhigh
						for vlow = 0; vlow < 4; vlow++ {
							key[8] = 0x5d + vlow
							for debug = 0; debug < 2; debug++ {
								key[9] = 0x3f + debug
								for lang = 0; lang < 147; lang++ {
									key[10] = 0x6b + lang
									// Initialize the substitution
									// table
									for i = 0; i < 256; i++ {
										stab[i] = uint8(i)
									}

									j = 0
									byte2 = 0
									for i = 0; i < 256; i++ {
										byte1 = stab[i]

										byte2 = (byte1 + byte2 + key[j]) & 0xff
										stab[i] = stab[byte2]
										stab[byte2] = byte1

										// This is faster than
										// calling i mod keylen
										// in the array index
										// above.
										j++
										if j > keylen-1 {
											j = 0
										}
									}

									j = 0
									for i = 1; i < len(enc); i++ {
										byte1 = stab[i]
										j = (j + int(byte1)) & 0xFF
										byte2 = stab[j]

										stab[i] = byte2
										stab[j] = byte1

										dec[i-1] = stab[(byte1+byte2)&0xFF] ^ enc[i-1]
									}

									if dec[0] == 'K' && dec[1] == 'e' && dec[2] == 'y' && dec[3] == ':' {
										decrypt <- string(dec)
									}
								}
							}
						}
					}
				}
			}
		}()
	}

	for {
		fmt.Println(<-decrypt)
		os.Exit(1)
	}
}
