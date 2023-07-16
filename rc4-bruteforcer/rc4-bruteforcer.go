/* -*- Mode: Go;
 *
 * reverser.go -- A basic threaded RC4 decryption tool.
 *
 * This is a threaded RC4 decryption utility that was originally written (in C) during a CTF.  It is fast
 * and allows you the enter what you know about the key -- known bytes, min/max values for unknown bytes,
 * and fixed offsets to add to individual bytes in order to constrain the key space to be searched.
 * It also includes an estimate mode (invoke with --estimate) that will tell you the current size of the
 * key space to be searched and a rough estimate for how long a worst-case brute force search of that
 * key space would take on the machine the utility is being executed on.  One weakness of this is that
 * it does require the user to specify a bit of known plaintext to identify when the correct key is
 * found.  It doesn't do any statistical analysis to identify likely successful keys.
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
 *
 */

package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

var n_threads int = 12 // Number of worker threads.  Physical cores * 2 is a good first guess
var n_keys int = 65536 // Number of keys to dispatch to a worker

// Put your encrypted blob here.
var enc []uint8 = []uint8{
	0xa6, 0xcb, 0x8d, 0xc9, 0x70, 0x96, 0xd1, 0x71, 0x6f,
	0x97, 0x66, 0xa7, 0x9d, 0xa6, 0x24, 0x61, 0xd6, 0xea,
	0x5e, 0x82, 0xeb, 0xdb, 0x1e, 0x22, 0xa5, 0x4f, 0xf6,
	0x02, 0x86, 0x97, 0x1c, 0x6c, 0x01, 0xb8, 0x00}

// This is rigged for testing to quickly find the key for the default encrypted payload.
/* var keyspace [][]uint8 = [][]uint8{
{98, 48, 48, 33, 65, 54, 74, 120, 94, 0, 0},                        // Known key bytes
{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00}, // Known/unknown byte flag
{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x6b}, // Manual offset
{0x00, 0x00, 0x00, 0x00, 1, 1, 0, 5, 0, 0, 0},                      // Min value for byte
{0x00, 0x00, 0x00, 0x00, 12, 31, 23, 12, 4, 2, 147}}                // Max value for byte
*/

// This is where you enter what you know about the key.  Each line should have the same number of bytes.
//
// The first array element should be an array of the bytes you known about -- they don't need to be
// consecutive.  Set unknown bytes to 0.
//
// The elements in the second line should be set to 1 for known bytes and 0 for unknown bytes.
//
// The elements in the third line should be set to any manual offsets for each byte (i.e., the sample
// you are analyzing adds 0x35 to the 4th byte of the key.
//
// The elements in the fourth line are the minimum values for each variable byte -- set to 0 if you
// don't know (or there is no obvious minimum.)
//
// The elements in the fifth line are the maximum value for each variable byte -- set to 255 if you don't
// know (or there is no obvious maximum.)
var keyspace [][]uint8 = [][]uint8{
	{0x62, 0x30, 0x30, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Known key bytes
	{0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Known/unknown byte flag
	{0x00, 0x00, 0x00, 0x00, 0x35, 0x29, 0x40, 0x73, 0x5d, 0x3f, 0x6b}, // Manual offset
	{0x00, 0x00, 0x00, 0x00, 1, 1, 0, 5, 0, 0, 0},                      // Min value for byte
	{0x00, 0x00, 0x00, 0x00, 12, 31, 23, 12, 4, 2, 147}}                // Max value for byte

// Set this to the known plaintext you are searching for.  So, if you know the flag starts out with
// Flag: or Key:, put that here.
var pattern string = "Key:"

var wg sync.WaitGroup

func worker(wg *sync.WaitGroup, dispatch chan [][]uint8, decrypt chan string) {
	var keys [][]uint8
	var status bool

	defer wg.Done()

	for {
		for {
			keys, status = <-dispatch
			if !status {
				return
			}

			if len(keys) > 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		for _, key := range keys {
			var i, j int
			var byte1, byte2 uint8

			stab := make([]uint8, 256)
			dec := make([]uint8, len(enc))
			keylen := len(key)

			// Initialize the substitution table
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

				// This is faster than calling i mod keylen in the array index above.
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

			found := true
			for i = 0; i < len(pattern); i++ {
				if dec[i] != pattern[i] {
					found = false
				}
			}
			if found == true {
				decrypt <- string(dec)
			}
		}
	}
}

func dispatcher(wg *sync.WaitGroup, dispatch chan [][]uint8) {
	var keys [][]uint8 = [][]uint8{}

	defer wg.Done()

	cur_key := make([]uint8, len(keyspace[0]))

	var i, j int = 0, 0

	// Copy the known bytes and the minimum values for the unknown bytes
	for i = 0; i < len(cur_key); i++ {
		if keyspace[1][i] == 1 {
			cur_key[i] = keyspace[0][i]
		} else {
			cur_key[i] = keyspace[3][i]
		}
	}

	var finished bool = false
	var rightmostidx int = 0
	var leftmostidx int = 0

	for i = 0; i < len(cur_key); i++ {
		if keyspace[1][i] == 0 {
			rightmostidx = i
		}
	}

	for i = len(cur_key) - 1; i >= 0; i-- {
		if keyspace[1][i] == 0 {
			leftmostidx = i
		}
	}

	keyidx := 0

	/* Our algorithm
	 * 1. Iterate over the right-most variable value from minval to maxval
	 * 2. Find the next most significant (further left) variable value that is < its maxval, and
	 *    increment by one.
	 * 3. If 2. is successful, reset all variable values to right of the value we incremented to
	 *    their minvals.
	 * 4. Test to see if there any variable values in the current key that are < their maxvals.
	 *    Set a flag to continue if we find any.
	 *
	 * ** Note that this handles the tail case correctly, because the right-most variable is
	 * ** iterated first, thus on the last round we'll go through the right-most iteration but then
	 * ** fail to find a more significant value to increment.
	 */
	for {
		for i = int(keyspace[3][rightmostidx]); cur_key[rightmostidx] < keyspace[4][rightmostidx]; i++ {
			cur_key[rightmostidx] = uint8(i)

			// Make a real copy of the current key
			tmp_key := make([]uint8, len(cur_key))
			for j = 0; j < len(cur_key); j++ {
				var byte = cur_key[j]
				tmp_key[j] = byte + keyspace[2][j]
			}
			keys = append(keys, tmp_key)
			keyidx++

			if keyidx == n_keys {
				dispatch <- keys
				keyidx = 0
				keys = [][]uint8{}
			}
		}

		for i = rightmostidx - 1; i >= leftmostidx; i-- {
			if cur_key[i] < keyspace[4][i] {
				cur_key[i]++
				if i < len(cur_key) {
					for j = i + 1; j <= rightmostidx; j++ {
						cur_key[j] = keyspace[3][j]
					}
				}
				break
			}
		}

		finished = true
		for i = 0; i < len(cur_key); i++ {
			if keyspace[1][i] == 0 && cur_key[i] != keyspace[4][i] {
				finished = false
			}
		}
		if finished == true {
			dispatch <- keys
			close(dispatch)
			break
		}
	}
}

func main() {
	decrypt := make(chan string)
	dispatch := make(chan [][]uint8)

	for _, arg := range os.Args {
		if arg == "--estimate" {
			nk := 1
			for i := 0; i < len(keyspace[1]); i++ {
				if keyspace[1][i] == 0 {
					nk *= int(keyspace[4][i]-keyspace[3][i]) + 1
				}
			}

			fmt.Printf("There are %d keys to search\n", nk)

			// Measure time to test ~16M keys
			keyspace = [][]uint8{{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {255, 255, 255}}

			start_t := time.Now()

			for i := 0; i < n_threads; i++ {
				wg.Add(1)
				go worker(&wg, dispatch, decrypt)
			}

			wg.Add(1)
			go dispatcher(&wg, dispatch)

			wg.Wait()

			stop_t := time.Now()

			fmt.Printf("Test run took %f seconds\n", stop_t.Sub(start_t).Seconds())
			fmt.Printf("A full search would take around %f seconds\n",
				float64(nk/(256*256*256))*float64(stop_t.Sub(start_t).Seconds()))
			os.Exit(0)
		}
	}

	for i := 0; i < n_threads; i++ {
		wg.Add(1)
		go worker(&wg, dispatch, decrypt)
	}

	wg.Add(1)
	go dispatcher(&wg, dispatch)

	fmt.Printf("Waiting for key...\n")
	fmt.Printf("Found key: '%s'\n", <-decrypt)
	os.Exit(0)
}
