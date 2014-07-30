// sha256.h
#ifndef SHA_256_H_INCLUDED
#define SHA_256_H_INCLUDED

// This is a relatively straightforward implementation of SHA-256. It makes no particular
// attempt at optimization, instead aiming toward easy verification against the standard.
// To that end, many of the variable names are identical to those used in FIPS 180-2 and
// FIPS 180-3.
//
// The code should be fairly portable, within a few limitations:
// 1. It requires that 'char' have 8 bits. In theory this is avoidable, but I don't think
// it's worth the bother.
// 2. It only deals with inputs in (8-bit) bytes. In theory, SHA-256 can deal with a number of
// bits that's not a multiple of 8, but I've never needed it. Since the padding always results
// in a byte-sized stream, the only parts that would need changing would be reading and padding
// the input. The main hashing portion would be unaffected.
//
// Originally written in February 2008 for SHA-1.
// Converted to SHA-256 sometime later (sorry, I don't remember exactly when).
//
// You can use this software any way you want to, with following limitations
// (shamelessly stolen from the Boost software license):
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
// SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
// FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//
// If you put this to real use, I'd be happy to hear about it. If you find a bug,
// I'd be interested in hearing about that too. There's even a pretty good chance
// that I'll try to fix it, though I certainly can't guarantee that.
//
// Jerry Coffin, Colorado Springs
//
#include <algorithm>
#include <vector>
#include <string>
#include <assert.h>
#include <iostream>
#include <sstream>
#include <iomanip>

#if defined(_MSC_VER) && _MSC_VER < 1600
typedef unsigned int uint32_t;
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#endif

namespace crypto {
    //namespace {
    struct ternary_operator {
            virtual uint32_t operator()(uint32_t x, uint32_t y, uint32_t z) = 0;
    };
    //}

    class sha256 {
            static const size_t hash_size = 8;
            static const size_t min_pad = 64;
            static const size_t block_bits = 512;
            static const size_t block_bytes = block_bits / 8;
            static const size_t block_words = block_bytes / 4;

            std::vector<uint32_t> K;
            std::vector<uint32_t> H;
            std::vector<uint32_t> W;
            std::vector<ternary_operator *> fs;
            std::vector<uint32_t> temp;

            static const size_t block_size = 16;
            static const size_t bytes_per_word = 4;
            size_t total_size;

            // hash a 512-bit block of input.
            //
            void hash_block(std::vector<uint32_t> const &block);

            // Pad the input to a multiple of 512 bits, and add the length
            // in binary to the end.
            static std::string pad(std::string const &input);

            // Turn 64 bytes into a block of 16 uint32_t's.
            std::vector<uint32_t> make_block(std::string const &in);

        public:
            // Construct a SHA-256 object. More expensive that typical
            // ctor, but not expected to be copied a lot or anything
            // like that, so it should be fairly harmless.
            sha256();

            // The two ways to provide input for hashing: as a stream or a string.
            // Either way, you get the result as a vector<uint32_t>. It's a fairly
            // small vector, so even if your compiler doesn't do return-value
            // optimization, the time for copying isn't like to be significant.
            //
            std::vector<uint32_t> operator()(std::string const &input);

            friend std::ostream &operator<<(std::ostream &os, sha256 const &s);
    };
}

#endif
