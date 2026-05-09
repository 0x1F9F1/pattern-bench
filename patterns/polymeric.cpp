// Source remote: https://github.com/p0lymeric/mewgenics_analysis/blob/3da0a0b4fa0ffdace7c914ba0cb5dd4905b991dc/cpp/amoeba/utilities/signature.hpp

// A simple SIMD pattern searcher implementation.
// Not bad just with SSE2 acceleration!
//
// polymeric 2026
// MIT License

#include "pattern_entry.h"

// Enable use of SIMD intrinsics, to accelerate pattern scanning
#define USE_SSE2_INTRINSICS_STAGE1
#define USE_SSE2_INTRINSICS_STAGE2

#include <cstddef>
#include <cstdint>
#include <concepts>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

// Config
#if defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)
#elif defined(__i386__) || defined(_M_IX86)
    // Runtime EFLAGS/CPUID checks not performed
#else
    // Undefine intrinsics use macros if not compiling for x86(-64)
    #undef USE_SSE2_INTRINSICS_STAGE1
    #undef USE_SSE2_INTRINSICS_STAGE2
    // Rename the scanner from "polymeric (SSE2)" to "polymeric (Scalar)"
    #define _PLATFORM_NOT_X86
#endif

#if defined(USE_SSE2_INTRINSICS_STAGE1) || defined(USE_SSE2_INTRINSICS_STAGE2)
    #include <immintrin.h>
#endif

#if defined(USE_SSE2_INTRINSICS_STAGE1)
    #if defined(_MSC_VER)
        #include <intrin.h>
        #pragma intrinsic(_BitScanForward)
    #endif
#endif

// Compiler attributes
#if defined(_MSC_VER)
    #define MUST_INLINE __forceinline
#else
    #define MUST_INLINE inline __attribute__((always_inline))
#endif

class BPatternDescriptor {
public:
    size_t first_nonwildcard_idx;
    size_t last_nonwildcard_idx;
    bool trivial_pattern; // empty or all wildcards

    virtual std::span<const byte> pattern() const = 0;
    virtual std::span<const byte> pattern_mask() const = 0;

    using stage2_compare_fp_t = bool(const byte *ptr_0, const byte *ptr_1, const byte *ptr_mask, size_t size_bytes);

    template<std::predicate<const byte *> CB>
    void find_callback(const byte *seq_start, size_t seq_size_bytes, CB &&callback) const {
        std::span<const byte> pattern_ = this->pattern();
        std::span<const byte> pattern_mask_ = this->pattern_mask();
        size_t pattern_size_bytes = pattern_.size_bytes();

        // Trivial cases
        if(pattern_size_bytes > seq_size_bytes) {
            // a pattern will never match a sequence of shorter length
            return;
        }
        if(this->trivial_pattern) {
            if(pattern_size_bytes < seq_size_bytes) {
                // an all-wildcard or empty pattern trivially matches a sequence of longer length at more than one point
                return;
            } else /*if(pattern_size_bytes == seq_size_bytes)*/ {
                // an all-wildcard pattern trivially matches a sequence of equivalent length at exactly one point
                // 'the' empty pattern uniquely matches 'the' empty sequence
                callback(seq_start);
                return;
            }
        }

        // Now we need to handle non-trivial cases. The following preconditions are assured:
        // - 1 <= pattern.pattern.size_bytes() <= size_bytes
        // - the pattern is not all wildcards

        // The search marches along the sequence at two points, testing the first and last non-wildcard bytes,
        // and cascades into a full comparison whenever both match.

        // now we readjust start to base indices on first_nonwildcard_idx
        size_t offset = this->first_nonwildcard_idx;
        // and end to avoid overrunning buffers beyond pattern.pattern.size_bytes()
        size_t limit = offset + seq_size_bytes - pattern_size_bytes + 1;
        size_t dist_pattern_first_last_nonwildcard = this->last_nonwildcard_idx - this->first_nonwildcard_idx;

        // Stage 2 optimizations involve a time tradeoff between rejecting short patterns vs. matching long patterns.
        // These specializations attempt to reduce overhead from redundant pattern length checks in the hot loop.
        stage2_compare_fp_t *stage2_compare_fp;
        // These checks are written in this form to reflect the arithmetic used for stage 2 dispatch
        // (if(dist_pattern_first_last_nonwildcard <= 1 || (*stage2_compare_fp)(... dist_pattern_first_last_nonwildcard - 1)))
        #ifdef USE_SSE2_INTRINSICS_STAGE2
        if(dist_pattern_first_last_nonwildcard > 1 && dist_pattern_first_last_nonwildcard - 1 >= 16) {
            stage2_compare_fp = &stage2_compare<true>;
        } else
        #endif
        {
            stage2_compare_fp = &stage2_compare<false>;
        }

        // ref: http://0x80.pl/notesen/2016-11-28-simd-strfind.html#generic-sse-avx2
        #ifdef USE_SSE2_INTRINSICS_STAGE1
        const __m128i vec_first_byte = _mm_set1_epi8(pattern_[this->first_nonwildcard_idx]);
        const __m128i vec_last_byte = _mm_set1_epi8(pattern_[this->last_nonwildcard_idx]);
        const __m128i vec_first_byte_mask = _mm_set1_epi8(pattern_mask_[this->first_nonwildcard_idx]);
        const __m128i vec_last_byte_mask = _mm_set1_epi8(pattern_mask_[this->last_nonwildcard_idx]);
        while(offset + 16 <= limit) {
            const byte *addr = seq_start + offset;
            const __m128i vec_first_block = _mm_loadu_si128(reinterpret_cast<const __m128i *>(addr));
            const __m128i vec_last_block = _mm_loadu_si128(reinterpret_cast<const __m128i *>(addr + dist_pattern_first_last_nonwildcard));

            const __m128i vec_eq_first_byte = _mm_cmpeq_epi8(vec_first_byte, _mm_and_si128(vec_first_byte_mask, vec_first_block));
            const __m128i vec_eq_last_byte = _mm_cmpeq_epi8(vec_last_byte, _mm_and_si128(vec_last_byte_mask, vec_last_block));

            const __m128i vec_eq_both_bytes = _mm_and_si128(vec_eq_first_byte, vec_eq_last_byte);

            uint32_t equality_bytewise = _mm_movemask_epi8(vec_eq_both_bytes);

            while(equality_bytewise != 0) {
                // get rightmost set index (lower indices first)
                uint32_t bitpos = bsf(equality_bytewise);

                const byte *match_start = addr + bitpos - this->first_nonwildcard_idx;

                if(
                    dist_pattern_first_last_nonwildcard <= 1 ||
                    (*stage2_compare_fp)(
                        addr + bitpos + 1,
                        &pattern_[this->first_nonwildcard_idx + 1],
                        &pattern_mask_[this->first_nonwildcard_idx + 1],
                        dist_pattern_first_last_nonwildcard - 1
                    )
                ) {
                    if(!callback(match_start)) {
                        return;
                    }
                }

                // clear rightmost set
                equality_bytewise &= equality_bytewise - 1;
            }

            offset += 16;
        }
        #endif

        while(offset < limit) {
            const byte *addr = seq_start + offset;
            bool first_byte_matches = (addr[0] & pattern_mask_[this->first_nonwildcard_idx]) == pattern_[this->first_nonwildcard_idx];
            bool last_byte_matches = (addr[dist_pattern_first_last_nonwildcard] & pattern_mask_[this->last_nonwildcard_idx]) == pattern_[this->last_nonwildcard_idx];

            if(first_byte_matches && last_byte_matches) {
                const byte *match_start = addr - this->first_nonwildcard_idx;

                if(
                    dist_pattern_first_last_nonwildcard <= 1 ||
                    (*stage2_compare_fp)(
                        addr + 1,
                        &pattern_[this->first_nonwildcard_idx + 1],
                        &pattern_mask_[this->first_nonwildcard_idx + 1],
                        dist_pattern_first_last_nonwildcard - 1
                    )
                ) {
                    if(!callback(match_start)) {
                        return;
                    }
                }
            }
            offset++;
        }
    }

protected:
    static constexpr byte parse_char_0_to_F_as_hex(char c) {
        if(c >= '0' && c <= '9') {
            return c - '0';
        }
        switch(c) {
            case 'a': return 10;
            case 'b': return 11;
            case 'c': return 12;
            case 'd': return 13;
            case 'e': return 14;
            case 'f': return 15;
            case 'A': return 10;
            case 'B': return 11;
            case 'C': return 12;
            case 'D': return 13;
            case 'E': return 14;
            case 'F': return 15;
            // 16 represents a decode error
            default: return 16;
        }
    }

    static constexpr size_t make_pattern_calc_size(const std::string_view sv) {
        size_t cnt = 0;
        for(size_t i = 0; i < sv.length(); i++) {
            if(sv[i] != ' ' && sv[i] != '\t') {
                cnt++;
            }
        }
        if(cnt % 2 != 0) { // odd
            // throwing in a constexpr context is very cursed, but as they say, "when in Rome"
            throw std::logic_error("Given hex pattern does not have an even number of digits");
        }
        return cnt / 2;
    }

    constexpr void make_pattern_compile(const std::string_view sv, const size_t size, std::span<byte> pattern_impl, std::span<byte> pattern_mask_impl) {
        this->first_nonwildcard_idx = size;
        this->last_nonwildcard_idx = size;
        this->trivial_pattern = true;

        size_t cnt = 0;
        for(size_t i = 0; i < sv.length(); i++) {
            if(sv[i] != ' ' && sv[i] != '\t') { // horizontal whitespace
                if(sv[i] != '?' && parse_char_0_to_F_as_hex(sv[i]) >= 16) { // ?, 0-9, A-F, a-f
                    throw std::logic_error("Given hex pattern has unexpected characters");
                }
                if(cnt % 2 == 0) { // nibble 0, high
                    pattern_impl[cnt / 2] = 0x00;
                    pattern_mask_impl[cnt / 2] = 0xFF;
                    if(sv[i] == '?') {
                        pattern_mask_impl[cnt / 2] ^= 0xF0;
                    } else {
                        pattern_impl[cnt / 2] |= parse_char_0_to_F_as_hex(sv[i]) << 4;
                        if(this->first_nonwildcard_idx == size) {
                            this->first_nonwildcard_idx = cnt / 2;
                        }
                        this->last_nonwildcard_idx = cnt / 2;
                        this->trivial_pattern = false;
                    }
                } else { // nibble 1, low
                    if(sv[i] == '?') {
                        pattern_mask_impl[cnt / 2] ^= 0x0F;
                    } else {
                        pattern_impl[cnt / 2] |= parse_char_0_to_F_as_hex(sv[i]);
                        if(this->first_nonwildcard_idx == size) {
                            this->first_nonwildcard_idx = cnt / 2;
                        }
                        this->last_nonwildcard_idx = cnt / 2;
                        this->trivial_pattern = false;
                    }
                }
                cnt++;
            }
            // mutual guarantee with make_pattern_calc_size: cnt will never exceed size here
        }
        // mutual guarantee with make_pattern_calc_size: cnt will equal size here
    }

private:
    #if defined(USE_SSE2_INTRINSICS_STAGE1)
    static MUST_INLINE uint32_t bsf(uint32_t mask) {
        uint32_t bitpos;
        #ifdef _MSC_VER
        static_assert(sizeof(uint32_t) == sizeof(unsigned long));
        _BitScanForward(reinterpret_cast<unsigned long *>(&bitpos), mask);
        #else
        bitpos = __builtin_ctz(mask);
        #endif
        return bitpos;
    }
    #endif

    template<bool USESSE2>
    static bool stage2_compare(const byte *ptr_0, const byte *ptr_1, const byte *ptr_mask, size_t size_bytes) {
        size_t offset = 0;

        #ifdef USE_SSE2_INTRINSICS_STAGE2
        if constexpr(USESSE2) {
            const __m128i vec_zero = _mm_setzero_si128();
            while(offset + 16 <= size_bytes) {
                const __m128i vec_0 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(ptr_0 + offset));
                const __m128i vec_1 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(ptr_1 + offset));
                // bitwise difference acceptance mask
                const __m128i vec_mask = _mm_loadu_si128(reinterpret_cast<const __m128i *>(ptr_mask + offset));

                // bitwise difference vector
                const __m128i vec_difference = _mm_xor_si128(vec_0, vec_1);

                // If bit i has different values and the mask bit is set, then there is a miscompare.
                // miscompares[bit_i] = vec_mask[bit_i] && vec_difference[bit_i]
                const __m128i vec_miscompares_bitwise = _mm_and_si128(vec_mask, vec_difference);

                // bytewise equality vector
                const __m128i vec_equality_bytewise = _mm_cmpeq_epi8(vec_miscompares_bitwise, vec_zero);

                int equality_bytewise = _mm_movemask_epi8(vec_equality_bytewise);

                if(equality_bytewise != 0xFFFF) {
                    return false;
                }

                offset += 16;
            }
        }
        #endif

        while(offset < size_bytes) {
            byte difference = ptr_0[offset] ^ ptr_1[offset];
            byte miscompares = ptr_mask[offset] & difference;
            if(miscompares != 0) {
                return false;
            }
            offset++;
        }

        return true;
    }
};

// VectorPatternDescriptors are meant to be instantiated at runtime
class VectorPatternDescriptor : public BPatternDescriptor {
public:
    VectorPatternDescriptor(const std::string_view sv) {
        size_t size = make_pattern_calc_size(sv);
        this->pattern_impl.resize(size);
        this->pattern_mask_impl.resize(size);

        make_pattern_compile(sv, size, this->pattern_impl, this->pattern_mask_impl);
    }

    std::span<const byte> pattern() const override {
        return std::span<const byte>(this->pattern_impl);
    }

    std::span<const byte> pattern_mask() const override {
        return std::span<const byte>(this->pattern_mask_impl);
    }

private:
    std::vector<byte> pattern_impl;
    std::vector<byte> pattern_mask_impl;
};

struct polymeric_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        auto sig = VectorPatternDescriptor(MakeCompactHexPattern(pattern, mask));

        std::vector<const byte*> matches;
        sig.find_callback(data, length, [&](const byte *result) -> bool {
            matches.push_back(result);
            return true;
        });
        return matches;
    }

    virtual const char* GetName() const override
    {
        #ifdef _PLATFORM_NOT_X86
        return "polymeric (Scalar)";
        #else
        return "polymeric (SSE2)";
        #endif
    }
};

REGISTER_PATTERN(polymeric_scanner);

#undef USE_SSE2_INTRINSICS_STAGE1
#undef USE_SSE2_INTRINSICS_STAGE2
#undef _PLATFORM_NOT_X86
#undef MUST_INLINE
