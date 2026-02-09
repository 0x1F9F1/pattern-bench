// Based on PeribuntFindPattern Source.cpp.
// https://github.com/Peribunt/FindPattern

#include "pattern_entry.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <immintrin.h>
#include <vector>

#ifndef ALIGN_LOW
#define ALIGN_LOW(_, n) (uintptr_t)((uintptr_t)(_) & ~((n)-1))
#endif

namespace peribunt_impl
{
static inline uint32_t count_bits(uint32_t v)
{
    uint32_t c = 0;
    while (v)
    {
        c += (v & 1u);
        v >>= 1;
    }
    return c;
}

static inline uint32_t trailing_zeros(uint32_t v)
{
    unsigned long idx = 0;
    _BitScanForward(&idx, v);
    return static_cast<uint32_t>(idx);
}

static const uint8_t* FindPattern(const uint8_t* baseAddress, uint64_t searchLength, const uint8_t* bytePattern,
    uint32_t patternLength, const char* mask)
{
    if (!baseAddress || !bytePattern || !mask || patternLength == 0 || searchLength < patternLength)
        return nullptr;

    uint32_t anchorIndex = patternLength;
    for (uint32_t i = 0; i < patternLength; ++i)
    {
        if (mask[i] != '?')
        {
            anchorIndex = i;
            break;
        }
    }

    if (anchorIndex == patternLength)
        return baseAddress;

    if (patternLength > 64u)
    {
        const uint8_t* end = baseAddress + searchLength - patternLength + 1;
        for (const uint8_t* p = baseAddress; p < end; ++p)
        {
            bool ok = true;
            for (uint32_t i = 0; i < patternLength; ++i)
            {
                if (mask[i] != '?' && p[i] != bytePattern[i])
                {
                    ok = false;
                    break;
                }
            }
            if (ok)
                return p;
        }
        return nullptr;
    }

    const __m128i identifierValue = _mm_set1_epi8(static_cast<char>(bytePattern[anchorIndex]));

    const uint8_t* const searchStart = baseAddress;
    const uint8_t* const searchEnd = baseAddress + searchLength;

    const uint8_t* searchBase = reinterpret_cast<const uint8_t*>(ALIGN_LOW(baseAddress, 0x10));
    while (searchBase + 16 <= searchEnd)
    {
        const __m128i identifierMask = _mm_cmpeq_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(searchBase)), identifierValue);

        if (_mm_testz_si128(identifierMask, identifierMask) == 0)
        {
            uint32_t idMask32 = static_cast<uint32_t>(_mm_movemask_epi8(identifierMask));

        CURRENT_SIG_RETRY:
            const uint32_t trailingZeros = trailing_zeros(idMask32);
            const uint8_t* candidate = searchBase + trailingZeros;
            if (candidate < searchStart + anchorIndex)
                goto CHECK_NEXT_CANDIDATE;
            candidate -= anchorIndex;

            if (candidate >= searchStart && candidate + patternLength <= searchEnd)
            {
                bool matched = true;
                for (uint32_t i = 0; i < patternLength; ++i)
                {
                    if (mask[i] != '?' && candidate[i] != bytePattern[i])
                    {
                        matched = false;
                        break;
                    }
                }

                if (matched)
                    return candidate;
            }

        CHECK_NEXT_CANDIDATE:
            if (count_bits(idMask32) > 1)
            {
                idMask32 = idMask32 & ~(1u << trailingZeros);
                goto CURRENT_SIG_RETRY;
            }
        }

        searchBase += 0x10;
    }

    // Tail region fallback for candidates not covered in the 16-byte stepping loop.
    const uint8_t* tailBegin = (searchBase > searchStart) ? (searchBase - 15) : searchStart;
    if (tailBegin < searchStart)
        tailBegin = searchStart;
    const uint8_t* tailEnd = searchEnd;

    for (const uint8_t* p = tailBegin; p < tailEnd; ++p)
    {
        if (*p != bytePattern[anchorIndex])
            continue;
        if (p < searchStart + anchorIndex)
            continue;

        const uint8_t* candidate = p - anchorIndex;
        if (candidate < searchStart || candidate + patternLength > searchEnd)
            continue;

        bool ok = true;
        for (uint32_t i = 0; i < patternLength; ++i)
        {
            if (mask[i] != '?' && candidate[i] != bytePattern[i])
            {
                ok = false;
                break;
            }
        }
        if (ok)
            return candidate;
    }

    return nullptr;
}

static std::vector<const byte*> FindAll(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;
    const uint32_t patternLength = static_cast<uint32_t>(std::strlen(mask));

    size_t base = 0;
    while (base < length)
    {
        const uint8_t* found = FindPattern(reinterpret_cast<const uint8_t*>(data + base),
            static_cast<uint64_t>(length - base), reinterpret_cast<const uint8_t*>(pattern), patternLength, mask);
        if (!found)
            break;

        const byte* hit = reinterpret_cast<const byte*>(found);
        results.push_back(hit);
        base = static_cast<size_t>((hit - data) + 1);
    }

    return results;
}
} // namespace peribunt_impl

struct peribunt_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return peribunt_impl::FindAll(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "PeribuntFindPattern";
    }
};

REGISTER_PATTERN(peribunt_pattern_scanner);
