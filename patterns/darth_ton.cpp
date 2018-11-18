// https://github.com/learn-more/findpattern-bench/blob/master/patterns/DarthTon.h

#include "pattern_entry.h"

#include <immintrin.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))

// Boyer-Moore-Horspool with wildcards implementation
void FillShiftTable( const uint8_t* pPattern, size_t patternSize, const char* pMask, size_t* bad_char_skip )
{
    size_t idx = 0;
    size_t last = patternSize - 1;

    // Get last wildcard position
    for (idx = last; idx > 0 && pMask[idx] != '?'; --idx);
    size_t diff = last - idx;
    if (diff == 0)
        diff = 1;

    // Prepare shift table
    for (idx = 0; idx <= UCHAR_MAX; ++idx)
        bad_char_skip[idx] = diff;
    for (idx = last - diff; idx < last; ++idx)
        bad_char_skip[pPattern[idx]] = last - idx;
}

std::vector<const byte*> Search( const uint8_t* pScanPos, size_t scanSize, const uint8_t* pPattern, const char* pMask)
{
    size_t patternSize = strlen(pMask);

    size_t bad_char_skip[UCHAR_MAX + 1];
    const uint8_t* scanEnd = pScanPos + scanSize - patternSize;
    intptr_t last = static_cast<intptr_t>(patternSize) - 1;

    FillShiftTable( pPattern, patternSize, pMask, bad_char_skip );

    std::vector<const byte*> results;

    // Search
    for (; pScanPos <= scanEnd; pScanPos += bad_char_skip[pScanPos[last]])
    {
        for (intptr_t idx = last; idx >= 0 ; --idx)
            if (pMask[idx] != '?' && pScanPos[idx] != pPattern[idx])
                goto skip;
            else if (idx == 0)
                results.push_back(pScanPos);
    skip:;
    }

    return results;
}

struct PartData
{
    int32_t mask = 0;
    __m128i needle; //C2797: list initialization inside member initializer list or non-static data member initializer is not implemented

    PartData()
    {
        memset(&needle, 0, sizeof(needle));
    }
};

std::vector<const byte*> Search2( const uint8_t* data, const uint32_t size, const uint8_t* pattern, const char* mask )
{
    auto len = strlen( mask );
    auto first = strchr( mask, '?' );
    size_t len2 = (first != nullptr) ? (first - mask) : len;
    auto firstlen = min( len2, 16 );
    intptr_t num_parts = (len < 16 || len % 16) ? (len / 16 + 1) : (len / 16);
    PartData parts[4];

    for (intptr_t i = 0; i < num_parts; ++i, len -= 16)
    {
        for (size_t j = 0; j < min( len, 16 ) - 1; ++j)
            if (mask[16 * i + j] == 'x')
                parts[i].mask |= (1 << j);

        parts[i].needle = _mm_loadu_si128( (const __m128i*)(pattern + i * 16) );
    }

    std::vector<const byte*> results;

    for (intptr_t i = 0; i < static_cast<intptr_t>(size) / 32 - 1; ++i)
    {
        // auto block = _mm256_loadu_si256( (const __m256i*)data + i );
        // if (_mm256_testz_si256( block, block ))
        //     continue;

        auto offset = _mm_cmpestri( parts->needle, firstlen, _mm_loadu_si128( (const __m128i*)(data + i * 32) ), 16, _SIDD_CMP_EQUAL_ORDERED );
        if (offset == 16)
        {
            offset += _mm_cmpestri( parts->needle, firstlen, _mm_loadu_si128( (const __m128i*)(data + i * 32 + 16) ), 16, _SIDD_CMP_EQUAL_ORDERED );
            if (offset == 32)
                continue;
        }

        for (intptr_t j = 0; j < num_parts; ++j)
        {
            auto hay = _mm_loadu_si128( (const __m128i*)(data + (2 * i + j) * 16 + offset) );
            auto bitmask = _mm_movemask_epi8( _mm_cmpeq_epi8( hay, parts[j].needle ) );
            if ((bitmask & parts[j].mask) != parts[j].mask)
                goto next;
        }

        results.push_back(data + 32 * i + offset);

    next:;
    }

    return results;
}

struct darth_ton_pattern_scanner
    : pattern_scanner
{
    virtual std::vector<const byte*> Scan(const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return Search( data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "DarthTon";
    }
};

REGISTER_PATTERN(darth_ton_pattern_scanner);

struct darth_ton2_pattern_scanner
    : pattern_scanner
{
    virtual std::vector<const byte*> Scan(const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return Search2( data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "DarthTon v2";
    }
};

// REGISTER_PATTERN(darth_ton2_pattern_scanner);
