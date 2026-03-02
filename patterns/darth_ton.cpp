// https://github.com/learn-more/findpattern-bench/blob/master/patterns/DarthTon.h

#include "pattern_entry.h"

#include <immintrin.h>
#include <algorithm>
#include <cstring>

#define min(a, b) (((a) < (b)) ? (a) : (b))

static std::vector<const byte*> find_masked(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    const size_t pattern_length = std::strlen(mask);
    if (pattern_length == 0 || pattern_length > length)
        return {};

    ptrdiff_t last[UCHAR_MAX + 1];
    const char* wild = std::strrchr(mask, '?');
    std::fill(std::begin(last), std::end(last), wild ? (wild - mask) : -1);

    for (ptrdiff_t i = 0; i < static_cast<ptrdiff_t>(pattern_length); ++i)
    {
        if (mask[i] == 'x' && last[pattern[i]] < i)
            last[pattern[i]] = i;
    }

    std::vector<const byte*> results;
    for (const byte *cursor = data, *end = data + (length - pattern_length); cursor <= end;)
    {
        ptrdiff_t i = static_cast<ptrdiff_t>(pattern_length) - 1;
        while (i >= 0 && (mask[i] == '?' || pattern[i] == cursor[i]))
            --i;

        if (i < 0)
        {
            results.push_back(cursor);
            ++cursor;
        }
        else
        {
            cursor += std::max<ptrdiff_t>(1, i - last[cursor[i]]);
        }
    }

    return results;
}

// Boyer-Moore-Horspool with wildcards implementation
void FillShiftTable(const uint8_t* pPattern, size_t patternSize, const char* pMask, size_t* bad_char_skip)
{
    size_t idx = 0;
    size_t last = patternSize - 1;

    // Get last wildcard position
    for (idx = last; idx > 0 && pMask[idx] != '?'; --idx)
        ;
    size_t diff = last - idx;
    if (diff == 0)
        diff = 1;

    // Prepare shift table
    for (idx = 0; idx <= UCHAR_MAX; ++idx)
        bad_char_skip[idx] = diff;
    for (idx = last - diff; idx < last; ++idx)
        bad_char_skip[pPattern[idx]] = last - idx;
}

std::vector<const byte*> Search(const uint8_t* pScanPos, size_t scanSize, const uint8_t* pPattern, const char* pMask)
{
    size_t patternSize = strlen(pMask);

    size_t bad_char_skip[UCHAR_MAX + 1];
    const uint8_t* scanEnd = pScanPos + scanSize - patternSize;
    intptr_t last = static_cast<intptr_t>(patternSize) - 1;

    FillShiftTable(pPattern, patternSize, pMask, bad_char_skip);

    std::vector<const byte*> results;

    // Search
    for (; pScanPos <= scanEnd; pScanPos += bad_char_skip[pScanPos[last]])
    {
        for (intptr_t idx = last; idx >= 0; --idx)
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
    __m128i needle; // C2797: list initialization inside member initializer list or non-static data member initializer
                    // is not implemented

    PartData()
    {
        memset(&needle, 0, sizeof(needle));
    }
};

std::vector<const byte*> Search2(const uint8_t* data, const uint32_t size, const uint8_t* pattern, const char* mask)
{
    return find_masked(data, size, pattern, mask);
}

struct darth_ton_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return Search(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "DarthTon";
    }
};

REGISTER_PATTERN(darth_ton_pattern_scanner);

struct darth_ton2_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return Search2(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "DarthTon v2";
    }
};

REGISTER_PATTERN(darth_ton2_pattern_scanner);
