// https://github.com/learn-more/findpattern-bench/blob/master/patterns/Forza.h

#include "pattern_entry.h"

#include <immintrin.h>
#include <algorithm>
#include <cstring>

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

struct PatternData
{
    uint32_t Count;
    uint32_t Size;
    uint32_t Length[16];
    uint32_t Skip[16];
    __m128i Value[16];
};

void GeneratePattern(const char* Signature, const char* Mask, PatternData* Out)
{
    auto l = strlen(Mask);

    Out->Count = 0;

    for (auto i = 0; i < l; i++)
    {
        if (Mask[i] == '?')
            continue;

        auto ml = 0, sl = 0;

        for (auto j = i; j < l; j++)
        {
            if (Mask[j] == '?' || sl >= 16)
                break;
            sl++;
        }

        for (auto j = i + sl; j < l; j++)
        {
            if (Mask[j] != '?')
                break;
            ml++;
        }

        auto c = Out->Count;

        Out->Length[c] = sl;
        Out->Skip[c] = sl + ml;
        Out->Value[c] = _mm_loadu_si128((const __m128i*) ((uint8_t*) Signature + i));

        Out->Count++;

        i += sl - 1;
    }

    Out->Size = l;
}

MEM_STRONG_INLINE bool Matches(const uint8_t* Data, PatternData* Patterns)
{
    auto k = Data + Patterns->Skip[0];

    for (auto i = 1; i < Patterns->Count; i++)
    {
        auto l = Patterns->Length[i];

        if (_mm_cmpestri(Patterns->Value[i], l, _mm_loadu_si128((const __m128i*) k), l,
                _SIDD_CMP_EQUAL_EACH | _SIDD_MASKED_NEGATIVE_POLARITY) != l)
            break;

        if (i + 1 == Patterns->Count)
            return true;

        k += Patterns->Skip[i];
    }

    return false;
}

std::vector<const byte*> FindEx(const uint8_t* Data, const uint32_t Length, const char* Signature, const char* Mask)
{
    PatternData d;
    GeneratePattern(Signature, Mask, &d);

    auto out = static_cast<uint8_t*>(nullptr);
    auto end = Data + Length - d.Size;

    std::vector<const byte*> results;

    // C3010: 'break' : jump out of OpenMP structured block not allowed
    for (intptr_t i = Length - 32; i >= 0; i -= 32)
    {
        auto p = Data + i;
        auto b = _mm256_loadu_si256((const __m256i*) p);

        // if (_mm256_test_all_zeros(b, b) == 1)
        //     continue;

        auto f = _mm_cmpestri(d.Value[0], d.Length[0], _mm256_extractf128_si256(b, 0), 16, _SIDD_CMP_EQUAL_ORDERED);

        if (f == 16)
        {
            f += _mm_cmpestri(d.Value[0], d.Length[0], _mm256_extractf128_si256(b, 1), 16, _SIDD_CMP_EQUAL_ORDERED);

            if (f == 32)
                continue;
        }

    PossibleMatch:
        p += f;

        if (p + d.Size > end)
        {
            for (auto j = 0; j < d.Size && j + i + f < Length; j++)
            {
                if (Mask[j] == 'x' && (uint8_t) Signature[j] != p[j])
                    break;

                if (j + 1 == d.Size)
                    results.push_back(p);
            }

            continue;
        }

        if (Matches(p, &d))
            results.push_back(p);

        p++;
        f = _mm_cmpestri(d.Value[0], d.Length[0], _mm_loadu_si128((const __m128i*) p), 16, _SIDD_CMP_EQUAL_ORDERED);

        if (f < 16)
            goto PossibleMatch;
    }

    return results;
}

void FindLargestArray(const char* Signature, const char* Mask, int Out[2])
{
    uint32_t t1 = 0;
    uint32_t t2 = strlen(Signature);
    uint32_t len = strlen(Mask);

    for (auto j = t2; j < len; j++)
    {
        if (Mask[j] != 'x')
            continue;

        auto find = strrchr(&Mask[j], '?');

        auto count = find ? (find - &Mask[j]) : (len - j);

        if (count > t2)
        {
            t1 = j;
            t2 = count;
        }

        j += (count - 1);
    }

    Out[0] = t1;
    Out[1] = t2;
}

std::vector<const byte*> Find(const byte* Data, const uint32_t Length, const char* Signature, const char* Mask)
{
    return find_masked(Data, Length, reinterpret_cast<const byte*>(Signature), Mask);
}

struct forza_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return Find(data, length, (const char*) pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "Forza (Boyer-Moore Variant)";
    }
};

REGISTER_PATTERN(forza_pattern_scanner);

struct forza_simd_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return FindEx(data, length, (const char*) pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "Forza (SIMD)";
    }
};

// REGISTER_PATTERN(forza_simd_pattern_scanner);
