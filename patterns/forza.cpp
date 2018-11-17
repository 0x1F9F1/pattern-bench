// https://github.com/learn-more/findpattern-bench/blob/master/patterns/Forza.h

#include "pattern_entry.h"

#include <immintrin.h>

struct PatternData
{
    uint32_t    Count;
    uint32_t    Size;
    uint32_t    Length[16];
    uint32_t    Skip[16];
    __m128i     Value[16];
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

        Out->Length[c]  = sl;
        Out->Skip[c]    = sl + ml;
        Out->Value[c]   = _mm_loadu_si128((const __m128i*)((uint8_t*)Signature + i));

        Out->Count++;

        i += sl - 1;
    }

    Out->Size = l;
}

__forceinline bool Matches(const uint8_t* Data, PatternData* Patterns)
{
    auto k = Data + Patterns->Skip[0];

    for (auto i = 1; i < Patterns->Count; i++)
    {
        auto l = Patterns->Length[i];

        if (_mm_cmpestri(Patterns->Value[i], l, _mm_loadu_si128((const __m128i*)k), l, _SIDD_CMP_EQUAL_EACH | _SIDD_MASKED_NEGATIVE_POLARITY) != l)
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

    //C3010: 'break' : jump out of OpenMP structured block not allowed
    for (intptr_t i = Length - 32; i >= 0; i -= 32)
    {
        auto p = Data + i;
        auto b = _mm256_loadu_si256((const __m256i*)p);

        if (_mm256_test_all_zeros(b, b) == 1)
            continue;

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
                if (Mask[j] == 'x' && (uint8_t)Signature[j] != p[j])
                    break;

                if (j + 1 == d.Size)
                    results.push_back(p);
            }

            continue;
        }

        if (Matches(p, &d))
            results.push_back(p);

        p++;
        f = _mm_cmpestri(d.Value[0], d.Length[0], _mm_loadu_si128((const __m128i*)p), 16, _SIDD_CMP_EQUAL_ORDERED);

        if (f < 16)
            goto PossibleMatch;
    }

    return results;
}

void FindLargestArray(const char* Signature, const char* Mask, int Out[2])
{
    uint32_t t1 = 0;
    uint32_t t2 = strlen(Signature);
    uint32_t len    = strlen(Mask);

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
    int d[2] = { 0 };
    FindLargestArray(Signature, Mask, d);

    const uint8_t len   = static_cast<uint8_t>(strlen(Mask));
    const uint8_t mbeg  = static_cast<uint8_t>(d[0]);
    const uint8_t mlen  = static_cast<uint8_t>(d[1]);
    const uint8_t mfirst    = static_cast<uint8_t>(Signature[mbeg]);

    uint8_t wildcard[UCHAR_MAX + 1] = { 0 };

    for (auto i = mbeg; i < mbeg + mlen; i++)
        wildcard[(uint8_t)Signature[i]] = 1;

    std::vector<const byte*> results;

    for (int i = Length - len; i >= 0; i--)
    {
        auto c  = Data[i];
        auto w  = wildcard[c];
        auto k  = 0;

        while (w == 0 && i > mlen)
        {
            i -= mlen;
            w = wildcard[Data[i]];
            k = 1;
        }

        if (k == 1)
        {
            i++;
            continue;
        }

        if (c != mfirst)
            continue;

        if (i - mbeg < 0 || i - mbeg + len > Length)
            break;

        for (auto j = 0; j < len - 1; j++)
        {
            if (j == mbeg || Mask[j] != 'x')
                continue;

            if (Data[i - mbeg + j] != (uint8_t)Signature[j])
                break;

            if (j + 1 == len - 1)
                results.push_back((uint8_t*)(Data + i - mbeg));
        }
    }

    return results;
}

struct forza_pattern_scanner
    : pattern_scanner
{
    virtual std::vector<const byte*> Scan(const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return Find(data, length, (const char*) pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "Forza (Boyer-Moore Variant)";
    }
};

REGISTER_PATTERN(forza_pattern_scanner);

struct forza_simd_pattern_scanner
    : pattern_scanner
{
    virtual std::vector<const byte*> Scan(const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return FindEx(data, length, (const char*) pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "Forza (SIMD)";
    }
};

REGISTER_PATTERN(forza_simd_pattern_scanner);
