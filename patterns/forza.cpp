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
    uint32_t FirstOffset;
    uint32_t Offset[16];
    uint32_t Length[16];
    uint32_t Skip[16];
    __m128i Value[16];
};

static __m128i load_partial_128(const uint8_t* src, size_t length)
{
    alignas(16) uint8_t buffer[16] = {};
    const size_t copy_length = std::min<size_t>(16, length);
    if (copy_length != 0)
        std::memcpy(buffer, src, copy_length);
    return _mm_loadu_si128(reinterpret_cast<const __m128i*>(buffer));
}

void GeneratePattern(const char* Signature, const char* Mask, PatternData* Out)
{
    auto l = strlen(Mask);

    std::memset(Out, 0, sizeof(*Out));
    Out->Count = 0;
    Out->FirstOffset = 0;

    for (auto i = 0u; i < l && Out->Count < 16; i++)
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

        const auto c = Out->Count;

        Out->Offset[c] = i;
        Out->Length[c] = sl;
        Out->Skip[c] = sl + ml;
        Out->Value[c] = load_partial_128(reinterpret_cast<const uint8_t*>(Signature + i), static_cast<size_t>(sl));

        if (c == 0)
            Out->FirstOffset = i;

        Out->Count++;

        i += sl - 1;
    }

    Out->Size = l;
}

MEM_STRONG_INLINE bool Matches(const uint8_t* Data, PatternData* Patterns)
{
    for (auto i = 0u; i < Patterns->Count; i++)
    {
        auto l = Patterns->Length[i];
        const uint8_t* k = Data + Patterns->Offset[i];
        const __m128i value = load_partial_128(k, static_cast<size_t>(l));

        if (_mm_cmpestri(Patterns->Value[i], static_cast<int>(l), value, static_cast<int>(l), _SIDD_CMP_EQUAL_ORDERED) != 0)
            return false;
    }

    return true;
}

MEM_STRONG_INLINE bool MatchesFast(const uint8_t* Data, PatternData* Patterns)
{
    for (auto i = 0u; i < Patterns->Count; i++)
    {
        const int l = static_cast<int>(Patterns->Length[i]);
        const uint8_t* k = Data + Patterns->Offset[i];
        const __m128i value = _mm_loadu_si128(reinterpret_cast<const __m128i*>(k));

        if (_mm_cmpestri(Patterns->Value[i], l, value, l, _SIDD_CMP_EQUAL_ORDERED) != 0)
            return false;
    }

    return true;
}

MEM_STRONG_INLINE bool MatchesTail(const uint8_t* Data, const uint8_t* DataEnd, PatternData* Patterns)
{
    for (auto i = 0u; i < Patterns->Count; i++)
    {
        const int l = static_cast<int>(Patterns->Length[i]);
        const uint8_t* k = Data + Patterns->Offset[i];
        const size_t remaining = static_cast<size_t>(DataEnd - k);
        const __m128i value = (remaining >= 16)
            ? _mm_loadu_si128(reinterpret_cast<const __m128i*>(k))
            : load_partial_128(k, remaining);

        if (_mm_cmpestri(Patterns->Value[i], l, value, l, _SIDD_CMP_EQUAL_ORDERED) != 0)
            return false;
    }

    return true;
}

std::vector<const byte*> FindEx(const uint8_t* Data, const uint32_t Length, const char* Signature, const char* Mask)
{
    PatternData d;
    GeneratePattern(Signature, Mask, &d);

    if (d.Size == 0 || d.Size > Length)
        return {};

    std::vector<const byte*> results;

    if (d.Count == 0)
    {
        for (uint32_t i = 0; i <= Length - d.Size; ++i)
            results.push_back(Data + i);
        return results;
    }

    const int anchor_length = static_cast<int>(d.Length[0]);
    const int no_match_advance = std::max(1, 16 - anchor_length + 1);
    const byte* const end = Data + (Length - d.Size);
    const byte* const data_end = Data + Length;
    const byte* const anchor_end = end + d.FirstOffset;

    const size_t max_full_read = static_cast<size_t>(d.Offset[d.Count - 1]) + 16u;
    const bool has_fast_match_path = Length >= max_full_read;
    const byte* fast_match_end = has_fast_match_path ? (Data + (Length - max_full_read)) : Data;

    const byte* search = Data + d.FirstOffset;
    while (search <= anchor_end)
    {
        const int remaining_anchor_starts = static_cast<int>(anchor_end - search + 1);
        const int hay_length = std::min(16, remaining_anchor_starts + anchor_length - 1);
        const size_t remaining_data = static_cast<size_t>(data_end - search);
        const __m128i hay = (hay_length == 16 && remaining_data >= 16)
            ? _mm_loadu_si128(reinterpret_cast<const __m128i*>(search))
            : load_partial_128(search, remaining_data);
        const int pos = _mm_cmpestri(d.Value[0], anchor_length, hay, hay_length, _SIDD_CMP_EQUAL_ORDERED);

        if (pos < hay_length)
        {
            const byte* anchor_hit = search + pos;
            const byte* candidate = anchor_hit - d.FirstOffset;

            if (candidate >= Data && candidate <= end)
            {
                const bool matched =
                    (has_fast_match_path && candidate <= fast_match_end)
                    ? MatchesFast(candidate, &d)
                    : MatchesTail(candidate, data_end, &d);
                if (matched)
                    results.push_back(candidate);
            }

            search = anchor_hit + 1;
        }
        else
        {
            if (hay_length < 16)
                break;
            search += no_match_advance;
        }
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

REGISTER_PATTERN(forza_simd_pattern_scanner);
