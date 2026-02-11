// Based on Can's cansearch.cpp algorithm (sentinel-first + masked verify).

#include "pattern_entry.h"

#include <cstdint>
#include <cstring>
#include <immintrin.h>
#include <vector>

namespace can_impl
{
struct exact_run
{
    size_t offset;
    size_t length;
};

static inline int first_set_bit(uint32_t v)
{
#if defined(_MSC_VER)
    unsigned long idx = 0;
    _BitScanForward(&idx, v);
    return static_cast<int>(idx);
#else
    return __builtin_ctz(v);
#endif
}

static inline bool match_exact_runs(const byte* candidate, const byte* pattern, const std::vector<exact_run>& runs)
{
    for (size_t i = 0; i < runs.size(); ++i)
    {
        const exact_run& run = runs[i];
        if (std::memcmp(candidate + run.offset, pattern + run.offset, run.length) != 0)
            return false;
    }
    return true;
}

static const byte* find_next_anchor_u8(const byte* cursor, const byte* end, byte value)
{
    const __m256i needle = _mm256_set1_epi8(static_cast<char>(value));
    while (cursor + 32 <= end)
    {
        const __m256i hay = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(cursor));
        const uint32_t bits = static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(hay, needle)));
        if (bits != 0)
            return cursor + first_set_bit(bits);
        cursor += 32;
    }

    while (cursor < end)
    {
        if (*cursor == value)
            return cursor;
        ++cursor;
    }

    return nullptr;
}

static const byte* find_next_anchor_u16(const byte* cursor, const byte* end, const byte* value)
{
    const __m256i n0 = _mm256_set1_epi8(static_cast<char>(value[0]));
    const __m256i n1 = _mm256_set1_epi8(static_cast<char>(value[1]));

    while (cursor + 32 <= end)
    {
        const __m256i d0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(cursor));
        const __m256i d1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(cursor + 1));
        const uint32_t b0 = static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(d0, n0)));
        const uint32_t b1 = static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(d1, n1)));
        const uint32_t bits = b0 & b1;
        if (bits != 0)
            return cursor + first_set_bit(bits);
        cursor += 32;
    }

    while (cursor < end)
    {
        if (cursor[0] == value[0] && cursor[1] == value[1])
            return cursor;
        ++cursor;
    }

    return nullptr;
}

static const byte* find_next_anchor_u32(const byte* cursor, const byte* end, const byte* value)
{
    const __m256i n0 = _mm256_set1_epi8(static_cast<char>(value[0]));
    const __m256i n1 = _mm256_set1_epi8(static_cast<char>(value[1]));
    const __m256i n2 = _mm256_set1_epi8(static_cast<char>(value[2]));
    const __m256i n3 = _mm256_set1_epi8(static_cast<char>(value[3]));

    while (cursor + 32 <= end)
    {
        const __m256i d0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(cursor));
        const __m256i d1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(cursor + 1));
        const __m256i d2 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(cursor + 2));
        const __m256i d3 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(cursor + 3));

        const uint32_t b0 = static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(d0, n0)));
        const uint32_t b1 = static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(d1, n1)));
        const uint32_t b2 = static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(d2, n2)));
        const uint32_t b3 = static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(d3, n3)));
        const uint32_t bits = b0 & b1 & b2 & b3;
        if (bits != 0)
            return cursor + first_set_bit(bits);

        cursor += 32;
    }

    while (cursor < end)
    {
        if (cursor[0] == value[0] && cursor[1] == value[1] && cursor[2] == value[2] && cursor[3] == value[3])
            return cursor;
        ++cursor;
    }

    return nullptr;
}

static inline const byte* find_next_anchor(const byte* cursor, const byte* end, const byte* value, size_t width)
{
    if (width == 4)
        return find_next_anchor_u32(cursor, end, value);
    if (width == 2)
        return find_next_anchor_u16(cursor, end, value);
    return find_next_anchor_u8(cursor, end, value[0]);
}

static std::vector<const byte*> FindAll(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;

    const size_t pattern_length = std::strlen(mask);
    if (pattern_length == 0 || pattern_length > length)
        return results;

    std::vector<exact_run> runs;
    runs.reserve(8);

    size_t first_exact = pattern_length;
    for (size_t i = 0; i < pattern_length;)
    {
        if (mask[i] != 'x')
        {
            ++i;
            continue;
        }

        if (first_exact == pattern_length)
            first_exact = i;

        const size_t begin = i;
        while (i < pattern_length && mask[i] == 'x')
            ++i;

        exact_run run {};
        run.offset = begin;
        run.length = i - begin;
        runs.push_back(run);
    }

    if (runs.empty())
    {
        const size_t max_start = length - pattern_length;
        results.reserve(max_start + 1);
        for (size_t i = 0; i <= max_start; ++i)
            results.push_back(data + i);
        return results;
    }

    size_t first_run_length = 0;
    for (size_t i = 0; i < runs.size(); ++i)
    {
        if (runs[i].offset == first_exact)
        {
            first_run_length = runs[i].length;
            break;
        }
    }

    size_t sentinel_width = 1;
    if (length >= (1024u * 1024u))
    {
        if (first_run_length >= 4)
            sentinel_width = 4;
        else if (first_run_length >= 2)
            sentinel_width = 2;
    }

    const size_t max_start = length - pattern_length;
    const byte* cursor = data + first_exact;
    const byte* end = data + max_start + first_exact + 1;
    const byte* sentinel = pattern + first_exact;

    while (cursor < end)
    {
        const byte* hit = find_next_anchor(cursor, end, sentinel, sentinel_width);
        if (!hit)
            break;

        const byte* candidate = hit - first_exact;
        if (match_exact_runs(candidate, pattern, runs))
            results.push_back(candidate);

        cursor = hit + 1;
    }

    return results;
}
} // namespace can_impl

struct can_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return can_impl::FindAll(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "Can";
    }
};

REGISTER_PATTERN(can_pattern_scanner);
