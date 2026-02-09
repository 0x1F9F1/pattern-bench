// https://github.com/learn-more/findpattern-bench/blob/master/patterns/mrexodia_horspool.h

#include "pattern_entry.h"

#include <algorithm>
#include <cstring>

// Wildcard-aware Boyer-Moore-Horspool variant that remains exhaustive.
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

struct mrexodia_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return find_masked(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "mrexodia (horspool)";
    }
};

REGISTER_PATTERN(mrexodia_pattern_scanner);
