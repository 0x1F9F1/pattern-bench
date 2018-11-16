// https://github.com/citizenfx/fivem/blob/master/code/client/shared/Hooking.Patterns.cpp

#include "pattern_entry.h"

#include <cassert>
#include <vector>

#include <algorithm>

static std::vector<const byte*> EnsureMatches(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;

    size_t maskSize = strlen(mask);

    const char* findWild = strrchr(mask, '?');

    ptrdiff_t Last[256];

    std::fill(std::begin(Last), std::end(Last), findWild ? (findWild - mask) : - 1);

    for (ptrdiff_t i = 0; i < static_cast<ptrdiff_t>(maskSize); ++i)
    {
        if (Last[pattern[i]] < i)
        {
            Last[pattern[i]] = i;
        }
    }

    for (const byte* i = data, *end = data + length - maskSize; i <= end;)
    {
        const byte* ptr = i;
        ptrdiff_t j = maskSize - 1;

        while ((j >= 0) && (mask[j] == '?' || pattern[j] == ptr[j])) j--;

        if (j < 0)
        {
            results.emplace_back(ptr);

            i++;
        }
        else i += std::max((ptrdiff_t)1, j - Last[ptr[j]]);
    }

    return results;
}

struct cfx_pattern_scanner
    : pattern_scanner
{
    const byte* CurrentPattern = nullptr;
    const char* CurrentMask = nullptr;

    virtual const char* GetName() const
    {
        return "CFX";
    }

    virtual void Init(const byte* pattern, const char* mask)
    {
        CurrentPattern = pattern;
        CurrentMask = mask;
    }

    virtual std::vector<const byte*> Scan(const byte* data, size_t length) const
    {
        return EnsureMatches(data, length, CurrentPattern, CurrentMask);
    }
};

REGISTER_PATTERN(cfx_pattern_scanner);
