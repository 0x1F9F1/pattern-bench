// https://github.com/citizenfx/fivem/blob/master/code/client/shared/Hooking.Patterns.cpp

#include "pattern_entry.h"

#include <cassert>
#include <vector>

#include <algorithm>

struct cfx_pattern_scanner
    : pattern_scanner
{
    const byte* CurrentPattern = nullptr;
    const char* CurrentMask = nullptr;
    size_t MaskSize = 0;
    ptrdiff_t Last[256];

    virtual const char* GetName() const
    {
        return "CFX";
    }

    virtual void Init(const byte* pattern, const char* mask)
    {
        CurrentPattern = pattern;
        CurrentMask = mask;

        MaskSize = strlen(mask);

        const char* findWild = strrchr(mask, '?');

        std::fill(std::begin(Last), std::end(Last), findWild ? (findWild - mask) : - 1);

        for (ptrdiff_t i = 0; i < static_cast<ptrdiff_t>(MaskSize); ++i)
        {
            if (Last[pattern[i]] < i)
            {
                Last[pattern[i]] = i;
            }
        }
    }

    virtual std::vector<const byte*> Scan(const byte* data, size_t length) const
    {
        const byte* const pattern = CurrentPattern;
        const char* const mask = CurrentMask;
        const ptrdiff_t* const last = Last;
        const size_t mask_size = MaskSize;

        std::vector<const byte*> results;

        for (const byte* i = data, *end = data + length - mask_size; i <= end;)
        {
            ptrdiff_t j = mask_size - 1;

            while ((j >= 0) && (mask[j] == '?' || pattern[j] == i[j])) j--;

            if (j < 0)
            {
                results.emplace_back(i);

                i++;
            }
            else
            {
                i += std::max((ptrdiff_t)1, j - last[i[j]]);
            }
        }

        return results;
    }
};

REGISTER_PATTERN(cfx_pattern_scanner);
