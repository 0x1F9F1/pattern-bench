// https://github.com/citizenfx/fivem/blob/master/code/client/shared/Hooking.Patterns.cpp

#include "pattern_entry.h"

#include <cassert>
#include <vector>

#include <algorithm>

struct cfx_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        size_t mask_size = strlen(mask);
        ptrdiff_t last[256];

        const char* findWild = strrchr(mask, '?');

        std::fill(std::begin(last), std::end(last), findWild ? (findWild - mask) : -1);

        for (ptrdiff_t i = 0; i < static_cast<ptrdiff_t>(mask_size); ++i)
        {
            if (last[pattern[i]] < i)
            {
                last[pattern[i]] = i;
            }
        }

        std::vector<const byte*> results;

        for (const byte *i = data, *end = data + length - mask_size; i <= end;)
        {
            ptrdiff_t j = mask_size - 1;

            while ((j >= 0) && (mask[j] == '?' || pattern[j] == i[j]))
                j--;

            if (j < 0)
            {
                results.emplace_back(i);

                i++;
            }
            else
            {
                i += std::max((ptrdiff_t) 1, j - last[i[j]]);
            }
        }

        return results;
    }

    virtual const char* GetName() const override
    {
        return "CFX";
    }
};

REGISTER_PATTERN(cfx_pattern_scanner);
