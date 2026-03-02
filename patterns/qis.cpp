// Source remote: https://github.com/qis/signature

#include "pattern_entry.h"

#include "signature.hpp"

struct qis_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        auto sig = qis::signature(MakeSpacedHexPattern(pattern, mask, false));

        std::vector<const byte*> results;

        for (size_t here = 0; here < length; ++here)
        {
            size_t found = qis::scan(&data[here], length - here, sig);

            if (found == SIZE_MAX)
                break;

            here += found;
            results.push_back(&data[here]);
        }

        return results;
    }

    virtual const char* GetName() const override
    {
        return "qis";
    }
};

REGISTER_PATTERN(qis_pattern_scanner);
