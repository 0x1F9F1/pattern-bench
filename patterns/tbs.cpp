// Based on TBS::Pattern::Parse + TBS::Light::Scan flow.
// https://github.com/pinwhell/TBS

#include "pattern_entry.h"

#include <cstring>
#include <vector>

namespace tbs_impl
{
struct ParseResult
{
    std::vector<byte> mPattern;
    std::vector<byte> mCompareMask;
    size_t mTrimmDisp = 0;
    bool mParseSuccess = false;

    inline operator bool() const
    {
        return mParseSuccess;
    }

    inline const byte* getTrimmedPattern() const
    {
        return mPattern.data() + mTrimmDisp;
    }

    inline const byte* getTrimmedCompareMask() const
    {
        return mCompareMask.data() + mTrimmDisp;
    }

    inline size_t getTrimmedSize() const
    {
        return mPattern.size() - mTrimmDisp;
    }

    inline bool TrimmedIsFirstTrullySolid() const
    {
        return getTrimmedCompareMask()[0] != 0;
    }
};

static bool Parse(const byte* pattern, const char* mask, ParseResult& result)
{
    result = ParseResult{};

    if (pattern == nullptr || mask == nullptr)
        return false;

    const size_t patternLen = std::strlen(mask);
    result.mPattern.resize(patternLen);
    result.mCompareMask.resize(patternLen);

    if (patternLen == 0)
        return result.mParseSuccess = true;

    std::memcpy(result.mPattern.data(), pattern, patternLen);
    std::memset(result.mCompareMask.data(), 0xFF, patternLen);

    bool firstSolidFound = false;
    for (size_t i = 0; i < patternLen; ++i)
    {
        if (mask[i] == '?')
        {
            result.mPattern[i] = 0x00;
            result.mCompareMask[i] = 0x00;
            continue;
        }

        if (!firstSolidFound)
        {
            result.mTrimmDisp = i;
            firstSolidFound = true;
        }
    }

    return result.mParseSuccess = true;
}

static const byte* SearchFirst(const byte* start, const byte* end, byte value)
{
    for (const byte* i = start; i != end; ++i)
    {
        if (*i == value)
            return i;
    }

    return nullptr;
}

static bool Compare(const byte* chunk1, const byte* chunk2, size_t len, const byte* compareMask)
{
    for (size_t i = 0; i < len; ++i)
    {
        const byte left = chunk1[i] & compareMask[i];
        const byte right = chunk2[i] & compareMask[i];
        if (left != right)
            return false;
    }

    return true;
}

static bool LightScan(const byte* start, const byte* end, std::vector<const byte*>& results, const ParseResult& parsed)
{
    results.clear();

    if (start >= end)
        return false;

    const size_t patternSize = parsed.getTrimmedSize();
    if (patternSize == 0)
        return false;

    const byte* found = start;
    bool firstStep = true;

    auto next = [&]() {
        if (!parsed.TrimmedIsFirstTrullySolid())
        {
            if (firstStep)
            {
                found = start;
                firstStep = false;
            }
            else
            {
                ++found;
            }
            return;
        }

        const byte* searchStart = firstStep ? start : (found + 1);
        firstStep = false;
        found = SearchFirst(searchStart, end, parsed.getTrimmedPattern()[0]);
    };

    for (next(); found && (found + patternSize - 1) < end; next())
    {
        if (!Compare(found, parsed.getTrimmedPattern(), patternSize, parsed.getTrimmedCompareMask()))
            continue;

        results.push_back(found - parsed.mTrimmDisp);
    }

    return !results.empty();
}

static std::vector<const byte*> FindAll(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    ParseResult parsed;
    std::vector<const byte*> results;

    if (!Parse(pattern, mask, parsed) || !parsed)
        return results;

    LightScan(data, data + length, results, parsed);
    return results;
}
} // namespace tbs_impl

struct tbs_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return tbs_impl::FindAll(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "TBS";
    }
};

REGISTER_PATTERN(tbs_pattern_scanner);
