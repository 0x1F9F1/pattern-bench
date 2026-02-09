// Based on LightningScanner backend logic.
// https://github.com/localcc/LightningScanner/

#include "pattern_entry.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace lightning_scanner_impl
{
struct Pattern
{
    std::vector<uint8_t> data;
    std::vector<uint8_t> mask;
    size_t unpaddedSize = 0;
};

static Pattern ParsePattern(const byte* pattern, const char* mask)
{
    Pattern out;
    const size_t len = std::strlen(mask);

    out.data.resize(len);
    out.mask.resize(len);
    out.unpaddedSize = len;

    for (size_t i = 0; i < len; ++i)
    {
        if (mask[i] == '?')
        {
            out.data[i] = 0x00;
            out.mask[i] = 0x00;
        }
        else
        {
            out.data[i] = pattern[i];
            out.mask[i] = 0xFF;
        }
    }

    return out;
}

static const byte* FindStdFind(const Pattern& data, const byte* startAddr, size_t size)
{
    if (data.unpaddedSize == 0 || size < data.unpaddedSize)
        return nullptr;

    const byte* start = startAddr;
    const byte* end = startAddr + size - data.unpaddedSize + 1;

    if (data.mask[0] == 0x00)
    {
        while (start != end)
        {
            bool found = true;

            for (size_t i = 0; i < data.unpaddedSize; ++i)
            {
                uint8_t searchElement = data.data[i] & data.mask[i];
                uint8_t foundElement = start[i] & data.mask[i];
                if (searchElement != foundElement)
                {
                    found = false;
                    break;
                }
            }

            if (found)
                return start;

            ++start;
        }

        return nullptr;
    }

    const byte element = data.data[0];
    while ((start = std::find(start, end, element)) != end)
    {
        bool found = true;

        for (size_t i = 0; i < data.unpaddedSize; ++i)
        {
            uint8_t searchElement = data.data[i] & data.mask[i];
            uint8_t foundElement = start[i] & data.mask[i];
            if (searchElement != foundElement)
            {
                found = false;
                break;
            }
        }

        if (found)
            return start;

        ++start;
    }

    return nullptr;
}

static std::vector<const byte*> FindAll(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;
    const Pattern parsed = ParsePattern(pattern, mask);

    if (parsed.unpaddedSize == 0 || length < parsed.unpaddedSize)
        return results;

    size_t base = 0;
    while (base < length)
    {
        const byte* found = FindStdFind(parsed, data + base, length - base);
        if (!found)
            break;

        results.push_back(found);
        base = static_cast<size_t>((found - data) + 1);
    }

    return results;
}
} // namespace lightning_scanner_impl

struct lightning_scanner_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return lightning_scanner_impl::FindAll(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "LightningScanner";
    }
};

REGISTER_PATTERN(lightning_scanner_pattern_scanner);
