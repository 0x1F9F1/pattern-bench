// https://github.com/x64dbg/x64dbg/pull/3793

#include "pattern_entry.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace x64dbg_bmh_impl
{
struct PatternNibble
{
    unsigned char data = 0;
    bool wildcard = false;
};

struct PatternByte
{
    PatternNibble nibble[2];
};

static inline bool patternmatchbyte(unsigned char byte, const PatternByte& pbyte)
{
    int matched = 0;

    unsigned char n1 = (byte >> 4) & 0xF;
    if (pbyte.nibble[0].wildcard)
        matched++;
    else if (pbyte.nibble[0].data == n1)
        matched++;

    unsigned char n2 = byte & 0xF;
    if (pbyte.nibble[1].wildcard)
        matched++;
    else if (pbyte.nibble[1].data == n2)
        matched++;

    return (matched == 2);
}

static bool isByteFullySpecified(const PatternByte& pbyte)
{
    return !pbyte.nibble[0].wildcard && !pbyte.nibble[1].wildcard;
}

static unsigned char getByteValue(const PatternByte& pbyte)
{
    return (pbyte.nibble[0].data << 4) | pbyte.nibble[1].data;
}

size_t patternfind(const unsigned char* data, size_t datasize, const std::vector<PatternByte>& pattern)
{
    size_t searchpatternsize = pattern.size();

    if (searchpatternsize == 0 || datasize < searchpatternsize)
        return static_cast<size_t>(-1);

    const size_t last = searchpatternsize - 1;

    size_t idx = last;
    while (idx > 0 && isByteFullySpecified(pattern[idx]))
        --idx;

    size_t diff = last - idx;
    if (diff == 0)
        diff = 1;

    size_t skip[256];
    for (size_t i = 0; i < 256; ++i)
        skip[i] = diff;

    for (size_t i = last - diff; i < last; ++i)
    {
        if (isByteFullySpecified(pattern[i]))
            skip[getByteValue(pattern[i])] = last - i;
    }

    size_t pos = 0;
    const size_t maxPos = datasize - searchpatternsize;
    while (pos <= maxPos)
    {
        bool matched = true;
        for (size_t i = searchpatternsize; i > 0; --i)
        {
            const size_t check = i - 1;
            if (!patternmatchbyte(data[pos + check], pattern[check]))
            {
                matched = false;
                break;
            }
        }

        if (matched)
            return pos;

        pos += skip[data[pos + last]];
    }

    return static_cast<size_t>(-1);
}

static std::vector<PatternByte> to_pattern_bytes(const byte* pattern, const char* mask)
{
    const size_t length = std::strlen(mask);
    std::vector<PatternByte> out(length);

    for (size_t i = 0; i < length; ++i)
    {
        if (mask[i] == '?')
        {
            out[i].nibble[0].wildcard = true;
            out[i].nibble[1].wildcard = true;
        }
        else
        {
            out[i].nibble[0].wildcard = false;
            out[i].nibble[0].data = (pattern[i] >> 4) & 0xF;
            out[i].nibble[1].wildcard = false;
            out[i].nibble[1].data = pattern[i] & 0xF;
        }
    }

    return out;
}

static std::vector<const byte*> find_all(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;
    const std::vector<PatternByte> parsed = to_pattern_bytes(pattern, mask);
    if (parsed.empty())
        return results;

    size_t base = 0;
    while (base < length)
    {
        const size_t hit = patternfind(data + base, length - base, parsed);
        if (hit == static_cast<size_t>(-1))
            break;

        const size_t absolute = base + hit;
        results.push_back(data + absolute);
        base = absolute + 1;
    }

    return results;
}
} // namespace x64dbg_bmh_impl

struct x64dbg_bmh_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return x64dbg_bmh_impl::find_all(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "x64dbg-bmh";
    }
};

REGISTER_PATTERN(x64dbg_bmh_pattern_scanner);
