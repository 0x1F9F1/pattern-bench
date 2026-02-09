// https://github.com/x64dbg/x64dbg/blob/c64f7784ab26b68482facf2a57e7689e4ab0defb/src/dbg/patternfind.cpp

#include "pattern_entry.h"

#include <cstring>
#include <vector>

namespace x64dbg_impl
{
struct PatternByte
{
    // Nibble-aware mask/value encoding:
    // ((byte ^ value) & mask) == 0 means match.
    // mask bit = 1 enforces compare, 0 ignores wildcard nibble.
    unsigned char value = 0;
    unsigned char mask = 0;
};

static inline bool patternmatchbyte(unsigned char byte, const PatternByte& pbyte)
{
    return (((byte ^ pbyte.value) & pbyte.mask) == 0);
}

size_t patternfind(const unsigned char* data, size_t datasize, const std::vector<PatternByte>& pattern)
{
    const size_t searchpatternsize = pattern.size();
    if (searchpatternsize == 0 || datasize < searchpatternsize)
        return static_cast<size_t>(-1);

    const PatternByte* pat = pattern.data();
    const size_t last_start = datasize - searchpatternsize;

    // Use the first fully-specified byte as a cheap prefilter.
    size_t anchor = 0;
    while (anchor < searchpatternsize && pat[anchor].mask != 0xFF)
        ++anchor;

    if (anchor == searchpatternsize)
    {
        // All bytes are wildcard: first valid hit is the start.
        return 0;
    }

    const unsigned char anchor_value = pat[anchor].value;
    size_t pos = 0;
    while (pos <= last_start)
    {
        while (pos <= last_start && data[pos + anchor] != anchor_value)
            ++pos;

        if (pos > last_start)
            break;

        size_t i = 0;
        for (; i < searchpatternsize; ++i)
        {
            if (!patternmatchbyte(data[pos + i], pat[i]))
                break;
        }

        if (i == searchpatternsize)
            return pos;

        ++pos;
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
            out[i].value = 0;
            out[i].mask = 0x00;
        }
        else
        {
            out[i].value = pattern[i];
            out[i].mask = 0xFF;
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
} // namespace x64dbg_impl

struct x64dbg_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return x64dbg_impl::find_all(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "x64dbg";
    }
};

REGISTER_PATTERN(x64dbg_pattern_scanner);
