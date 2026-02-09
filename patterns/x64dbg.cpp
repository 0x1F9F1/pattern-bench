// https://github.com/x64dbg/x64dbg/blob/c64f7784ab26b68482facf2a57e7689e4ab0defb/src/dbg/patternfind.cpp

#include "pattern_entry.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace x64dbg_impl
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

size_t patternfind(const unsigned char* data, size_t datasize, const std::vector<PatternByte>& pattern)
{
    size_t searchpatternsize = pattern.size();
    for (size_t i = 0, pos = 0; i < datasize; i++)
    {
        if (patternmatchbyte(data[i], pattern.at(pos)))
        {
            pos++;
            if (pos == searchpatternsize)
                return i - searchpatternsize + 1;
        }
        else if (pos > 0)
        {
            i -= pos;
            pos = 0;
        }
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
