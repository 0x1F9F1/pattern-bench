// https://github.com/x64dbg/x64dbg/pull/3793

#include "pattern_entry.h"

#include <array>
#include <cstring>
#include <vector>

namespace x64dbg_bmh_impl
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

struct CompiledPattern
{
    std::vector<PatternByte> bytes;
    std::array<size_t, 256> skip {};
    size_t last = 0;
};

static CompiledPattern compile_pattern(const byte* pattern, const char* mask)
{
    CompiledPattern compiled;
    compiled.bytes = to_pattern_bytes(pattern, mask);

    if (compiled.bytes.empty())
        return compiled;

    compiled.last = compiled.bytes.size() - 1;
    size_t idx = compiled.last;
    while (idx > 0 && compiled.bytes[idx].mask == 0xFF)
        --idx;

    size_t diff = compiled.last - idx;
    if (diff == 0)
        diff = 1;

    compiled.skip.fill(diff);
    for (size_t i = compiled.last - diff; i < compiled.last; ++i)
    {
        if (compiled.bytes[i].mask == 0xFF)
            compiled.skip[compiled.bytes[i].value] = compiled.last - i;
    }

    return compiled;
}

static std::vector<const byte*> find_all(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;
    const CompiledPattern compiled = compile_pattern(pattern, mask);
    const std::vector<PatternByte>& parsed = compiled.bytes;
    const size_t searchpatternsize = parsed.size();
    if (searchpatternsize == 0 || length < searchpatternsize)
        return results;

    const PatternByte* pat = parsed.data();
    const size_t last = compiled.last;
    const size_t maxPos = length - searchpatternsize;

    size_t pos = 0;
    while (pos <= maxPos)
    {
        bool matched = true;
        for (size_t i = searchpatternsize; i > 0; --i)
        {
            const size_t check = i - 1;
            if (!patternmatchbyte(data[pos + check], pat[check]))
            {
                matched = false;
                break;
            }
        }

        if (matched)
        {
            results.push_back(data + pos);
            ++pos; // preserve overlap behavior from repeated find-next-at+1 calls
            continue;
        }

        pos += compiled.skip[data[pos + last]];
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
