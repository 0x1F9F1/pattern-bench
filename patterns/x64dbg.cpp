// https://github.com/x64dbg/x64dbg/blob/c64f7784ab26b68482facf2a57e7689e4ab0defb/src/dbg/patternfind.cpp

#include "pattern_entry.h"

#include <cstring>
#include <vector>
#include <algorithm>

namespace x64dbg_impl
{
struct PatternByte
{
    // Nibble-aware mask/value encoding:
    // ((byte ^ value) & mask) == 0 means match.
    // mask bit = 1 enforces compare, 0 ignores wildcard nibble.
    unsigned char data = 0;
    unsigned char mask = 0;
};

struct PatternNeedle
{
    unsigned char data;
    unsigned char mask;
    size_t offset;
};

size_t patternfind(const unsigned char* data, size_t datasize, const std::vector<PatternByte>& pattern)
{
    size_t searchpatternsize = pattern.size();

    if (datasize < searchpatternsize)
        return -1;

    std::unique_ptr<PatternNeedle[]> const needles(new PatternNeedle[searchpatternsize]);
    size_t n_needles = 0;

    // Collect all of the literal bytes.
    // The less common bytes tend to be at the end, so iterate back-to-front.
    for (size_t i = searchpatternsize; i--;)
    {
        if (pattern[i].mask == 0xFF)
            needles[n_needles++] = {pattern[i].data, pattern[i].mask, i};
    }

    size_t literals = n_needles;

    // Don't forget the partially masked bytes.
    for (size_t i = searchpatternsize; i--;)
    {
        if (pattern[i].mask != 0x00 && pattern[i].mask != 0xFF)
            needles[n_needles++] = {pattern[i].data, pattern[i].mask, i};
    }

    if (n_needles == 0)
        return -1;

    const unsigned char* here = data;
    const unsigned char* end = &data[datasize - (searchpatternsize - 1)];

    do
    {
        if (literals)
        {
            PatternNeedle needle = needles[0];

            // On Windows, memchr is not as fast as it could be, so MSVC's std::find uses its own SIMD implementation.
            here = std::find(here + needle.offset, end + needle.offset, needle.data) - needle.offset;
            if (here == end)
                break;

            for (size_t i = 1; i < literals; ++i)
            {
                needle = needles[i];

                if (here[needle.offset] != needle.data)
                {
                    // Swap this mismatched needle with the previously matched one.
                    // By constantly re-adjusting the order of the needles, the least common one should be moved to the front,
                    // maximizing the time spent inside std::find, and minimizing the time spent checking the rest of the bytes.
                    needles[i] = needles[i - 1];
                    needles[i - 1] = needle;
                    goto skip;
                }
            }
        }

        for (size_t i = literals; i < n_needles; ++i)
        {
            PatternNeedle needle = needles[i];

            if ((here[needle.offset] & needle.mask) != needle.data)
                goto skip;
        }

        return here - data;

    skip:
        ++here;
    } while (here != end);

    return -1;
}

static std::vector<PatternByte> to_pattern_bytes(const byte* pattern, const char* mask)
{
    const size_t length = std::strlen(mask);
    std::vector<PatternByte> out(length);

    for (size_t i = 0; i < length; ++i)
    {
        if (mask[i] == '?')
        {
            out[i].data = 0;
            out[i].mask = 0x00;
        }
        else
        {
            out[i].data = pattern[i];
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
