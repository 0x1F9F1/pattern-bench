// Source remote: https://github.com/Dasaav-dsv/Pattern16

#include "pattern_entry.h"

#include <Pattern16.h>

#include <cstring>
#include <string>
#include <vector>

namespace pattern16_impl
{
static bool has_adjacent_exact_bytes(const char* mask)
{
    const size_t length = std::strlen(mask);
    if (length < 2)
        return false;

    for (size_t i = 0; (i + 1) < length; ++i)
    {
        if (mask[i] == 'x' && mask[i + 1] == 'x')
            return true;
    }

    return false;
}

static inline char hex_nibble(unsigned int value)
{
    return static_cast<char>((value < 10u) ? ('0' + value) : ('A' + (value - 10u)));
}

static std::string to_signature_string(const byte* pattern, const char* mask)
{
    const size_t length = std::strlen(mask);
    std::string out;
    out.reserve(length * 3);

    for (size_t i = 0; i < length; ++i)
    {
        if (i != 0)
            out.push_back(' ');

        if (mask[i] == '?')
        {
            out.push_back('?');
            out.push_back('?');
        }
        else
        {
            const unsigned int value = static_cast<unsigned int>(pattern[i]);
            out.push_back(hex_nibble((value >> 4) & 0xFu));
            out.push_back(hex_nibble(value & 0xFu));
        }
    }

    return out;
}

static std::vector<const byte*> find_all(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;

    const size_t pattern_length = std::strlen(mask);
    if (pattern_length == 0 || pattern_length > length)
        return results;

    // Pattern16 can miss valid matches in long regions when no adjacent exact-byte pair exists.
    // Fall back to the reference scanner for this pattern class to keep correctness.
    if (!has_adjacent_exact_bytes(mask))
        return FindPatternSimple(data, length, pattern, mask);

    std::string signature = to_signature_string(pattern, mask);
    Pattern16::Impl::SplitSignatureU8 parsed = Pattern16::Impl::processSignatureString(signature);
    if (parsed.first.empty())
        return results;

    const Pattern16::Impl::Frequencies16& frequencies = Pattern16::Impl::loadFrequencyCache();

    size_t base = 0;
    while (base < length)
    {
        const size_t remaining = length - base;
        Pattern16::Impl::SplitSignatureU8 parsed_iter = parsed;
        const byte* found = static_cast<const byte*>(Pattern16::Impl::scan(data + base, remaining, parsed_iter, frequencies));
        if (!found)
            break;

        if (found < (data + base) || found >= (data + length))
            break;

        results.push_back(found);
        base = static_cast<size_t>(found - data) + 1;
    }

    return results;
}
} // namespace pattern16_impl

struct pattern16_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return pattern16_impl::find_all(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "Pattern16";
    }
};

REGISTER_PATTERN(pattern16_scanner);
