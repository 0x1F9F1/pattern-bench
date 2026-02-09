// Based on Sig mask-comparator pattern search.
// https://github.com/HoShiMin/Sig

#include "pattern_entry.h"

#include <cstring>
#include <vector>

namespace sig_impl
{
struct Mask
{
    template <char ch>
    struct Eq
    {
        static constexpr char k_char = ch;
        static bool cmp(char data, char pattern)
        {
            return data == pattern;
        }
    };

    template <char ch>
    struct Any
    {
        static constexpr char k_char = ch;
        static bool cmp(char, char)
        {
            return true;
        }
    };
};

template <typename... Entries>
struct MaskComparator;

template <typename Entry, typename... Entries>
struct MaskComparator<Entry, Entries...>
{
    static bool cmp(char data, char pattern, char mask)
    {
        if (mask == Entry::k_char)
            return Entry::cmp(data, pattern);

        return MaskComparator<Entries...>::cmp(data, pattern, mask);
    }
};

template <>
struct MaskComparator<>
{
    static bool cmp(char, char, char)
    {
        return false;
    }
};

template <typename... Comparators>
static const byte* FindFirst(const byte* buf, size_t size, const char* sig, const char* mask, size_t sigsize)
{
    if (!buf || !sig || !mask || sigsize == 0 || size < sigsize)
        return nullptr;

    const byte* pos = buf;
    const byte* const end = buf + size - sigsize + 1;
    while (pos < end)
    {
        bool result = true;
        for (size_t i = 0; i < sigsize; ++i)
        {
            const bool matches = MaskComparator<Comparators...>::cmp(
                static_cast<char>(pos[i]), sig[i], mask[i]);
            result &= matches;
            if (!result)
                break;
        }

        if (result)
            return pos;

        ++pos;
    }

    return nullptr;
}

static std::vector<const byte*> FindAll(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;
    const size_t patternLen = std::strlen(mask);

    size_t base = 0;
    while (base < length)
    {
        const byte* found = FindFirst<Mask::Eq<'x'>, Mask::Any<'?'>>(
            data + base, length - base, reinterpret_cast<const char*>(pattern), mask, patternLen);
        if (!found)
            break;

        results.push_back(found);
        base = static_cast<size_t>((found - data) + 1);
    }

    return results;
}
} // namespace sig_impl

struct sig_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return sig_impl::FindAll(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "Sig";
    }
};

REGISTER_PATTERN(sig_pattern_scanner);
