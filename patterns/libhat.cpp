// Based on libhat single-mode scanner flow:
// signature_element -> truncate -> find_pattern_single -> find_all_pattern.
// Source remote: https://github.com/BasedInc/libhat

#include "pattern_entry.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace libhat_impl
{
struct signature_element
{
    signature_element() : value_(0), mask_(0) {}
    signature_element(byte value, byte mask) : value_(value & mask), mask_(mask) {}

    byte value() const
    {
        return value_;
    }

    byte mask() const
    {
        return mask_;
    }

    bool all() const
    {
        return mask_ == static_cast<byte>(0xFF);
    }

    bool any() const
    {
        return mask_ != static_cast<byte>(0x00);
    }

    bool none() const
    {
        return mask_ == static_cast<byte>(0x00);
    }

    bool operator==(byte v) const
    {
        return (v & mask_) == value_;
    }

private:
    byte value_;
    byte mask_;
};

typedef std::vector<signature_element> pattern_signature;

static pattern_signature make_signature(const byte* pattern, const char* mask)
{
    const size_t size = std::strlen(mask);
    pattern_signature sig;
    sig.reserve(size);

    for (size_t i = 0; i < size; ++i)
    {
        if (mask[i] == '?')
            sig.push_back(signature_element(0x00, 0x00));
        else
            sig.push_back(signature_element(pattern[i], 0xFF));
    }

    return sig;
}

static std::pair<size_t, pattern_signature> truncate(const pattern_signature& sig)
{
    size_t offset = 0;
    for (size_t i = 0; i < sig.size(); ++i)
    {
        if (sig[i].any())
            break;
        ++offset;
    }

    pattern_signature trunc(sig.begin() + static_cast<ptrdiff_t>(offset), sig.end());
    return std::make_pair(offset, trunc);
}

static const byte* find_pattern_single(const byte* begin, const byte* end, const pattern_signature& sig)
{
    if (sig.empty())
        return nullptr;

    const byte firstByte = sig[0].value();
    const byte* const scanEnd = end - sig.size() + 1;

    for (const byte* i = begin; i != scanEnd; ++i)
    {
        i = std::find(i, scanEnd, firstByte);
        if (i == scanEnd)
            break;

        bool match = true;
        for (size_t j = 1; j < sig.size(); ++j)
        {
            if (!(sig[j] == i[j]))
            {
                match = false;
                break;
            }
        }

        if (match)
            return i;
    }

    return nullptr;
}

static std::vector<const byte*> find_all_pattern(
    const byte* begin, const byte* end, const pattern_signature& sig)
{
    std::vector<const byte*> results;
    const std::pair<size_t, pattern_signature> truncated = truncate(sig);

    const size_t offset = truncated.first;
    const pattern_signature& trunc = truncated.second;

    const byte* i = begin + static_cast<ptrdiff_t>(offset);
    while (i < end && trunc.size() <= static_cast<size_t>(end - i))
    {
        const byte* result = find_pattern_single(i, end, trunc);
        if (!result)
            break;

        const byte* addr = result - static_cast<ptrdiff_t>(offset);
        results.push_back(addr);
        i = result + 1;
    }

    return results;
}

static std::vector<const byte*> find_all(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    const pattern_signature sig = make_signature(pattern, mask);
    if (sig.empty())
        return {};

    return find_all_pattern(data, data + length, sig);
}
} // namespace libhat_impl

struct libhat_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return libhat_impl::find_all(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "libhat";
    }
};

REGISTER_PATTERN(libhat_pattern_scanner);
