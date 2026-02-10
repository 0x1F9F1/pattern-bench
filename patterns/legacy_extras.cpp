// Source remote: https://github.com/learn-more/findpattern-bench

#include "pattern_entry.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace legacy_common
{
static inline char hex_upper(unsigned int v)
{
    return static_cast<char>((v < 10u) ? ('0' + v) : ('A' + (v - 10u)));
}

static std::string make_compact_hex_pattern(const byte* pattern, const char* mask)
{
    const size_t length = std::strlen(mask);
    std::string out;
    out.reserve(length * 2);

    for (size_t i = 0; i < length; ++i)
    {
        if (mask[i] == '?')
        {
            out.push_back('?');
            out.push_back('?');
        }
        else
        {
            const unsigned int value = static_cast<unsigned int>(pattern[i]);
            out.push_back(hex_upper((value >> 4) & 0xFu));
            out.push_back(hex_upper(value & 0xFu));
        }
    }

    return out;
}

static std::string make_spaced_hex_pattern(const byte* pattern, const char* mask, bool single_wildcard_token)
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
            if (!single_wildcard_token)
                out.push_back('?');
        }
        else
        {
            const unsigned int value = static_cast<unsigned int>(pattern[i]);
            out.push_back(hex_upper((value >> 4) & 0xFu));
            out.push_back(hex_upper(value & 0xFu));
        }
    }

    return out;
}
} // namespace legacy_common

namespace atom0s_impl
{
static std::vector<std::pair<byte, bool>> build_pattern(const byte* pattern, const char* mask)
{
    std::vector<std::pair<byte, bool>> out;
    const size_t length = std::strlen(mask);
    out.reserve(length);

    for (size_t i = 0; i < length; ++i)
        out.push_back(std::make_pair(pattern[i], mask[i] == 'x'));

    return out;
}

static const byte* find_first(const byte* begin, const byte* end, const std::vector<std::pair<byte, bool>>& pattern)
{
    if (pattern.empty())
        return nullptr;

    const byte* it = std::search(begin, end, pattern.begin(), pattern.end(), [](byte curr, const std::pair<byte, bool>& p) {
        return (!p.second) || curr == p.first;
    });
    return (it == end) ? nullptr : it;
}

static std::vector<const byte*> find_all(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;
    const std::vector<std::pair<byte, bool>> pat = build_pattern(pattern, mask);
    if (pat.empty() || pat.size() > length)
        return results;

    const byte* begin = data;
    const byte* const end = data + length;
    while (begin < end)
    {
        const byte* found = find_first(begin, end, pat);
        if (!found)
            break;

        results.push_back(found);
        begin = found + 1;
    }

    return results;
}
} // namespace atom0s_impl

struct atom0s_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return atom0s_impl::find_all(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "atom0s";
    }
};

REGISTER_PATTERN(atom0s_pattern_scanner);

namespace atom0s_mrexodia_impl
{
struct PatternByte
{
    struct PatternNibble
    {
        unsigned char data;
        bool wildcard;
    } nibble[2];
};

static int hex_ch_to_int(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    return 0;
}

static std::string format_pattern(const std::string& pattern_text)
{
    std::string result;
    result.reserve(pattern_text.size());

    for (size_t i = 0; i < pattern_text.size(); ++i)
    {
        const unsigned char ch = static_cast<unsigned char>(pattern_text[i]);
        if (pattern_text[i] == '?' || std::isxdigit(ch))
            result.push_back(static_cast<char>(std::toupper(ch)));
    }
    return result;
}

static bool transform_pattern(const std::string& pattern_text, std::vector<PatternByte>& pattern)
{
    pattern.clear();
    std::string text = format_pattern(pattern_text);
    size_t len = text.length();
    if (!len)
        return false;

    if (len % 2)
    {
        text.push_back('?');
        ++len;
    }

    PatternByte current {};
    int nibble = 0;
    for (size_t i = 0; i < len; ++i)
    {
        if (text[i] == '?')
        {
            current.nibble[nibble].wildcard = true;
            current.nibble[nibble].data = 0;
        }
        else
        {
            current.nibble[nibble].wildcard = false;
            current.nibble[nibble].data = static_cast<unsigned char>(hex_ch_to_int(text[i]) & 0xF);
        }

        ++nibble;
        if (nibble == 2)
        {
            pattern.push_back(current);
            current = PatternByte {};
            nibble = 0;
        }
    }

    return true;
}

static bool match_byte(byte value, const PatternByte& pbyte)
{
    unsigned int matched = 0;

    const unsigned char n1 = static_cast<unsigned char>((value >> 4) & 0xF);
    if (pbyte.nibble[0].wildcard || pbyte.nibble[0].data == n1)
        ++matched;

    const unsigned char n2 = static_cast<unsigned char>(value & 0xF);
    if (pbyte.nibble[1].wildcard || pbyte.nibble[1].data == n2)
        ++matched;

    return matched == 2;
}

static const byte* find_first(const byte* begin, const byte* end, const std::vector<PatternByte>& pattern)
{
    if (pattern.empty())
        return nullptr;

    const byte* it = std::search(begin, end, pattern.begin(), pattern.end(), [](byte curr, const PatternByte& p) {
        return match_byte(curr, p);
    });
    return (it == end) ? nullptr : it;
}

static std::vector<const byte*> find_all(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;
    const std::string pattern_text = legacy_common::make_compact_hex_pattern(pattern, mask);

    std::vector<PatternByte> pat;
    if (!transform_pattern(pattern_text, pat) || pat.size() > length)
        return results;

    const byte* begin = data;
    const byte* const end = data + length;
    while (begin < end)
    {
        const byte* found = find_first(begin, end, pat);
        if (!found)
            break;

        results.push_back(found);
        begin = found + 1;
    }

    return results;
}
} // namespace atom0s_mrexodia_impl

struct atom0s_mrexodia_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return atom0s_mrexodia_impl::find_all(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "atom0s (mrexodia modification)";
    }
};

REGISTER_PATTERN(atom0s_mrexodia_pattern_scanner);

namespace learn_more_impl
{
static inline bool in_range(unsigned char x, unsigned char a, unsigned char b)
{
    return x >= a && x <= b;
}

static inline unsigned char get_bits(unsigned char x)
{
    return static_cast<unsigned char>(in_range(x, '0', '9') ? (x - '0') : ((x & static_cast<unsigned char>(~0x20)) - 'A' + 0xA));
}

static inline unsigned char get_byte(const unsigned char* x)
{
    return static_cast<unsigned char>((get_bits(x[0]) << 4) | get_bits(x[1]));
}

static const byte* find_first(const byte* range_start, const byte* range_end, const char* pattern)
{
    const unsigned char* pat = reinterpret_cast<const unsigned char*>(pattern);
    const byte* first_match = nullptr;

    for (const byte* cur = range_start; cur < range_end; ++cur)
    {
        if (*pat == static_cast<unsigned char>('?') || *cur == get_byte(pat))
        {
            if (!first_match)
                first_match = cur;

            pat += ((pat[0] == '?' && pat[1] == '?') || pat[0] != '?') ? 2 : 1;
            if (!*pat)
                return first_match;

            ++pat;
            if (!*pat)
                return first_match;
        }
        else if (first_match)
        {
            cur = first_match;
            pat = reinterpret_cast<const unsigned char*>(pattern);
            first_match = nullptr;
        }
    }

    return nullptr;
}

static std::vector<const byte*> find_all(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;
    const size_t pattern_length = std::strlen(mask);
    if (pattern_length == 0 || pattern_length > length)
        return results;

    const std::string pattern_text = legacy_common::make_spaced_hex_pattern(pattern, mask, false);

    size_t base = 0;
    while (base < length)
    {
        const byte* found = find_first(data + base, data + length, pattern_text.c_str());
        if (!found)
            break;

        results.push_back(found);
        base = static_cast<size_t>(found - data) + 1;
    }

    return results;
}
} // namespace learn_more_impl

struct learn_more_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return learn_more_impl::find_all(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "learn_more";
    }
};

REGISTER_PATTERN(learn_more_pattern_scanner);

namespace learn_more_v2_impl
{
static const byte* find_first(const byte* range_start, size_t len, const char* pattern)
{
    std::vector<byte> pat;
    std::vector<char> msk;

    while (*pattern)
    {
        if (*pattern == ' ')
        {
            ++pattern;
            continue;
        }

        if (!*pattern)
            break;

        if (*pattern == '?')
        {
            pat.push_back(0);
            msk.push_back('?');
            pattern += (pattern[1] == '?') ? 2 : 1;
        }
        else
        {
            pat.push_back(learn_more_impl::get_byte(reinterpret_cast<const unsigned char*>(pattern)));
            msk.push_back('x');
            pattern += 2;
        }
    }

    if (pat.empty() || pat.size() > len)
        return nullptr;

    for (size_t n = 0; n <= len - pat.size(); ++n)
    {
        bool match = true;
        for (size_t i = 0; i < pat.size(); ++i)
        {
            if (msk[i] == 'x' && range_start[n + i] != pat[i])
            {
                match = false;
                break;
            }
        }

        if (match)
            return range_start + n;
    }

    return nullptr;
}

static std::vector<const byte*> find_all(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;
    const size_t pattern_length = std::strlen(mask);
    if (pattern_length == 0 || pattern_length > length)
        return results;

    const std::string pattern_text = legacy_common::make_spaced_hex_pattern(pattern, mask, false);

    size_t base = 0;
    while (base < length)
    {
        const byte* found = find_first(data + base, length - base, pattern_text.c_str());
        if (!found)
            break;

        results.push_back(found);
        base = static_cast<size_t>(found - data) + 1;
    }

    return results;
}
} // namespace learn_more_v2_impl

struct learn_more_v2_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return learn_more_v2_impl::find_all(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "learn_more v2";
    }
};

REGISTER_PATTERN(learn_more_v2_pattern_scanner);

namespace mike_impl
{
static const byte* find_first(const byte* base, size_t size, const std::string& pattern_text)
{
    const unsigned char* pattern = reinterpret_cast<const unsigned char*>(pattern_text.c_str());
    const int pattern_length = static_cast<int>(pattern_text.size());
    if (pattern_length <= 0 || pattern[0] == ' ')
        return nullptr;

    for (size_t i = 0; i < size; ++i)
    {
        for (int j = 0, k = 0; j < pattern_length && (i + static_cast<size_t>(k) < size); ++k)
        {
            if (pattern[j] == static_cast<unsigned char>('?'))
            {
                j += 2;
                if (j >= pattern_length)
                    return base + i;
                continue;
            }

            unsigned char temp_char[3] = {0, 0, 0};
            std::snprintf(reinterpret_cast<char*>(temp_char), sizeof(temp_char), "%02X", base[i + static_cast<size_t>(k)]);

            if (temp_char[0] != pattern[j] || temp_char[1] != pattern[j + 1])
                break;

            j += 3;
            if (j >= pattern_length)
                return base + i;
        }
    }

    return nullptr;
}

static std::vector<const byte*> find_all(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;
    const size_t pattern_length = std::strlen(mask);
    if (pattern_length == 0 || pattern_length > length)
        return results;

    const std::string pattern_text = legacy_common::make_spaced_hex_pattern(pattern, mask, true);

    size_t base = 0;
    while (base < length)
    {
        const byte* found = find_first(data + base, length - base, pattern_text);
        if (!found)
            break;

        results.push_back(found);
        base = static_cast<size_t>(found - data) + 1;
    }

    return results;
}
} // namespace mike_impl

struct mike_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return mike_impl::find_all(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "M-i-K-e";
    }
};

// Disabled by default: fails randomized smoke in this harness.
REGISTER_PATTERN(mike_pattern_scanner);

namespace stevemk14ebr_impl
{
static int get_pattern_size(const char* signature)
{
    return static_cast<int>((std::strlen(signature) + 1) / 3);
}

static unsigned char get_bits(unsigned char x)
{
    if (x >= '0' && x <= '9')
        return static_cast<unsigned char>(x - '0');

    return static_cast<unsigned char>(((x & 0xDF) - 'A') + 0xA);
}

static ptrdiff_t find_first(const char* signature, const byte* data, size_t data_size)
{
    const int pattern_size = get_pattern_size(signature);
    if (pattern_size <= 0)
        return -1;

    for (size_t i = 0; i < data_size; ++i)
    {
        int sig_idx = 0;
        for (; sig_idx < pattern_size && (i + static_cast<size_t>(sig_idx)) < data_size; ++sig_idx)
        {
            const int sig_pat_idx = sig_idx * 3;
            const byte dat = data[i + static_cast<size_t>(sig_idx)];
            const unsigned char sig_hi =
                signature[sig_pat_idx] == '?' ? static_cast<unsigned char>(dat & 0xF0)
                                              : static_cast<unsigned char>(get_bits(static_cast<unsigned char>(signature[sig_pat_idx])) << 4);
            const unsigned char sig_lo = signature[sig_pat_idx + 1] == '?'
                ? static_cast<unsigned char>(dat & 0x0F)
                : get_bits(static_cast<unsigned char>(signature[sig_pat_idx + 1]));

            if (dat != static_cast<byte>(sig_hi | sig_lo))
                break;
        }

        if (sig_idx >= pattern_size)
            return static_cast<ptrdiff_t>(i);
    }

    return -1;
}

static std::vector<const byte*> find_all(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;
    const size_t pattern_length = std::strlen(mask);
    if (pattern_length == 0 || pattern_length > length)
        return results;

    const std::string pattern_text = legacy_common::make_spaced_hex_pattern(pattern, mask, false);

    size_t base = 0;
    while (base < length)
    {
        const ptrdiff_t offset = find_first(pattern_text.c_str(), data + base, length - base);
        if (offset < 0)
            break;

        const byte* found = data + base + offset;
        results.push_back(found);
        base = static_cast<size_t>(found - data) + 1;
    }

    return results;
}
} // namespace stevemk14ebr_impl

struct stevemk14ebr_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return stevemk14ebr_impl::find_all(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "stevemk14ebr";
    }
};

REGISTER_PATTERN(stevemk14ebr_pattern_scanner);

namespace superdoc1234_impl
{
static bool data_compare(const byte* data, const byte* mask_data, const char* mask)
{
    for (; *mask; ++mask, ++data, ++mask_data)
    {
        if (*mask == 'x' && *data != *mask_data)
            return false;
    }

    return true;
}

static const byte* find_first(const byte* base, const byte* pattern, const char* mask, size_t length)
{
    const size_t mask_length = std::strlen(mask);
    if (mask_length == 0 || mask_length > length)
        return nullptr;

    const byte* cursor = base;
    const byte* scan_end = base + length - mask_length;
    for (; cursor <= scan_end; ++cursor)
    {
        if (data_compare(cursor, pattern, mask))
            return cursor;
    }

    return nullptr;
}

static std::vector<const byte*> find_all(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;
    const size_t pattern_length = std::strlen(mask);
    if (pattern_length == 0 || pattern_length > length)
        return results;

    size_t base = 0;
    while (base < length)
    {
        const byte* found = find_first(data + base, pattern, mask, length - base);
        if (!found)
            break;

        results.push_back(found);
        base = static_cast<size_t>(found - data) + 1;
    }

    return results;
}
} // namespace superdoc1234_impl

struct superdoc1234_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return superdoc1234_impl::find_all(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "superdoc1234";
    }
};

REGISTER_PATTERN(superdoc1234_pattern_scanner);

namespace trippeh_v2_impl
{
static bool compare_byte_array(const byte* lhs, const byte* rhs, size_t length)
{
    for (size_t i = 0; i < length; ++i)
    {
        if (rhs[i] != static_cast<byte>(0xCC) && lhs[i] != rhs[i])
            return false;
    }

    return true;
}

static const byte* find_first(const byte* base, size_t image_size, const byte* pattern, size_t length)
{
    if (length == 0 || image_size < length)
        return nullptr;

    for (size_t i = 0; i <= image_size - length; ++i)
    {
        if (compare_byte_array(base + i, pattern, length))
            return base + i;
    }

    return nullptr;
}

static std::vector<const byte*> find_all(const byte* data, size_t length, const byte* pattern, const char* mask)
{
    std::vector<const byte*> results;
    const size_t pattern_length = std::strlen(mask);
    if (pattern_length == 0 || pattern_length > length)
        return results;

    std::vector<byte> transformed(pattern, pattern + pattern_length);
    for (size_t i = 0; i < pattern_length; ++i)
    {
        if (mask[i] == '?')
            transformed[i] = static_cast<byte>(0xCC);
    }

    size_t base = 0;
    while (base < length)
    {
        const byte* found = find_first(data + base, length - base, transformed.data(), transformed.size());
        if (!found)
            break;

        results.push_back(found);
        base = static_cast<size_t>(found - data) + 1;
    }

    return results;
}
} // namespace trippeh_v2_impl

struct trippeh_v2_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return trippeh_v2_impl::find_all(data, length, pattern, mask);
    }

    virtual const char* GetName() const override
    {
        return "Trippeh v2";
    }
};

REGISTER_PATTERN(trippeh_v2_pattern_scanner);
