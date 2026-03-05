/*
    Copyright 2018 Brick

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software
    and associated documentation files (the "Software"), to deal in the Software without restriction,
    including without limitation the rights to use, copy, modify, merge, publish, distribute,
    sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or
    substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
    BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "pattern_entry.h"

#include <mem/pattern.h>

#include <mem/boyer_moore_scanner.h>

struct mem_boyer_moore_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* bytes, const char* mask, const byte* data, size_t length) const override
    {
        mem::pattern pattern(bytes, mask);
        mem::boyer_moore_scanner scanner(pattern);

        std::vector<const byte*> results;

        scanner({data, length}, [&](mem::pointer result) {
            results.push_back(result.as<const byte*>());

            return false;
        });

        return results;
    }

    virtual const char* GetName() const override
    {
        return "mem::boyer_moore_scanner";
    }
};

REGISTER_PATTERN(mem_boyer_moore_pattern_scanner);

#include <mem/simd_scanner.h>

struct mem_simd_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* bytes, const char* mask, const byte* data, size_t length) const override
    {
        mem::pattern pattern(bytes, mask);
        mem::simd_scanner scanner(pattern);

        std::vector<const byte*> results;

        scanner({data, length}, [&](mem::pointer result) {
            results.push_back(result.as<const byte*>());

            return false;
        });

        return results;
    }

    virtual const char* GetName() const override
    {
        return "mem::simd_scanner";
    }
};

REGISTER_PATTERN(mem_simd_pattern_scanner);

struct dynamic_freq_scanner : pattern_scanner
{
    struct scan_byte
    {
        std::uint8_t value;
        std::uint32_t offset;
    };

    virtual std::vector<const byte*> Scan(
        const byte* bytes, const char* mask, const byte* data, size_t length) const override
    {
        const std::size_t pattern_length = std::strlen(mask);

        if (length < pattern_length)
            return {};

        std::vector<scan_byte> needles;

        for (std::size_t i = pattern_length; i--;)
        {
            if (mask[i] == 'x')
                needles.push_back({bytes[i], static_cast<std::uint32_t>(i)});
        }

        if (needles.empty())
            return {};

        const byte* const end = &data[length - (pattern_length - 1)];
        scan_byte* p_needles = needles.data();
        const std::size_t n_needles = needles.size();

        std::vector<const byte*> results;

        while (true)
        {
            scan_byte needle = p_needles[0];
            data = std::find(data + needle.offset, end + needle.offset, needle.value) - needle.offset;
            if (data == end)
                break;

            for (std::size_t i = 1;;)
            {
                if (i == n_needles)
                {
                    results.push_back(data);
                    break;
                }

                needle = p_needles[i++];

                if (data[needle.offset] == needle.value)
                    continue;

                p_needles[i - 1] = p_needles[i - 2];
                p_needles[i - 2] = needle;
                break;
            }

            ++data;
        }

        return results;
    }

    virtual const char* GetName() const override
    {
        return "dynamic_freq_scanner";
    }
};

REGISTER_PATTERN(dynamic_freq_scanner);