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

std::vector<std::unique_ptr<pattern_scanner>> PATTERN_SCANNERS;

std::vector<const byte*> FindPatternSimple(const byte* data, size_t length, const byte* pattern, const char* masks)
{
    size_t pattern_length = strlen(masks);

    if (pattern_length > length)
    {
        return {};
    }

    std::vector<const byte*> results;

    length -= pattern_length;

    for (size_t i = 0; i <= length; ++i)
    {
        bool found = true;

        for (size_t j = 0; j < pattern_length; ++j)
        {
            if ((data[i + j] != pattern[j]) && (masks[j] != '?'))
            {
                found = false;

                break;
            }
        }

        if (found)
        {
            results.push_back(data + i);
        }
    }

    return results;
}

static inline char hex_upper(unsigned int v)
{
    return static_cast<char>((v < 10u) ? ('0' + v) : ('A' + (v - 10u)));
}

std::string MakeCompactHexPattern(const byte* pattern, const char* mask)
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

std::string MakeSpacedHexPattern(const byte* pattern, const char* mask, bool single_wildcard_token)
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