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