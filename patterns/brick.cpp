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

struct mem_pattern_scanner
    : pattern_scanner
{
    mem::pattern CurrentPattern;

    virtual const char* GetName() const
    {
        return "mem::pattern";
    }

    virtual void Init(const byte* pattern, const char* mask)
    {
        CurrentPattern = mem::pattern((const char*) pattern, mask);
    }

    virtual std::vector<const byte*> Scan(const byte* data, size_t length) const
    {
        std::vector<const byte*> results;

        CurrentPattern.scan_predicate({ data, length }, [&] (mem::pointer result)
        {
            results.push_back(result.as<const byte*>());

            return false;
        });

        return results;
    }
};

REGISTER_PATTERN(mem_pattern_scanner);
