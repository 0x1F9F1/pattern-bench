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

#pragma once

#include <mem/mem.h>
#include <mem/init_function.h>

#include <chrono>
#include <vector>
#include <memory>
#include <vector>

using mem::byte;

using stopwatch = std::chrono::steady_clock;

struct pattern_scanner
{
    stopwatch::duration ElapsedScan;
    stopwatch::duration ElapsedTotal;

    size_t Failed {0};

    virtual const char* GetName() const = 0;
    virtual void Init(const byte* pattern, const char* mask) = 0;
    virtual std::vector<const byte*> Scan(const byte* data, size_t length) const = 0;
};

extern std::vector<std::unique_ptr<pattern_scanner>> PATTERNS;

#define REGISTER_PATTERN__(CLASS, LINE) static mem::init_function DO_REGISTER_PATTERN_##LINE {[ ] { PATTERNS.emplace_back(std::make_unique<CLASS>()); }}
#define REGISTER_PATTERN_(CLASS, LINE) REGISTER_PATTERN__(CLASS, LINE)
#define REGISTER_PATTERN(CLASS) REGISTER_PATTERN_(CLASS, __LINE__)

std::vector<const byte*> FindPatternSimple(const byte* data, size_t length, const byte* pattern, const char* masks);
