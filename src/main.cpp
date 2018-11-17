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

#include <random>
#include <unordered_set>
#include <chrono>
#include <cassert>

#include <mem/mem.h>
#include <mem/pattern.h>
#include <mem/utils.h>

#include <mem/platform.h>
#include <mem/platform-inl.h>

#include <mem/init_function.h>
#include <mem/init_function-inl.h>

#include <fmt/format.h>

#include "pattern_entry.h"

static constexpr const size_t PAGE_COUNT = 64;
static constexpr const size_t TEST_COUNT = 1024 * 16;
static constexpr const uint32_t RNG_SEED = 0;
static constexpr const size_t LOG_LEVEL = 0;

using mem::byte;

std::mt19937 create_twister(uint32_t& seed)
{
    if (seed == 0)
    {
        seed = std::random_device{}();
    }

    std::minstd_rand0 source(seed);

    // Magic number 624: The number of unsigned ints the MT uses as state
    std::vector<unsigned int> random_data(624);
    std::generate(begin(random_data), end(random_data), source);

    std::seed_seq seeds(begin(random_data), end(random_data));
    std::mt19937 result(seeds);

    return result;
}

struct scan_bench
{
private:
    byte* raw_region_ {nullptr};

    byte* raw_data_ {nullptr};
    size_t raw_size_ {0};

    byte* data_ {nullptr};
    size_t size_ {0};

    uint32_t seed_ {RNG_SEED};
    std::mt19937 rng_ {create_twister(seed_)};

    std::string pattern_;
    std::string masks_;
    std::unordered_set<size_t> expected_;

public:
    scan_bench()
    {
        size_t page_size = mem::page_size();

        raw_size_ = page_size * PAGE_COUNT;
        raw_region_ = static_cast<byte*>(mem::protect_alloc(raw_size_ + (page_size * 2), mem::prot_flags::RW));
        raw_data_ = raw_region_ + page_size;

        mem::protect_modify(raw_region_, page_size, mem::prot_flags::NONE);
        mem::protect_modify(raw_region_ + page_size + raw_size_, page_size, mem::prot_flags::NONE);

        std::uniform_int_distribution<uint32_t> byte_dist(0, 0xFF);

        std::generate_n(data(), size(), [&] { return (byte) byte_dist(rng_); });
    }

    ~scan_bench()
    {
        mem::protect_free(raw_region_);
    }

    byte* data() noexcept
    {
        return data_;
    }

    size_t size() const noexcept
    {
        return size_;
    }

    const byte* pattern() const noexcept
    {
        return (const byte*) pattern_.c_str();
    }

    const char* masks() const noexcept
    {
        return masks_.c_str();
    }

    uint32_t seed() const noexcept
    {
        return seed_;
    }

    std::unordered_set<size_t> shift_results(const std::vector<const byte*>& results)
    {
        std::unordered_set<size_t> shifted;

        for (const byte* result : results)
        {
            shifted.emplace(result - data());
        }

        return shifted;
    }

    void generate()
    {
        std::uniform_int_distribution<size_t> size_dist(0, 100);

        size_t variation = size_dist(rng_);

        data_ = raw_data_ + variation;
        size_ = raw_size_ - variation;

        std::uniform_int_distribution<uint32_t> byte_dist(0, 0xFF);

        std::uniform_int_distribution<size_t> length_dist(5, 32);

        size_t pattern_length = length_dist(rng_);

        pattern_.resize(pattern_length);
        masks_.resize(pattern_length);

        bool all_masks = true;

        std::bernoulli_distribution mask_dist(0.1);

        do
        {
            std::generate_n(&pattern_[0], pattern_.size(), [&] { return (char) byte_dist(rng_); });
            std::generate_n(&masks_[0], masks_.size(), [&] { return mask_dist(rng_) ? '?' : 'x'; });

            all_masks = true;

            for (size_t i = 0; i < pattern_.size(); ++i)
            {
                if (masks_[i] == '?')
                    pattern_[i] = 0;
                else
                    all_masks = false;
            }
        } while (all_masks);

        std::uniform_int_distribution<size_t> count_dist(2, 10);

        size_t result_count = count_dist(rng_);

        std::uniform_int_distribution<size_t> range_dist(0, size() - pattern_.size());

        for (size_t i = 0; i < result_count; ++i)
        {
            size_t offset = range_dist(rng_);

            for (size_t j = 0; j < pattern_.size(); ++j)
            {
                if (masks_[j] != '?')
                    data_[offset + j] = pattern_[j];
            }
        }

        expected_ = shift_results(FindPatternSimple(data(), size(), pattern(), masks()));
    }

    bool check_results(const pattern_scanner& scanner, const std::vector<const byte*>& results)
    {
        std::unordered_set<size_t> shifted = shift_results(results);

        if (shifted.size() != expected_.size())
        {
            if (LOG_LEVEL > 2)
                fmt::print("{0:<32} - Got {1} results, Expected {2}\n", scanner.GetName(), shifted.size(), expected_.size());

            return false;
        }

        for (size_t result : shifted)
        {
            if (expected_.find(result) == expected_.end())
            {
                if (LOG_LEVEL > 2)
                    fmt::print("{0:<32} - Wasn't expecting 0x{1:X}\n", scanner.GetName(), result);

                return false;
            }
        }

        return true;
    }
};

int main()
{
    mem::init_function::init();

    scan_bench reg;

    fmt::print("Begin Scan: Seed: 0x{0:08X}, Pages: {1}, Tests: {2}\n", reg.seed(), PAGE_COUNT, TEST_COUNT);

    for (size_t i = 0; i < TEST_COUNT; ++i)
    {
        reg.generate();

        for (auto& pattern : PATTERNS)
        {
            stopwatch::time_point start_time = stopwatch::now();

            try
            {
                std::vector<const byte*> results = pattern->Scan(reg.pattern(), reg.masks(), reg.data(), reg.size());

                if (!reg.check_results(*pattern, results))
                {
                    if (LOG_LEVEL > 1)
                        fmt::print("{0:<32} - Failed test {1} ({2}, {3})\n", pattern->GetName(), i, mem::as_hex({ reg.pattern(), strlen(reg.masks()) }), reg.masks());

                    pattern->Failed++;
                }
            }
            catch (...)
            {
                if (LOG_LEVEL > 0)
                    fmt::print("{0:<32} - Failed test {1} (Exception)\n", pattern->GetName(), i);

                pattern->Failed++;
            }
            
            stopwatch::time_point end_time = stopwatch::now();

            pattern->Elapsed += end_time - start_time;
        }
    }

    std::sort(PATTERNS.begin(), PATTERNS.end(), [ ] (const auto& lhs, const auto& rhs)
    {
        if (lhs->Failed != rhs->Failed)
            return lhs->Failed < rhs->Failed;

        return lhs->Elapsed < rhs->Elapsed;
    });

    fmt::print("End Scan\n\n");

    for (size_t i = 0; i < PATTERNS.size(); ++i)
    {
        const auto& pattern = *PATTERNS[i];

        long long elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(pattern.Elapsed).count();

        fmt::print("{0} | {1:<32} | {2:>4} ms | {3:>3} failed\n", i, pattern.GetName(), elapsed, pattern.Failed);
    }
}
