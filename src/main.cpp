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

#include <cassert>
#include <chrono>
#include <fstream>
#include <random>
#include <unordered_set>

#include <mem/mem.h>
#include <mem/pattern.h>
#include <mem/utils.h>

#include <mem/execution_handler.h>
#include <mem/protect.h>

#include <mem/arch.h>

#include <mem/init_function.h>

#include <mem/cmd_param-inl.h>
#include <mem/cmd_param.h>

#include <mem/data_buffer.h>

#include <fmt/format.h>

#include "pattern_entry.h"

static size_t LOG_LEVEL = 0;

using mem::byte;

mem::byte_buffer read_file(const char* path)
{
    std::ifstream input(path, std::ifstream::binary | std::ifstream::ate);

    size_t length = static_cast<size_t>(input.tellg());

    input.seekg(0);

    mem::byte_buffer result(length);

    if (!input.read(reinterpret_cast<char*>(result.data()), result.size()))
    {
        result.reset();
    }

    return result;
}

struct scan_bench
{
private:
    byte* raw_data_ {nullptr};
    size_t raw_size_ {0};

    byte* full_data_ {nullptr};
    size_t full_size_ {0};

    byte* data_ {nullptr};
    size_t size_ {0};

    uint32_t seed_ {0};
    std::mt19937 rng_ {};

    std::vector<byte> pattern_;
    std::string masks_;
    std::unordered_set<size_t> expected_;

public:
    scan_bench(uint32_t seed)
        : seed_(seed)
        , rng_(seed_)
    {}

    scan_bench(const scan_bench&) = delete;
    scan_bench(scan_bench&&) = delete;

    ~scan_bench()
    {
        mem::protect_free(raw_data_, raw_size_);
    }

    void reset(size_t region_size)
    {
        reset(nullptr, region_size);
    }

    void reset(const char* file_name)
    {
        mem::byte_buffer region_data = read_file(file_name);

        reset(region_data.data(), region_data.size());
    }

    void reset(const byte* region_data, size_t region_size)
    {
        size_t page_size = mem::page_size();

        full_size_ = (region_size + page_size - 1) / page_size * page_size;

        raw_size_ = full_size_ + (page_size * 2);
        raw_data_ = static_cast<byte*>(mem::protect_alloc(raw_size_, mem::prot_flags::RW));

        full_data_ = raw_data_ + page_size;

        mem::protect_modify(raw_data_, page_size, mem::prot_flags::NONE);
        mem::protect_modify(raw_data_ + raw_size_ - page_size, page_size, mem::prot_flags::NONE);

        if (region_data)
        {
            size_t extra = (full_size_ - region_size);

            std::memset(full_data_, 0, extra);
            std::memcpy(full_data_ + extra, region_data, region_size);
        }
        else
        {
            std::uniform_int_distribution<uint32_t> byte_dist(0, 0xFF);

            std::generate_n(full_data_, full_size_, [&] { return (byte) byte_dist(rng_); });
        }
    }

    size_t full_size() const noexcept
    {
        return full_size_;
    }

    const byte* data() const noexcept
    {
        return data_;
    }

    size_t size() const noexcept
    {
        return size_;
    }

    const byte* pattern() const noexcept
    {
        return pattern_.data();
    }

    const char* masks() const noexcept
    {
        return masks_.data();
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

        data_ = full_data_ + variation;
        size_ = full_size_ - variation;

        std::uniform_int_distribution<uint32_t> byte_dist(0, 0xFF);

        std::uniform_int_distribution<size_t> length_dist(5, 32);

        size_t pattern_length = length_dist(rng_);

        pattern_.resize(pattern_length);
        masks_.resize(pattern_length);

        std::bernoulli_distribution mask_dist(0.9);

        bool all_masks = true;

        do
        {
            for (size_t i = 0; i < pattern_length; ++i)
            {
                if (mask_dist(rng_))
                {
                    pattern_[i] = (char) byte_dist(rng_);
                    masks_[i] = 'x';

                    all_masks = false;
                }
                else
                {
                    pattern_[i] = 0x00;
                    masks_[i] = '?';
                }
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
                fmt::print(
                    "{0:<32} - Got {1} results, Expected {2}\n", scanner.GetName(), shifted.size(), expected_.size());

            if (LOG_LEVEL > 3)
            {
                fmt::print("Got:\n");

                for (size_t v : shifted)
                    fmt::print("> 0x{0:X}\n", v);

                fmt::print("Expected:\n");

                for (size_t v : expected_)
                    fmt::print("> 0x{0:X}\n", v);
            }

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

static mem::cmd_param cmd_region_size {"size"};
static mem::cmd_param cmd_test_count {"tests"};
static mem::cmd_param cmd_rng_seed {"seed"};
static mem::cmd_param cmd_test_file {"file"};
static mem::cmd_param cmd_log_level {"loglevel"};
static mem::cmd_param cmd_full_scan {"full"};
static mem::cmd_param cmd_filter {"filter"};
static mem::cmd_param cmd_test_index {"test"};

int main(int argc, char** argv)
{
#if defined(_WIN32)
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
#endif

    mem::init_function::init();
    mem::cmd_param::init(argc, argv);

    LOG_LEVEL = cmd_log_level.get_or<size_t>(0);

    const char* filter = cmd_filter.get();

    if (filter)
    {
        fmt::print("Filter: {}\n", filter);

        auto iter = PATTERN_SCANNERS.begin();

        while (iter != PATTERN_SCANNERS.end())
        {
            const char* name = (*iter)->GetName();

            if (std::strstr(name, filter))
            {
                ++iter;
            }
            else
            {
                iter = PATTERN_SCANNERS.erase(iter);
            }
        }
    }

    if (PATTERN_SCANNERS.empty())
    {
        fmt::print("No Scanners\n");

        return 1;
    }

    uint32_t seed = 0;

    if (!cmd_rng_seed.get(seed))
    {
        seed = std::random_device {}();
    }

    scan_bench reg(seed);

    if (const char* file_name = cmd_test_file.get())
    {
        fmt::print("Scanning file: {}\n", file_name);

        reg.reset(file_name);
    }
    else
    {
        size_t region_size = cmd_region_size.get_or<size_t>(32 * 1024 * 1024);

        if (region_size == 0)
        {
            fmt::print("Invalid region size\n");

            std::abort();
        }

        fmt::print("Scanning random data\n");

        reg.reset(region_size);
    }

    const size_t test_count = cmd_test_count.get_or<size_t>(256);
    const bool skip_fails = !cmd_full_scan.get<bool>();

    const size_t test_index = cmd_test_index.get_or<size_t>(SIZE_MAX);

    fmt::print("Begin Scan: Seed: 0x{0:08X}, Size: 0x{1:X}, Tests: {2}, Skip Fails: {3}, Scanners: {4}\n", reg.seed(),
        reg.full_size(), test_count, skip_fails, PATTERN_SCANNERS.size());

    mem::execution_handler handler;

    for (size_t i = 0; i < test_count; ++i)
    {
        reg.generate();

        if (test_index != SIZE_MAX && i != test_index)
            continue;

        if (LOG_LEVEL > 0)
        {
            if (!(i % 25))
                fmt::print("{}/{}...\n", i, test_count);
        }

        for (auto& pattern : PATTERN_SCANNERS)
        {
            if (skip_fails && pattern->Failed != 0)
                continue;

            uint64_t start_clock = mem::rdtsc();

            try
            {
                std::vector<const byte*> results =
                    handler.execute([&] { return pattern->Scan(reg.pattern(), reg.masks(), reg.data(), reg.size()); });

                if (!reg.check_results(*pattern, results))
                {
                    if (LOG_LEVEL > 1)
                        fmt::print("{0:<32} - Failed test {1} ({2}, {3})\n", pattern->GetName(), i,
                            mem::as_hex({reg.pattern(), strlen(reg.masks())}), reg.masks());

                    pattern->Failed++;
                }
            }
            catch (const std::exception& ex)
            {
                if (LOG_LEVEL > 0)
                    fmt::print("{0:<32} - Failed test {1}: {2}\n", pattern->GetName(), i, ex.what());

                pattern->Failed++;
            }
            catch (...)
            {
                if (LOG_LEVEL > 0)
                    fmt::print("{0:<32} - Failed test {1} (Exception)\n", pattern->GetName(), i);

                pattern->Failed++;
            }

            uint64_t end_clock = mem::rdtsc();

            pattern->Elapsed += end_clock - start_clock;
        }
    }

    std::sort(PATTERN_SCANNERS.begin(), PATTERN_SCANNERS.end(),
        [](const std::unique_ptr<pattern_scanner>& lhs, const std::unique_ptr<pattern_scanner>& rhs) {
            if ((lhs->Failed != 0) != (rhs->Failed != 0))
                return lhs->Failed < rhs->Failed;

            return lhs->Elapsed < rhs->Elapsed;
        });

    fmt::print("End Scan\n\n");

    const uint64_t total_scan_length = static_cast<uint64_t>(reg.full_size()) * test_count;

    for (size_t i = 0; i < PATTERN_SCANNERS.size(); ++i)
    {
        const auto& pattern = *PATTERN_SCANNERS[i];

        fmt::print("{:<32} | ", pattern.GetName());

        if (skip_fails)
        {
            if (pattern.Failed)
            {
                fmt::print("failed");
            }
            else
            {
                fmt::print("{:>12} cycles = {:>6.3f} cycles/byte", pattern.Elapsed,
                    double(pattern.Elapsed) / total_scan_length);
            }
        }
        else
        {
            fmt::print("{:>12} cycles = {:>6.3f} cycles/byte | {} failed",
                pattern.Elapsed, double(pattern.Elapsed) / total_scan_length, pattern.Failed);
        }

        fmt::print("\n");
    }
}
