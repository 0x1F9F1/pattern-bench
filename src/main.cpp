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
#include <algorithm>
#include <chrono>
#include <fstream>
#include <random>
#include <string>
#include <unordered_set>
#include <vector>

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

struct smoke_stats
{
    size_t passed {0};
    size_t failed {0};
};

static bool smoke_expect(smoke_stats& stats, bool condition, const char* name)
{
    if (condition)
    {
        ++stats.passed;
        return true;
    }

    ++stats.failed;
    if (LOG_LEVEL > 0)
        fmt::print("Smoke failed: {}\n", name);
    return false;
}

struct scanner_smoke_case
{
    std::string name;
    std::vector<byte> data;
    std::vector<byte> pattern;
    std::string mask;
};

static void print_offsets(const char* label, const std::unordered_set<size_t>& values)
{
    std::vector<size_t> sorted(values.begin(), values.end());
    std::sort(sorted.begin(), sorted.end());

    fmt::print("{}:", label);
    if (sorted.empty())
    {
        fmt::print(" <none>\n");
        return;
    }

    for (size_t v : sorted)
        fmt::print(" 0x{:X}", v);
    fmt::print("\n");
}

static std::unordered_set<size_t> to_offsets(
    const std::vector<const byte*>& results, const byte* base, size_t length, bool& in_range)
{
    std::unordered_set<size_t> out;
    in_range = true;

    for (const byte* result : results)
    {
        if (result < base || result >= (base + length))
        {
            in_range = false;
            continue;
        }

        out.emplace(static_cast<size_t>(result - base));
    }

    return out;
}

static bool run_scanner_case(
    smoke_stats& stats, mem::execution_handler& handler, const scanner_smoke_case& test_case)
{
    bool ok = true;

    const auto expected_raw = FindPatternSimple(
        test_case.data.data(), test_case.data.size(), test_case.pattern.data(), test_case.mask.c_str());

    bool expected_in_range = true;
    const auto expected = to_offsets(expected_raw, test_case.data.data(), test_case.data.size(), expected_in_range);
    ok &= smoke_expect(stats, expected_in_range, test_case.name.c_str());

    for (const auto& scanner : PATTERN_SCANNERS)
    {
        bool scanner_ok = true;
        bool got_in_range = true;
        std::unordered_set<size_t> got;
        const char* exception_text = nullptr;

        try
        {
            const auto results = handler.execute([&] {
                return scanner->Scan(
                    test_case.pattern.data(), test_case.mask.c_str(), test_case.data.data(), test_case.data.size());
            });

            got = to_offsets(results, test_case.data.data(), test_case.data.size(), got_in_range);

            if (!got_in_range || got.size() != expected.size())
            {
                scanner_ok = false;
            }
            else
            {
                for (const size_t v : expected)
                {
                    if (got.find(v) == got.end())
                    {
                        scanner_ok = false;
                        break;
                    }
                }
            }
        }
        catch (...)
        {
            scanner_ok = false;
            exception_text = "exception";
        }

        if (!scanner_ok && LOG_LEVEL > 0)
        {
            fmt::print("Scanner smoke failed: {} / {}\n", scanner->GetName(), test_case.name);
            if (!got_in_range)
                fmt::print("Result contained out-of-range pointer(s)\n");
            if (exception_text)
                fmt::print("Failure reason: {}\n", exception_text);

            fmt::print("Mask: {}\n", test_case.mask);
            fmt::print("Pattern: {}\n", mem::as_hex({test_case.pattern.data(), test_case.pattern.size()}));
            fmt::print("Buffer: {}\n", mem::as_hex({test_case.data.data(), test_case.data.size()}));
            print_offsets("Expected", expected);
            print_offsets("Got", got);
        }

        ok &= smoke_expect(stats, scanner_ok, test_case.name.c_str());
    }

    return ok;
}

static scanner_smoke_case make_case(
    const char* name, const std::initializer_list<byte>& data, const std::initializer_list<byte>& pattern, const char* mask)
{
    scanner_smoke_case out;
    out.name = name;
    out.data.assign(data.begin(), data.end());
    out.pattern.assign(pattern.begin(), pattern.end());
    out.mask = mask;
    return out;
}

static bool run_scanner_smoke_tests(size_t fuzz_cases)
{
    smoke_stats stats;
    mem::execution_handler handler;

    std::vector<scanner_smoke_case> cases;
    cases.push_back(make_case("scanner_exact_one", {0xAA, 0xBB, 0xCC, 0xDD}, {0xBB, 0xCC}, "xx"));
    cases.push_back(make_case("scanner_overlap", {0xAB, 0xAB, 0xAB, 0xAB, 0xAB}, {0xAB, 0xAB, 0xAB}, "xxx"));
    cases.push_back(make_case("scanner_leading_wildcard", {0x11, 0x22, 0x33, 0x44, 0x22, 0x33}, {0x00, 0x22, 0x33}, "?xx"));
    cases.push_back(make_case("scanner_trailing_wildcard", {0x10, 0x20, 0x30, 0x10, 0x20, 0x40}, {0x10, 0x20, 0x00}, "xx?"));
    cases.push_back(make_case("scanner_middle_wildcard", {0x55, 0xAA, 0x66, 0x55, 0xBB, 0x66}, {0x55, 0x00, 0x66}, "x?x"));
    cases.push_back(make_case("scanner_literal_zero", {0x11, 0x00, 0x22, 0x11, 0xFF, 0x22, 0x11, 0x00, 0x22}, {0x11, 0x00, 0x22}, "xxx"));
    cases.push_back(make_case("scanner_start_end", {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF}, {0xDE, 0xAD, 0xBE, 0xEF}, "xxxx"));
    cases.push_back(make_case("scanner_bmh_prefix_trap",
        {0x41, 0x42, 0x41, 0x42, 0x41, 0x42, 0x41, 0x42, 0x58, 0x41, 0x42, 0x41, 0x42, 0x41, 0x42, 0x41, 0x42, 0x59},
        {0x41, 0x42, 0x41, 0x42, 0x41, 0x42, 0x41, 0x42, 0x59}, "xxxxxxxxx"));
    cases.push_back(make_case("scanner_single_byte", {0x01, 0x02, 0x01, 0x01}, {0x01}, "x"));

    const size_t total_cases = cases.size() + fuzz_cases;
    size_t completed_cases = 0;

    for (const auto& test_case : cases)
    {
        run_scanner_case(stats, handler, test_case);
        ++completed_cases;
    }

    std::mt19937 rng(0xC0DEFACEu);
    std::uniform_int_distribution<size_t> data_len_dist(64, 512);
    std::uniform_int_distribution<size_t> pat_len_dist(3, 32);
    std::uniform_int_distribution<uint32_t> byte_dist(0, 0xFF);
    std::bernoulli_distribution wildcard_dist(0.2);
    std::uniform_int_distribution<size_t> inject_count_dist(0, 4);

    for (size_t i = 0; i < fuzz_cases; ++i)
    {
        scanner_smoke_case fuzz;
        fuzz.name = fmt::format("scanner_fuzz_{}", i);

        const size_t data_len = data_len_dist(rng);
        fuzz.data.resize(data_len);
        std::generate(fuzz.data.begin(), fuzz.data.end(), [&] { return static_cast<byte>(byte_dist(rng)); });

        size_t pat_len = pat_len_dist(rng);
        pat_len = (std::min)(pat_len, data_len);
        fuzz.pattern.resize(pat_len);
        fuzz.mask.resize(pat_len);

        bool any_solid = false;
        for (size_t j = 0; j < pat_len; ++j)
        {
            fuzz.pattern[j] = static_cast<byte>(byte_dist(rng));
            if (wildcard_dist(rng))
            {
                fuzz.mask[j] = '?';
                fuzz.pattern[j] = 0x00;
            }
            else
            {
                fuzz.mask[j] = 'x';
                any_solid = true;
            }
        }

        if (!any_solid)
        {
            size_t force = rng() % pat_len;
            fuzz.mask[force] = 'x';
            fuzz.pattern[force] = static_cast<byte>(byte_dist(rng));
        }

        if (data_len >= pat_len)
        {
            std::uniform_int_distribution<size_t> offset_dist(0, data_len - pat_len);
            const size_t inject_count = inject_count_dist(rng);
            for (size_t k = 0; k < inject_count; ++k)
            {
                const size_t off = offset_dist(rng);
                for (size_t j = 0; j < pat_len; ++j)
                {
                    if (fuzz.mask[j] == 'x')
                        fuzz.data[off + j] = fuzz.pattern[j];
                }
            }
        }

        run_scanner_case(stats, handler, fuzz);
        ++completed_cases;
    }

    fmt::print("Scanner smoke tests: {} passed, {} failed\n", stats.passed, stats.failed);
    return stats.failed == 0;
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
static mem::cmd_param cmd_skip_smoke {"skip_smoke"};
static mem::cmd_param cmd_smoke_only {"smoke_only"};
static mem::cmd_param cmd_smoke_fuzz {"smoke_fuzz"};

int main(int argc, char** argv)
{
#if defined(_WIN32)
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
#endif

    mem::init_function::init();
    mem::cmd_param::init(argc, argv);

    LOG_LEVEL = cmd_log_level.get_or<size_t>(0);

    if (!cmd_skip_smoke.get<bool>())
    {
        const size_t smoke_fuzz_cases = cmd_smoke_fuzz.get_or<size_t>(32);

        if (!run_scanner_smoke_tests(smoke_fuzz_cases))
        {
            fmt::print("Smoke test failed. Use --skip_smoke to bypass.\n");
            return 2;
        }
    }

    if (cmd_smoke_only.get<bool>())
    {
        fmt::print("Smoke-only mode complete.\n");
        return 0;
    }

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
    const size_t progress_step = (test_count >= 20) ? (test_count / 20) : 1;

    const size_t test_index = cmd_test_index.get_or<size_t>(SIZE_MAX);

    fmt::print("Begin Scan: Seed: 0x{0:08X}, Size: 0x{1:X}, Tests: {2}, Skip Fails: {3}, Scanners: {4}\n", reg.seed(),
        reg.full_size(), test_count, skip_fails, PATTERN_SCANNERS.size());

    mem::execution_handler handler;

    for (size_t i = 0; i < test_count; ++i)
    {
        reg.generate();

        if (test_index != SIZE_MAX && i != test_index)
            continue;

        if (LOG_LEVEL > 0 && test_index == SIZE_MAX)
        {
            if (!(i % progress_step) || (i + 1 == test_count))
                fmt::print("Benchmark progress: {}/{}\n", i + 1, test_count);
        }
        else if (LOG_LEVEL > 0 && test_index != SIZE_MAX && i == test_index)
        {
            fmt::print("Benchmark progress: running selected test {}/{}\n", i + 1, test_count);
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

    double best_perf = 0.0f;

    for (size_t i = 0; i < PATTERN_SCANNERS.size(); ++i)
    {
        const auto& pattern = *PATTERN_SCANNERS[i];

        fmt::print("{:<32} | ", pattern.GetName());

        double cycles_per_byte = double(pattern.Elapsed) / total_scan_length;

        if (i == 0)
            best_perf = cycles_per_byte;

        double normalized_perf = cycles_per_byte / best_perf;

        if (skip_fails && pattern.Failed)
        {
            fmt::print("failed");
        }
        else
        {
            fmt::print(
                "{:>12} cycles = {:>6.3f} cycles/byte | {:>5.2f}x", pattern.Elapsed, cycles_per_byte, normalized_perf);

            if (!skip_fails)
            {
                fmt::print(" | {} failed", pattern.Failed);
            }
        }

        fmt::print("\n");
    }
}
