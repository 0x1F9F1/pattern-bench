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
#include <array>
#include <chrono>
#include <cmath>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#endif

#include <mem/mem.h>
#include <mem/pattern.h>
#include <mem/utils.h>

#include <mem/execution_handler.h>
#include <mem/protect.h>

#include <mem/init_function.h>

#include <mem/cmd_param-inl.h>
#include <mem/cmd_param.h>

#include <mem/data_buffer.h>

#include <fmt/format.h>

#include "pattern_entry.h"
#include "rdtsc.h"

static size_t LOG_LEVEL = 0;
static bool PATHOLOGICAL_MODE = false;
static std::string PATHOLOGICAL_CASE {"freq_anchor_near_miss"};

enum class data_mode
{
    random,
    synthetic_realistic,
};

static data_mode DATA_MODE = data_mode::random;

static const char* data_mode_name(data_mode mode)
{
    switch (mode)
    {
    case data_mode::random:
        return "random";
    case data_mode::synthetic_realistic:
        return "synthetic_realistic";
    }

    return "unknown";
}

static bool parse_data_mode(const char* value, data_mode& out)
{
    if (!value || std::strcmp(value, "random") == 0)
    {
        out = data_mode::random;
        return true;
    }

    if (std::strcmp(value, "synthetic_realistic") == 0)
    {
        out = data_mode::synthetic_realistic;
        return true;
    }

    return false;
}

enum class synthetic_corpus
{
    mixed,
    code,
    structured,
    text,
    padding,
    entropy,
};

static synthetic_corpus SYNTHETIC_CORPUS = synthetic_corpus::mixed;

static const char* synthetic_corpus_name(synthetic_corpus corpus)
{
    switch (corpus)
    {
    case synthetic_corpus::mixed:
        return "mixed";
    case synthetic_corpus::code:
        return "code";
    case synthetic_corpus::structured:
        return "structured";
    case synthetic_corpus::text:
        return "text";
    case synthetic_corpus::padding:
        return "padding";
    case synthetic_corpus::entropy:
        return "entropy";
    }

    return "unknown";
}

static bool parse_synthetic_corpus(const char* value, synthetic_corpus& out)
{
    if (!value || std::strcmp(value, "mixed") == 0)
    {
        out = synthetic_corpus::mixed;
        return true;
    }

    if (std::strcmp(value, "code") == 0)
    {
        out = synthetic_corpus::code;
        return true;
    }

    if (std::strcmp(value, "structured") == 0)
    {
        out = synthetic_corpus::structured;
        return true;
    }

    if (std::strcmp(value, "text") == 0)
    {
        out = synthetic_corpus::text;
        return true;
    }

    if (std::strcmp(value, "padding") == 0)
    {
        out = synthetic_corpus::padding;
        return true;
    }

    if (std::strcmp(value, "entropy") == 0)
    {
        out = synthetic_corpus::entropy;
        return true;
    }

    return false;
}

enum class bench_suite
{
    single,
    realistic,
    pathological,
    combined,
};

static bench_suite BENCH_SUITE = bench_suite::single;

static const char* bench_suite_name(bench_suite suite)
{
    switch (suite)
    {
    case bench_suite::single:
        return "single";
    case bench_suite::realistic:
        return "realistic";
    case bench_suite::pathological:
        return "pathological";
    case bench_suite::combined:
        return "combined";
    }

    return "unknown";
}

static bool parse_bench_suite(const char* value, bench_suite& out)
{
    if (!value || std::strcmp(value, "single") == 0)
    {
        out = bench_suite::single;
        return true;
    }

    if (std::strcmp(value, "realistic") == 0)
    {
        out = bench_suite::realistic;
        return true;
    }

    if (std::strcmp(value, "pathological") == 0)
    {
        out = bench_suite::pathological;
        return true;
    }

    if (std::strcmp(value, "combined") == 0)
    {
        out = bench_suite::combined;
        return true;
    }

    return false;
}

static const std::array<const char*, 8> PATHOLOGICAL_CASES {{
    "freq_anchor_near_miss",
    "bmh_shift1_periodic",
    "last_byte_flood",
    "high_overlap_matches",
    "wildcard_sparse_exact",
    "alternating_anchor_noise",
    "short_pattern_stress",
    "boundary_alignment",
}};

static const char* resolve_pathological_case(const std::string& name, size_t iteration)
{
    if (name == "all")
        return PATHOLOGICAL_CASES[iteration % PATHOLOGICAL_CASES.size()];

    return name.c_str();
}

#if defined(_WIN32)
struct core_pin_result
{
    bool pinned {false};
    WORD group {0};
    KAFFINITY mask {0};
    BYTE efficiency_class {0xFF};
};

static KAFFINITY pick_single_logical(KAFFINITY mask)
{
    return mask & (~mask + 1);
}

static core_pin_result pin_thread_to_preferred_core()
{
    core_pin_result result;

    DWORD buffer_size = 0;
    if (GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &buffer_size) == FALSE
        && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        return result;
    }

    if (!buffer_size)
        return result;

    std::vector<uint8_t> buffer(buffer_size);
    auto* info = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data());
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, info, &buffer_size))
        return result;

    BYTE best_efficiency = 0xFF;
    WORD best_group = 0;
    KAFFINITY best_mask = 0;

    const uint8_t* curr = buffer.data();
    const uint8_t* end = buffer.data() + buffer_size;
    while (curr < end)
    {
        const auto* entry = reinterpret_cast<const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(curr);
        if (entry->Relationship == RelationProcessorCore)
        {
            const PROCESSOR_RELATIONSHIP& proc = entry->Processor;
            const BYTE efficiency = proc.EfficiencyClass;
            for (WORD i = 0; i < proc.GroupCount; ++i)
            {
                const WORD group = proc.GroupMask[i].Group;
                const KAFFINITY group_mask = proc.GroupMask[i].Mask;
                if (!group_mask)
                    continue;

                const KAFFINITY logical = pick_single_logical(group_mask);
                if (!logical)
                    continue;

                if (!best_mask || efficiency < best_efficiency
                    || (efficiency == best_efficiency && (group < best_group || (group == best_group && logical < best_mask))))
                {
                    best_efficiency = efficiency;
                    best_group = group;
                    best_mask = logical;
                }
            }
        }

        curr += entry->Size;
    }

    if (!best_mask)
        return result;

    GROUP_AFFINITY affinity {};
    affinity.Group = best_group;
    affinity.Mask = best_mask;
    if (!SetThreadGroupAffinity(GetCurrentThread(), &affinity, nullptr))
    {
        if (best_group == 0)
        {
            if (!SetThreadAffinityMask(GetCurrentThread(), static_cast<DWORD_PTR>(best_mask)))
                return result;
        }
        else
        {
            return result;
        }
    }

    result.pinned = true;
    result.group = best_group;
    result.mask = best_mask;
    result.efficiency_class = best_efficiency;
    return result;
}
#endif

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

static uint64_t epoch_millis()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

static bool file_exists(const std::string& path)
{
    std::ifstream in(path.c_str(), std::ios::binary);
    return in.good();
}

static void ensure_directory_exists(const char* path)
{
#if defined(_WIN32)
    _mkdir(path);
#else
    mkdir(path, 0755);
#endif
}

static std::string json_escape(const std::string& in)
{
    std::string out;
    out.reserve(in.size() + 16);
    for (char c : in)
    {
        switch (c)
        {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            out.push_back(c);
            break;
        }
    }
    return out;
}

static std::string bytes_to_hex(const byte* data, size_t length)
{
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(length * 2);
    for (size_t i = 0; i < length; ++i)
    {
        const byte v = data[i];
        out.push_back(kHex[(v >> 4) & 0xF]);
        out.push_back(kHex[v & 0xF]);
    }
    return out;
}

static uint64_t fnv1a64(const byte* data, size_t length)
{
    uint64_t hash = 1469598103934665603ull;
    for (size_t i = 0; i < length; ++i)
    {
        hash ^= static_cast<uint64_t>(data[i]);
        hash *= 1099511628211ull;
    }
    return hash;
}

static std::string join_command_line(int argc, char** argv)
{
    std::string out;
    for (int i = 0; i < argc; ++i)
    {
        if (i)
            out += " ";

        const std::string arg = argv[i] ? argv[i] : "";
        if (arg.find(' ') != std::string::npos)
            out += "\"" + arg + "\"";
        else
            out += arg;
    }
    return out;
}

template <typename T>
static std::vector<T> sorted_values(const std::unordered_set<T>& values)
{
    std::vector<T> sorted(values.begin(), values.end());
    std::sort(sorted.begin(), sorted.end());
    return sorted;
}

template <typename T>
static std::string values_to_json_array(const std::vector<T>& values)
{
    std::ostringstream os;
    os << "[";
    for (size_t i = 0; i < values.size(); ++i)
    {
        if (i)
            os << ",";
        os << values[i];
    }
    os << "]";
    return os.str();
}

struct scan_bench;

class failure_logger
{
private:
    bool ready_ {false};
    bool opened_ {false};
    uint64_t start_epoch_ms_ {0};
    size_t failure_count_ {0};
    std::string command_line_;
    std::string dir_ {"failure_logs"};
    std::string log_path_;
    std::string session_start_line_;
    std::ofstream log_;

    void write_line(const std::string& line)
    {
        if (!opened_)
            return;
        log_ << line << "\n";
        log_.flush();
    }

    bool ensure_opened()
    {
        if (opened_)
            return true;

        if (!ready_ || log_path_.empty())
            return false;

        ensure_directory_exists(dir_.c_str());
        log_.open(log_path_.c_str(), std::ios::out | std::ios::binary);
        opened_ = log_.is_open();
        if (!opened_)
            return false;

        write_line(session_start_line_);
        return true;
    }

public:
    failure_logger(int argc, char** argv)
    {
        command_line_ = join_command_line(argc, argv);
        start_epoch_ms_ = epoch_millis();

        std::string candidate = fmt::format("{}/pattern-bench-failures-{}.jsonl", dir_, start_epoch_ms_);
        size_t attempt = 1;
        while (file_exists(candidate))
        {
            candidate = fmt::format("{}/pattern-bench-failures-{}-{}.jsonl", dir_, start_epoch_ms_, attempt++);
        }

        log_path_ = candidate;
        ready_ = true;
        session_start_line_ = fmt::format(
            "{{\"type\":\"session_start\",\"epoch_ms\":{},\"command\":\"{}\"}}", start_epoch_ms_,
            json_escape(command_line_));
    }

    ~failure_logger()
    {
        if (opened_)
        {
            write_line(fmt::format(
                "{{\"type\":\"session_end\",\"epoch_ms\":{},\"failure_count\":{}}}", epoch_millis(), failure_count_));
        }
    }

    bool ready() const
    {
        return ready_;
    }

    size_t failure_count() const
    {
        return failure_count_;
    }

    const std::string& log_path() const
    {
        return log_path_;
    }

    void log_failure(
        const char* run_label, size_t test_index, const char* scanner_name, const scan_bench& reg, const char* reason,
        const char* exception_text, const std::vector<size_t>* got_offsets, const std::vector<size_t>* expected_offsets);
};

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
    {
        auto make_sparse_pairless_case = [](const char* name, size_t length) {
            scanner_smoke_case out;
            out.name = name;
            out.data.assign(length, static_cast<byte>(0x11));
            out.pattern = {0x00, 0x00, 0xBE, 0x00, 0xD9};
            out.mask = "??x?x";
            for (size_t base = 0; (base + out.pattern.size()) <= out.data.size(); base += 64)
            {
                out.data[base + 2] = 0xBE;
                out.data[base + 4] = 0xD9;
            }
            return out;
        };

        // Repro sequence for sparse-mask warmup behavior seen in Pattern16:
        // 1024-byte run is stable, then the same sparse mask on 2048 bytes can degrade.
        cases.push_back(make_sparse_pairless_case("scanner_sparse_pairless_warmup_1024", 1024));
        cases.push_back(make_sparse_pairless_case("scanner_sparse_pairless_warmup_2048", 2048));
    }
    {
        scanner_smoke_case sparse_wrong_offset;
        sparse_wrong_offset.name = "scanner_sparse_pairless_wrong_first_offset_repro";
        sparse_wrong_offset.data.assign(2048, static_cast<byte>(0x11));
        sparse_wrong_offset.pattern = {0x96, 0x00, 0x00, 0x00, 0x00};
        sparse_wrong_offset.mask = "x????";

        for (size_t base = 0; (base + sparse_wrong_offset.pattern.size()) <= sparse_wrong_offset.data.size(); base += 64)
        {
            sparse_wrong_offset.data[base] = sparse_wrong_offset.pattern[0];
        }

        cases.push_back(sparse_wrong_offset);
    }
    {
        scanner_smoke_case sparse_false_negative;
        sparse_false_negative.name = "scanner_sparse_pairless_false_negative_repro";
        sparse_false_negative.data.resize(4699);
        sparse_false_negative.pattern = {
            0x00, 0x00, 0xF2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x57, 0x00, 0xB8, 0x00, 0x00, 0x00,
            0xD3, 0x00, 0x2C, 0x00, 0x4B, 0x00, 0x00, 0x00, 0x00, 0x19};
        sparse_false_negative.mask = "??x?????x?????x?x???x?x?x????x";

        for (size_t i = 0; i < sparse_false_negative.data.size(); ++i)
        {
            sparse_false_negative.data[i] = static_cast<byte>((i * 17u + 91u) & 0xFFu);
        }

        const size_t inject_offsets[] = {31, 440, 684, 1023, 1388, 2011, 2750, 3301, 4096};
        for (size_t off : inject_offsets)
        {
            if (off + sparse_false_negative.pattern.size() > sparse_false_negative.data.size())
                continue;

            for (size_t j = 0; j < sparse_false_negative.pattern.size(); ++j)
            {
                if (sparse_false_negative.mask[j] == 'x')
                    sparse_false_negative.data[off + j] = sparse_false_negative.pattern[j];
            }
        }

        cases.push_back(sparse_false_negative);
    }

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
    size_t pathological_iteration_ {0};

    byte random_byte()
    {
        return static_cast<byte>(rng_() & 0xFFu);
    }

    void fill_random_bytes(byte* out, size_t length)
    {
        for (size_t i = 0; i < length; ++i)
            out[i] = random_byte();
    }

    static void write_u32_le(byte* out, uint32_t value)
    {
        out[0] = static_cast<byte>((value >> 0) & 0xFFu);
        out[1] = static_cast<byte>((value >> 8) & 0xFFu);
        out[2] = static_cast<byte>((value >> 16) & 0xFFu);
        out[3] = static_cast<byte>((value >> 24) & 0xFFu);
    }

    static void write_u64_le(byte* out, uint64_t value)
    {
        out[0] = static_cast<byte>((value >> 0) & 0xFFu);
        out[1] = static_cast<byte>((value >> 8) & 0xFFu);
        out[2] = static_cast<byte>((value >> 16) & 0xFFu);
        out[3] = static_cast<byte>((value >> 24) & 0xFFu);
        out[4] = static_cast<byte>((value >> 32) & 0xFFu);
        out[5] = static_cast<byte>((value >> 40) & 0xFFu);
        out[6] = static_cast<byte>((value >> 48) & 0xFFu);
        out[7] = static_cast<byte>((value >> 56) & 0xFFu);
    }

    void fill_block_code_like(byte* out, size_t length)
    {
        static const byte single_ops[] = {
            0x55, 0x53, 0x56, 0x57, 0x5D, 0x5E, 0x5F, 0x90, 0xCC, 0xC3, 0xC2, 0xF3,
        };
        static const byte jcc_ops[] = {
            0x84, 0x85, 0x8C, 0x8D, 0x8E, 0x8F,
        };

        size_t pos = 0;
        while (pos < length)
        {
            const uint32_t roll = rng_() % 100u;
            if (roll < 22 && (pos + 1) <= length)
            {
                out[pos++] = single_ops[rng_() % (sizeof(single_ops) / sizeof(single_ops[0]))];
            }
            else if (roll < 44 && (pos + 5) <= length)
            {
                out[pos++] = static_cast<byte>(0xB8u + (rng_() % 8u)); // mov reg, imm32
                write_u32_le(out + pos, rng_());
                pos += 4;
            }
            else if (roll < 56 && (pos + 5) <= length)
            {
                out[pos++] = (rng_() & 1u) ? 0xE8 : 0xE9; // call/jmp rel32
                write_u32_le(out + pos, rng_());
                pos += 4;
            }
            else if (roll < 68 && (pos + 2) <= length)
            {
                out[pos++] = (rng_() & 1u) ? 0x8B : 0x89; // mov r/m, r
                out[pos++] = static_cast<byte>(0x40u + (rng_() % 0x40u));
            }
            else if (roll < 80 && (pos + 6) <= length)
            {
                out[pos++] = 0x0F;
                out[pos++] = jcc_ops[rng_() % (sizeof(jcc_ops) / sizeof(jcc_ops[0]))];
                write_u32_le(out + pos, rng_());
                pos += 4;
            }
            else
            {
                out[pos++] = random_byte();
            }
        }
    }

    void fill_block_structured(byte* out, size_t length)
    {
        size_t pos = 0;
        while (pos < length)
        {
            const uint32_t roll = rng_() % 100u;
            if (roll < 35 && (pos + 8) <= length)
            {
                // Pointer-like value in a typical 64-bit user-space range.
                const uint64_t v = 0x0000000140000000ull + (static_cast<uint64_t>(rng_()) & 0x0000000000FFFFFFull);
                write_u64_le(out + pos, v);
                pos += 8;
            }
            else if (roll < 60 && (pos + 4) <= length)
            {
                const uint32_t v = rng_() & 0x0000FFFFu;
                write_u32_le(out + pos, v);
                pos += 4;
            }
            else if (roll < 80 && (pos + 8) <= length)
            {
                static const uint64_t constants[] = {
                    0x0000000000000000ull,
                    0x0000000000000001ull,
                    0x00000000FFFFFFFFull,
                    0x3FF0000000000000ull,
                    0xBFF0000000000000ull,
                    0x7FF8000000000000ull,
                };
                write_u64_le(out + pos, constants[rng_() % (sizeof(constants) / sizeof(constants[0]))]);
                pos += 8;
            }
            else
            {
                out[pos++] = random_byte();
            }
        }
    }

    void fill_block_text_like(byte* out, size_t length)
    {
        static const char* words[] = {
            "section", "import", "runtime", "shader", "engine", "config", "version", "error",
            "memory", "window", "thread", "module", "render", "audio", "debug", "network",
        };
        size_t pos = 0;
        while (pos < length)
        {
            if ((rng_() % 100u) < 75u)
            {
                const char* word = words[rng_() % (sizeof(words) / sizeof(words[0]))];
                const size_t len = std::strlen(word);
                if ((pos + len + 1) <= length)
                {
                    std::memcpy(out + pos, word, len);
                    pos += len;
                    out[pos++] = ((rng_() % 10u) == 0u) ? '\n' : ' ';
                    continue;
                }
            }

            if ((rng_() % 100u) < 80u)
                out[pos++] = static_cast<byte>(0x20u + (rng_() % 0x5Fu)); // printable ascii
            else
                out[pos++] = 0x00;
        }
    }

    void fill_block_padding_like(byte* out, size_t length)
    {
        std::memset(out, 0, length);
        const size_t noise = (length / 64) + 1;
        for (size_t i = 0; i < noise; ++i)
            out[rng_() % length] = random_byte();
    }

    void fill_synthetic_realistic_region(byte* out, size_t length)
    {
        const size_t block_size = 4096;
        size_t w_code = 38;
        size_t w_structured = 28;
        size_t w_text = 13;
        size_t w_padding = 12;
        size_t w_entropy = 9;

        switch (SYNTHETIC_CORPUS)
        {
        case synthetic_corpus::mixed:
            break;
        case synthetic_corpus::code:
            w_code = 70;
            w_structured = 15;
            w_text = 5;
            w_padding = 5;
            w_entropy = 5;
            break;
        case synthetic_corpus::structured:
            w_code = 15;
            w_structured = 65;
            w_text = 5;
            w_padding = 10;
            w_entropy = 5;
            break;
        case synthetic_corpus::text:
            w_code = 10;
            w_structured = 20;
            w_text = 55;
            w_padding = 10;
            w_entropy = 5;
            break;
        case synthetic_corpus::padding:
            w_code = 5;
            w_structured = 15;
            w_text = 5;
            w_padding = 65;
            w_entropy = 10;
            break;
        case synthetic_corpus::entropy:
            w_code = 10;
            w_structured = 10;
            w_text = 5;
            w_padding = 5;
            w_entropy = 70;
            break;
        }

        const size_t t_code = w_code;
        const size_t t_structured = t_code + w_structured;
        const size_t t_text = t_structured + w_text;
        const size_t t_padding = t_text + w_padding;
        const size_t t_entropy = t_padding + w_entropy;

        for (size_t base = 0; base < length; base += block_size)
        {
            const size_t span = (std::min)(block_size, length - base);
            byte* block = out + base;
            const uint32_t roll = rng_() % 100u;

            if (roll < t_code)
                fill_block_code_like(block, span);
            else if (roll < t_structured)
                fill_block_structured(block, span);
            else if (roll < t_text)
                fill_block_text_like(block, span);
            else if (roll < t_padding)
                fill_block_padding_like(block, span);
            else if (roll < t_entropy)
                fill_random_bytes(block, span); // high-entropy chunk
            else
                fill_random_bytes(block, span);
        }

        // Add repeated chunks to mimic duplicated constants/tables/functions.
        if (length >= 512)
        {
            const size_t clone_count = (length / (256 * 1024)) + 4;
            for (size_t i = 0; i < clone_count; ++i)
            {
                size_t clone_len = 64 + (rng_() % 448u); // [64, 511]
                if (clone_len >= length)
                    clone_len = length - 1;

                const size_t src = rng_() % (length - clone_len);
                const size_t dst = rng_() % (length - clone_len);
                std::memmove(out + dst, out + src, clone_len);
            }
        }
    }

    size_t pick_realistic_pattern_length()
    {
        const uint32_t roll = rng_() % 100u;
        if (roll < 55u)
            return 6 + (rng_() % 7u); // 6..12
        if (roll < 85u)
            return 13 + (rng_() % 8u); // 13..20
        return 21 + (rng_() % 12u); // 21..32
    }

    double pick_realistic_wildcard_rate()
    {
        const uint32_t roll = rng_() % 100u;
        if (roll < 55u)
            return 0.08;
        if (roll < 85u)
            return 0.18;
        return 0.35;
    }

    byte pick_rarest_data_byte() const
    {
        std::array<size_t, 256> freq {};
        for (size_t i = 0; i < size_; ++i)
            ++freq[data_[i]];

        byte best = 0;
        size_t best_count = freq[0];
        for (size_t b = 1; b < 256; ++b)
        {
            if (freq[b] < best_count)
            {
                best = static_cast<byte>(b);
                best_count = freq[b];
            }
        }
        return best;
    }

    void generate_random_case()
    {
        std::uniform_int_distribution<uint32_t> byte_dist(0, 0xFF);
        std::uniform_int_distribution<size_t> length_dist(5, 32);

        size_t pattern_length = length_dist(rng_);
        pattern_.resize(pattern_length);
        masks_.resize(pattern_length);

        std::bernoulli_distribution mask_dist(0.9);
        bool all_masks = true;
        do
        {
            all_masks = true;
            for (size_t i = 0; i < pattern_length; ++i)
            {
                if (mask_dist(rng_))
                {
                    pattern_[i] = static_cast<byte>(byte_dist(rng_));
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
        const size_t result_count = count_dist(rng_);
        std::uniform_int_distribution<size_t> range_dist(0, size() - pattern_.size());

        for (size_t i = 0; i < result_count; ++i)
        {
            const size_t offset = range_dist(rng_);
            for (size_t j = 0; j < pattern_.size(); ++j)
            {
                if (masks_[j] != '?')
                    data_[offset + j] = pattern_[j];
            }
        }
    }

    void generate_synthetic_realistic_case()
    {
        size_t pattern_length = pick_realistic_pattern_length();
        if (pattern_length > size_)
            pattern_length = size_;

        pattern_.resize(pattern_length);
        masks_.resize(pattern_length);

        const size_t source_offset = rng_() % (size_ - pattern_length + 1);
        std::memcpy(pattern_.data(), data_ + source_offset, pattern_length);

        std::bernoulli_distribution wildcard_dist(pick_realistic_wildcard_rate());
        bool any_exact = false;
        std::vector<size_t> exact_positions;
        exact_positions.reserve(pattern_length);
        for (size_t i = 0; i < pattern_length; ++i)
        {
            if (wildcard_dist(rng_))
            {
                masks_[i] = '?';
                pattern_[i] = 0x00;
            }
            else
            {
                masks_[i] = 'x';
                any_exact = true;
                exact_positions.push_back(i);
            }
        }

        if (!any_exact)
        {
            const size_t force = rng_() % pattern_length;
            masks_[force] = 'x';
            pattern_[force] = data_[source_offset + force];
            exact_positions.push_back(force);
        }

        const size_t min_exact = (std::min)(static_cast<size_t>(4), pattern_length);
        while (exact_positions.size() < min_exact)
        {
            const size_t pos = rng_() % pattern_length;
            if (masks_[pos] == 'x')
                continue;
            masks_[pos] = 'x';
            pattern_[pos] = data_[source_offset + pos];
            exact_positions.push_back(pos);
        }

        std::array<bool, 256> seen {};
        size_t distinct_exact = 0;
        for (size_t pos : exact_positions)
        {
            const byte v = pattern_[pos];
            if (!seen[v])
            {
                seen[v] = true;
                ++distinct_exact;
            }
        }
        if (distinct_exact <= 1 && !exact_positions.empty())
        {
            const size_t pivot = exact_positions[rng_() % exact_positions.size()];
            pattern_[pivot] = pick_rarest_data_byte();
        }

        // Ensure at least one guaranteed true match in-buffer.
        for (size_t j = 0; j < pattern_length; ++j)
        {
            if (masks_[j] == 'x')
                data_[source_offset + j] = pattern_[j];
        }

        // Keep real hit density low-to-moderate.
        const size_t extra_hit_count = rng_() % 3u; // 0..2 additional hits
        for (size_t i = 0; i < extra_hit_count; ++i)
        {
            const size_t off = rng_() % (size_ - pattern_length + 1);
            for (size_t j = 0; j < pattern_length; ++j)
            {
                if (masks_[j] == 'x')
                    data_[off + j] = pattern_[j];
            }
        }

        // Add a few near-misses to prevent trivial always-hit streaks.
        if (!exact_positions.empty())
        {
            const size_t near_miss_count = rng_() % 3u; // 0..2 near misses
            for (size_t i = 0; i < near_miss_count; ++i)
            {
                const size_t off = rng_() % (size_ - pattern_length + 1);
                for (size_t j = 0; j < pattern_length; ++j)
                {
                    if (masks_[j] == 'x')
                        data_[off + j] = pattern_[j];
                }

                const size_t exact_j = exact_positions[rng_() % exact_positions.size()];
                data_[off + exact_j] ^= 0x01;
            }
        }
    }

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
            if (DATA_MODE == data_mode::synthetic_realistic)
                fill_synthetic_realistic_region(full_data_, full_size_);
            else
                fill_random_bytes(full_data_, full_size_);
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

    const std::unordered_set<size_t>& expected_offsets() const noexcept
    {
        return expected_;
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
        if (PATHOLOGICAL_MODE)
        {
            std::uniform_int_distribution<size_t> size_dist(0, 100);
            const size_t variation = size_dist(rng_);
            const size_t case_iteration = pathological_iteration_++;
            const char* pathological_case = resolve_pathological_case(PATHOLOGICAL_CASE, case_iteration);

            data_ = full_data_ + variation;
            size_ = full_size_ - variation;

            if (std::strcmp(pathological_case, "freq_anchor_near_miss") == 0)
            {
                // Degenerate case for frequency-anchor scanners:
                // every position looks like a "near hit" that only fails late.
                const byte anchor = 0x9A; // rank 0 in mem::simd_scanner default frequency table
                const size_t pattern_length = 32;
                const size_t mismatch_pos = 1;

                std::fill_n(data_, size_, anchor);

                pattern_.assign(pattern_length, anchor);
                masks_.assign(pattern_length, 'x');

                // Make pattern impossible in the all-anchor buffer while still matching
                // almost every byte position except this early check.
                pattern_[mismatch_pos] = static_cast<byte>(anchor ^ 0xFF);
            }
            else if (std::strcmp(pathological_case, "bmh_shift1_periodic") == 0)
            {
                const byte a = 0x41;
                const byte b = 0x42;
                const byte c = 0x43;
                std::fill_n(data_, size_, 0x00);
                for (size_t i = 0; i < size_; ++i)
                    data_[i] = (i & 1) ? b : a;

                pattern_ = {a, b, a, b, a, b, a, b, a, b, a, c};
                masks_.assign(pattern_.size(), 'x');
            }
            else if (std::strcmp(pathological_case, "last_byte_flood") == 0)
            {
                const byte tail = 0xE7;
                pattern_.resize(24);
                masks_.assign(pattern_.size(), 'x');

                for (size_t i = 0; i < (pattern_.size() - 1); ++i)
                    pattern_[i] = static_cast<byte>(0x11 + (i * 7));
                pattern_.back() = tail;

                std::fill_n(data_, size_, tail);
            }
            else if (std::strcmp(pathological_case, "high_overlap_matches") == 0)
            {
                const byte repeated = 0xAA;
                pattern_ = {repeated, repeated, repeated, repeated, repeated, repeated};
                masks_.assign(pattern_.size(), 'x');

                std::fill_n(data_, size_, static_cast<byte>(0x5A));
                for (size_t base = 0; (base + 8) <= size_; base += 128)
                {
                    std::fill_n(data_ + base, 8, repeated);
                }
            }
            else if (std::strcmp(pathological_case, "wildcard_sparse_exact") == 0)
            {
                const size_t len = 32;
                pattern_.assign(len, 0x00);
                masks_.assign(len, '?');

                pattern_[0] = 0xDE;
                pattern_[15] = 0xAD;
                pattern_[31] = 0xBE;
                masks_[0] = 'x';
                masks_[15] = 'x';
                masks_[31] = 'x';

                std::fill_n(data_, size_, static_cast<byte>(0x00));
                for (size_t base = 0; (base + len) <= size_; base += len)
                {
                    data_[base + 0] = 0xDE;
                    data_[base + 15] = 0xAD;
                    data_[base + 31] = 0xBF; // near-hit, fail on final exact byte
                }
            }
            else if (std::strcmp(pathological_case, "alternating_anchor_noise") == 0)
            {
                const byte anchor = 0x9A;
                pattern_.assign(24, anchor);
                masks_.assign(pattern_.size(), 'x');
                pattern_[12] = 0x77;

                for (size_t i = 0; i < size_; ++i)
                {
                    const bool anchor_block = ((i / 64) & 1) == 0;
                    data_[i] = anchor_block ? anchor : static_cast<byte>(0x10);
                }
            }
            else if (std::strcmp(pathological_case, "short_pattern_stress") == 0)
            {
                const size_t len = 1 + (case_iteration % 4);
                const byte p0 = 0xA5;
                const byte p1 = 0x5A;
                const byte p2 = 0xC3;
                const byte p3 = 0x3C;

                pattern_.assign(len, 0x00);
                masks_.assign(len, 'x');
                pattern_[0] = p0;
                if (len >= 2)
                    pattern_[1] = p1;
                if (len >= 3)
                    pattern_[2] = p2;
                if (len >= 4)
                    pattern_[3] = p3;

                if (len == 3)
                {
                    masks_[1] = '?';
                    pattern_[1] = 0x00;
                }
                else if (len == 4)
                {
                    masks_[2] = '?';
                    pattern_[2] = 0x00;
                }

                if (len == 1)
                {
                    std::fill_n(data_, size_, static_cast<byte>(p0 ^ 0x01));
                    for (size_t i = 0; i < size_; i += 128)
                        data_[i] = p0;
                }
                else if (len == 2)
                {
                    for (size_t i = 0; i < size_; ++i)
                        data_[i] = (i & 1) ? static_cast<byte>(0x00) : p0;
                }
                else if (len == 3)
                {
                    for (size_t i = 0; i < size_; ++i)
                    {
                        const size_t slot = i % 3;
                        if (slot == 0)
                            data_[i] = p0;
                        else if (slot == 1)
                            data_[i] = static_cast<byte>(0x7D);
                        else
                            data_[i] = static_cast<byte>(0x00);
                    }
                }
                else
                {
                    for (size_t i = 0; i < size_; ++i)
                    {
                        const size_t slot = i % 4;
                        if (slot == 0)
                            data_[i] = p0;
                        else if (slot == 1)
                            data_[i] = p1;
                        else if (slot == 2)
                            data_[i] = static_cast<byte>(0x7D);
                        else
                            data_[i] = static_cast<byte>(0x00);
                    }
                }
            }
            else if (std::strcmp(pathological_case, "boundary_alignment") == 0)
            {
                const size_t len = 32;
                pattern_.resize(len);
                masks_.assign(len, 'x');
                for (size_t i = 0; i < len; ++i)
                    pattern_[i] = static_cast<byte>(0x40 + i);

                std::fill_n(data_, size_, static_cast<byte>(0xEE));

                const size_t block = 64;
                const size_t starts[2] = {15, 31};
                for (size_t base = 0; base < size_; base += block)
                {
                    for (size_t k = 0; k < 2; ++k)
                    {
                        const size_t off = base + starts[k];
                        if ((off + len) > size_)
                            continue;

                        std::memcpy(data_ + off, pattern_.data(), len);
                        data_[off + len - 1] ^= 0x01; // late mismatch at boundary-heavy offsets
                    }
                }
            }

            expected_ = shift_results(FindPatternSimple(data(), size(), pattern(), masks()));
            return;
        }

        std::uniform_int_distribution<size_t> size_dist(0, 100);

        const size_t variation = size_dist(rng_);

        data_ = full_data_ + variation;
        size_ = full_size_ - variation;

        if (DATA_MODE == data_mode::synthetic_realistic)
        {
            const size_t max_expected_hits = (std::max)(static_cast<size_t>(2048), size_ / 8192);
            const size_t max_attempts = 12;
            for (size_t attempt = 0; attempt < max_attempts; ++attempt)
            {
                generate_synthetic_realistic_case();
                expected_ = shift_results(FindPatternSimple(data(), size(), pattern(), masks()));
                if (expected_.size() <= max_expected_hits)
                    return;
            }
        }
        else
            generate_random_case();

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

void failure_logger::log_failure(
    const char* run_label, size_t test_index, const char* scanner_name, const scan_bench& reg, const char* reason,
    const char* exception_text, const std::vector<size_t>* got_offsets, const std::vector<size_t>* expected_offsets)
{
    if (!ensure_opened())
        return;

    const size_t id = ++failure_count_;
    const size_t pattern_length = std::strlen(reg.masks());
    const std::string pattern_hex = bytes_to_hex(reg.pattern(), pattern_length);
    const std::string mask = reg.masks();
    const uint64_t data_hash = fnv1a64(reg.data(), reg.size());
    const std::string corpus_label = (DATA_MODE == data_mode::synthetic_realistic) ? synthetic_corpus_name(SYNTHETIC_CORPUS) : "off";

    std::string data_file = fmt::format("pattern-bench-failure-{}-{:06}.bin", start_epoch_ms_, id);
    std::string data_path = fmt::format("{}/{}", dir_, data_file);
    size_t attempt = 1;
    while (file_exists(data_path))
    {
        data_file = fmt::format("pattern-bench-failure-{}-{:06}-{}.bin", start_epoch_ms_, id, attempt++);
        data_path = fmt::format("{}/{}", dir_, data_file);
    }

    {
        std::ofstream out(data_path.c_str(), std::ios::binary | std::ios::out);
        if (out.is_open())
            out.write(reinterpret_cast<const char*>(reg.data()), static_cast<std::streamsize>(reg.size()));
    }

    const size_t max_offsets_logged = 2048;
    std::vector<size_t> got_sample;
    std::vector<size_t> expected_sample;
    const size_t got_count = got_offsets ? got_offsets->size() : 0;
    const size_t expected_count = expected_offsets ? expected_offsets->size() : 0;
    if (got_offsets)
    {
        const size_t n = (std::min)(got_offsets->size(), max_offsets_logged);
        got_sample.assign(got_offsets->begin(), got_offsets->begin() + n);
    }
    if (expected_offsets)
    {
        const size_t n = (std::min)(expected_offsets->size(), max_offsets_logged);
        expected_sample.assign(expected_offsets->begin(), expected_offsets->begin() + n);
    }
    const std::string got_json = values_to_json_array(got_sample);
    const std::string expected_json = values_to_json_array(expected_sample);
    const std::string exception_json = exception_text ? json_escape(exception_text) : "";

    std::ostringstream line;
    line << "{";
    line << "\"type\":\"failure\"";
    line << ",\"failure_index\":" << id;
    line << ",\"timestamp_ms\":" << epoch_millis();
    line << ",\"suite\":\"" << json_escape(bench_suite_name(BENCH_SUITE)) << "\"";
    line << ",\"run_label\":\"" << json_escape(run_label ? run_label : "") << "\"";
    line << ",\"scanner\":\"" << json_escape(scanner_name ? scanner_name : "") << "\"";
    line << ",\"reason\":\"" << json_escape(reason ? reason : "") << "\"";
    line << ",\"seed\":" << reg.seed();
    line << ",\"test_index\":" << test_index;
    line << ",\"data_mode\":\"" << json_escape(data_mode_name(DATA_MODE)) << "\"";
    line << ",\"corpus\":\"" << json_escape(corpus_label) << "\"";
    line << ",\"pathological\":" << (PATHOLOGICAL_MODE ? "true" : "false");
    line << ",\"pathological_case\":\"" << json_escape(PATHOLOGICAL_MODE ? PATHOLOGICAL_CASE : "off") << "\"";
    line << ",\"pattern_hex\":\"" << pattern_hex << "\"";
    line << ",\"mask\":\"" << json_escape(mask) << "\"";
    line << ",\"data_size\":" << reg.size();
    line << ",\"data_fnv1a64\":\"0x" << std::hex << std::uppercase << data_hash << std::dec << "\"";
    line << ",\"data_file\":\"" << json_escape(data_file) << "\"";
    line << ",\"got_count\":" << got_count;
    line << ",\"expected_count\":" << expected_count;
    line << ",\"offsets_truncated\":" << ((got_count > max_offsets_logged || expected_count > max_offsets_logged) ? "true" : "false");
    line << ",\"got_offsets\":" << got_json;
    line << ",\"expected_offsets\":" << expected_json;
    if (exception_text)
        line << ",\"exception\":\"" << exception_json << "\"";
    line << "}";

    write_line(line.str());
}

struct scanner_bench_result
{
    std::string name;
    uint64_t elapsed {0};
    uint64_t elapsed_ns {0};
    size_t failed {0};
    double cycles_per_byte {0.0};
    double gib_per_sec {0.0};
};

struct bench_run_summary
{
    std::string label;
    std::vector<scanner_bench_result> results;
};

static bool scanner_bench_result_less(const scanner_bench_result& lhs, const scanner_bench_result& rhs)
{
    if ((lhs.failed != 0) != (rhs.failed != 0))
        return lhs.failed < rhs.failed;
    return lhs.elapsed < rhs.elapsed;
}

static void reset_scanner_counters()
{
    for (auto& pattern : PATTERN_SCANNERS)
    {
        pattern->Elapsed = 0;
        pattern->ElapsedNs = 0;
        pattern->Failed = 0;
    }
}

static bench_run_summary run_benchmark(
    scan_bench& reg, size_t test_count, bool skip_fails, size_t test_index, const char* run_label, failure_logger& failures)
{
    reset_scanner_counters();

    const size_t progress_step = (test_count >= 20) ? (test_count / 20) : 1;
    const char* corpus_label = (DATA_MODE == data_mode::synthetic_realistic) ? synthetic_corpus_name(SYNTHETIC_CORPUS) : "off";

    fmt::print(
        "Begin Scan [{}]: Seed: 0x{:08X}, Size: 0x{:X}, Tests: {}, Skip Fails: {}, Scanners: {}, DataMode: {}, Corpus: {}, Pathological: {}, Case: {}\n",
        run_label, reg.seed(), reg.full_size(), test_count, skip_fails, PATTERN_SCANNERS.size(), data_mode_name(DATA_MODE),
        corpus_label, PATHOLOGICAL_MODE, PATHOLOGICAL_MODE ? PATHOLOGICAL_CASE : "off");

    mem::execution_handler handler;
    for (size_t i = 0; i < test_count; ++i)
    {
        reg.generate();

        if (test_index != SIZE_MAX && i != test_index)
            continue;

        if (LOG_LEVEL > 0 && test_index == SIZE_MAX)
        {
            if (!(i % progress_step) || (i + 1 == test_count))
                fmt::print("Benchmark progress [{}]: {}/{}\n", run_label, i + 1, test_count);
        }
        else if (LOG_LEVEL > 0 && test_index != SIZE_MAX && i == test_index)
        {
            fmt::print("Benchmark progress [{}]: running selected test {}/{}\n", run_label, i + 1, test_count);
        }

        for (auto& pattern : PATTERN_SCANNERS)
        {
            if (skip_fails && pattern->Failed != 0)
                continue;

            const auto start_time = std::chrono::steady_clock::now();
            const uint64_t start_clock = bench_rdtsc();

            try
            {
                std::vector<const byte*> results =
                    handler.execute([&] { return pattern->Scan(reg.pattern(), reg.masks(), reg.data(), reg.size()); });

                if (!reg.check_results(*pattern, results))
                {
                    const std::unordered_set<size_t> got_set = reg.shift_results(results);
                    const std::vector<size_t> got_sorted = sorted_values(got_set);
                    const std::vector<size_t> expected_sorted = sorted_values(reg.expected_offsets());
                    failures.log_failure(run_label, i, pattern->GetName(), reg, "mismatch", nullptr, &got_sorted, &expected_sorted);

                    if (LOG_LEVEL > 1)
                        fmt::print("{0:<32} - Failed test {1} ({2}, {3})\n", pattern->GetName(), i,
                            mem::as_hex({reg.pattern(), std::strlen(reg.masks())}), reg.masks());

                    pattern->Failed++;
                }
            }
            catch (const std::exception& ex)
            {
                const std::vector<size_t> expected_sorted = sorted_values(reg.expected_offsets());
                failures.log_failure(run_label, i, pattern->GetName(), reg, "exception", ex.what(), nullptr, &expected_sorted);

                if (LOG_LEVEL > 0)
                    fmt::print("{0:<32} - Failed test {1}: {2}\n", pattern->GetName(), i, ex.what());

                pattern->Failed++;
            }
            catch (...)
            {
                const std::vector<size_t> expected_sorted = sorted_values(reg.expected_offsets());
                failures.log_failure(run_label, i, pattern->GetName(), reg, "exception", "unknown", nullptr, &expected_sorted);

                if (LOG_LEVEL > 0)
                    fmt::print("{0:<32} - Failed test {1} (Exception)\n", pattern->GetName(), i);

                pattern->Failed++;
            }

            const uint64_t end_clock = bench_rdtsc();
            const auto end_time = std::chrono::steady_clock::now();

            pattern->Elapsed += end_clock - start_clock;
            pattern->ElapsedNs += static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count());
        }
    }

    bench_run_summary summary;
    summary.label = run_label;

    const uint64_t total_scan_length = static_cast<uint64_t>(reg.full_size()) * test_count;
    for (const auto& pattern : PATTERN_SCANNERS)
    {
        scanner_bench_result out;
        out.name = pattern->GetName();
        out.elapsed = pattern->Elapsed;
        out.elapsed_ns = pattern->ElapsedNs;
        out.failed = pattern->Failed;
        out.cycles_per_byte = double(pattern->Elapsed) / total_scan_length;
        if (pattern->ElapsedNs != 0)
        {
            const double total_gib = double(total_scan_length) / (1024.0 * 1024.0 * 1024.0);
            const double elapsed_sec = double(pattern->ElapsedNs) / 1000000000.0;
            out.gib_per_sec = total_gib / elapsed_sec;
        }
        summary.results.push_back(out);
    }

    std::sort(summary.results.begin(), summary.results.end(), scanner_bench_result_less);
    return summary;
}

static void print_run_summary(const bench_run_summary& summary, bool skip_fails)
{
    fmt::print("End Scan [{}]\n\n", summary.label);

    double best_perf = 0.0;
    bool best_set = false;

    for (size_t i = 0; i < summary.results.size(); ++i)
    {
        const scanner_bench_result& pattern = summary.results[i];

        if (!best_set && (!skip_fails || pattern.failed == 0))
        {
            best_perf = pattern.cycles_per_byte;
            best_set = true;
        }
        if (!best_set)
        {
            best_perf = pattern.cycles_per_byte;
            best_set = true;
        }
    }

    size_t name_width = 32;
    size_t elapsed_width = 12;
    size_t cpb_width = 6;
    size_t gib_width = 7;
    size_t norm_width = 5;

    for (size_t i = 0; i < summary.results.size(); ++i)
    {
        const scanner_bench_result& pattern = summary.results[i];
        name_width = (std::max)(name_width, pattern.name.size());

        if (skip_fails && pattern.failed)
            continue;

        elapsed_width = (std::max)(elapsed_width, fmt::format("{}", pattern.elapsed).size());
        cpb_width = (std::max)(cpb_width, fmt::format("{:.3f}", pattern.cycles_per_byte).size());
        gib_width = (std::max)(gib_width, fmt::format("{:.2f}", pattern.gib_per_sec).size());

        const double normalized_perf = (best_perf != 0.0) ? (pattern.cycles_per_byte / best_perf) : 0.0;
        norm_width = (std::max)(norm_width, fmt::format("{:.2f}", normalized_perf).size());
    }

    for (size_t i = 0; i < summary.results.size(); ++i)
    {
        const scanner_bench_result& pattern = summary.results[i];

        fmt::print("{:<{}} | ", pattern.name, name_width);

        const double normalized_perf = (best_perf != 0.0) ? (pattern.cycles_per_byte / best_perf) : 0.0;

        if (skip_fails && pattern.failed)
        {
            fmt::print("failed");
        }
        else
        {
            fmt::print("{:>{}} cycles = {:>{}.3f} cycles/byte | {:>{}.2f} GiB/s | {:>{}.2f}x", pattern.elapsed,
                elapsed_width, pattern.cycles_per_byte, cpb_width, pattern.gib_per_sec, gib_width, normalized_perf,
                norm_width);

            if (!skip_fails)
                fmt::print(" | {} failed", pattern.failed);
        }

        fmt::print("\n");
    }
}

struct aggregate_scanner_result
{
    std::string name;
    size_t pass_corpora {0};
    size_t fail_corpora {0};
    size_t total_failed_tests {0};
    double geomean_cycles_per_byte {0.0};
    double arithmetic_cycles_per_byte {0.0};
};

static bool aggregate_scanner_result_less(const aggregate_scanner_result& lhs, const aggregate_scanner_result& rhs)
{
    if ((lhs.fail_corpora != 0) != (rhs.fail_corpora != 0))
        return lhs.fail_corpora < rhs.fail_corpora;
    return lhs.geomean_cycles_per_byte < rhs.geomean_cycles_per_byte;
}

static void print_suite_aggregate(const std::vector<bench_run_summary>& runs, bool skip_fails, const char* title)
{
    struct aggregate_tmp
    {
        double sum_log_cpb {0.0};
        double sum_cpb {0.0};
        size_t cpb_count {0};
        size_t fail_corpora {0};
        size_t total_failed_tests {0};
    };

    std::unordered_map<std::string, aggregate_tmp> by_name;
    for (const bench_run_summary& run : runs)
    {
        for (const scanner_bench_result& scanner : run.results)
        {
            aggregate_tmp& agg = by_name[scanner.name];
            agg.total_failed_tests += scanner.failed;
            if (scanner.failed != 0)
            {
                agg.fail_corpora++;
                continue;
            }

            const double cpb = (scanner.cycles_per_byte > 0.0) ? scanner.cycles_per_byte : 1e-12;
            agg.sum_log_cpb += std::log(cpb);
            agg.sum_cpb += cpb;
            agg.cpb_count++;
        }
    }

    std::vector<aggregate_scanner_result> aggregate;
    aggregate.reserve(by_name.size());

    for (const auto& kv : by_name)
    {
        aggregate_scanner_result out;
        out.name = kv.first;
        out.fail_corpora = kv.second.fail_corpora;
        out.pass_corpora = kv.second.cpb_count;
        out.total_failed_tests = kv.second.total_failed_tests;
        if (kv.second.cpb_count != 0)
        {
            out.geomean_cycles_per_byte = std::exp(kv.second.sum_log_cpb / kv.second.cpb_count);
            out.arithmetic_cycles_per_byte = kv.second.sum_cpb / kv.second.cpb_count;
        }
        aggregate.push_back(out);
    }

    std::sort(aggregate.begin(), aggregate.end(), aggregate_scanner_result_less);

    fmt::print("\nAggregate {} Leaderboard ({} runs)\n\n", title, runs.size());

    double best_perf = 0.0;
    bool best_set = false;
    for (const aggregate_scanner_result& scanner : aggregate)
    {
        if (scanner.fail_corpora == 0)
        {
            best_perf = scanner.geomean_cycles_per_byte;
            best_set = true;
            break;
        }
    }
    if (!best_set && !aggregate.empty())
    {
        best_perf = aggregate.front().geomean_cycles_per_byte;
        best_set = true;
    }

    size_t name_width = 32;
    size_t geo_width = 6;
    size_t mean_width = 6;
    size_t norm_width = 5;

    for (size_t i = 0; i < aggregate.size(); ++i)
    {
        const aggregate_scanner_result& scanner = aggregate[i];
        name_width = (std::max)(name_width, scanner.name.size());

        if (skip_fails && scanner.fail_corpora != 0)
            continue;

        geo_width = (std::max)(geo_width, fmt::format("{:.3f}", scanner.geomean_cycles_per_byte).size());
        mean_width = (std::max)(mean_width, fmt::format("{:.3f}", scanner.arithmetic_cycles_per_byte).size());
        const double normalized = (best_set && best_perf != 0.0)
            ? (scanner.geomean_cycles_per_byte / best_perf)
            : 0.0;
        norm_width = (std::max)(norm_width, fmt::format("{:.2f}", normalized).size());
    }

    for (const aggregate_scanner_result& scanner : aggregate)
    {
        fmt::print("{:<{}} | ", scanner.name, name_width);

        if (skip_fails && scanner.fail_corpora != 0)
        {
            fmt::print("failed ({} / {} runs failed)", scanner.fail_corpora, runs.size());
        }
        else
        {
            const double normalized = (best_set && best_perf != 0.0)
                ? (scanner.geomean_cycles_per_byte / best_perf)
                : 0.0;
            fmt::print("geo {:>{}.3f} cpb | mean {:>{}.3f} cpb | {:>{}.2f}x", scanner.geomean_cycles_per_byte,
                geo_width, scanner.arithmetic_cycles_per_byte, mean_width, normalized, norm_width);
            if (!skip_fails)
            {
                fmt::print(" | {} / {} runs failed | {} failed tests", scanner.fail_corpora, runs.size(),
                    scanner.total_failed_tests);
            }
        }

        fmt::print("\n");
    }
}

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
static mem::cmd_param cmd_data_mode {"data_mode"};
static mem::cmd_param cmd_corpus {"corpus"};
static mem::cmd_param cmd_suite {"suite"};
static mem::cmd_param cmd_help {"help"};
static mem::cmd_param cmd_help_short {"h"};

static void apply_scanner_filter(const char* filter)
{
    if (!filter)
        return;

    fmt::print("Filter: {}\n", filter);

    auto iter = PATTERN_SCANNERS.begin();
    while (iter != PATTERN_SCANNERS.end())
    {
        const char* name = (*iter)->GetName();
        if (std::strstr(name, filter))
            ++iter;
        else
            iter = PATTERN_SCANNERS.erase(iter);
    }
}

static void print_help(const char* exe_name)
{
    const char* exe = exe_name ? exe_name : "pattern-bench.exe";

    fmt::print("Usage: {} [options]\n", exe);
    fmt::print("Options:\n");
    fmt::print("  --help, -h                         Show this help and exit\n");
    fmt::print("  --size <bytes>                     Region size (default: 33554432)\n");
    fmt::print("  --tests <N>                        Number of randomized tests (default: 256)\n");
    fmt::print("  --seed <u32>                       RNG seed (default: random_device)\n");
    fmt::print("  --file <path>                      Scan a file instead of generated region\n");
    fmt::print("  --filter <text>                    Run only scanners whose name contains text\n");
    fmt::print("  --full <true|false>                Keep running after failures (default: false)\n");
    fmt::print("  --test <index>                     Run a single generated test index\n");
    fmt::print("  --loglevel <N>                     0=minimal, 4=verbose mismatch dumps\n");
    fmt::print("  --skip_smoke                       Skip startup scanner smoke tests\n");
    fmt::print("  --smoke_only <true|false>          Run smoke tests and exit\n");
    fmt::print("  --smoke_fuzz <N>                   Randomized smoke cases (default: 32)\n");
    fmt::print("  --data_mode <random|synthetic_realistic>\n");
    fmt::print("  --corpus <mixed|code|structured|text|padding|entropy|all>\n");
    fmt::print("  --suite <single|realistic|pathological|combined>\n");
}

int main(int argc, char** argv)
{
#if defined(_WIN32)
    core_pin_result pin_result = pin_thread_to_preferred_core();
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
#endif

    mem::init_function::init();
    mem::cmd_param::init(argc, argv);

    if (cmd_help.get<bool>() || cmd_help_short.get<bool>())
    {
        print_help((argc > 0) ? argv[0] : "pattern-bench.exe");
        return 0;
    }

    LOG_LEVEL = cmd_log_level.get_or<size_t>(0);
    bool run_all_corpora = false;

    if (const char* suite_value = cmd_suite.get())
    {
        if (!parse_bench_suite(suite_value, BENCH_SUITE))
        {
            fmt::print("Invalid suite: {}\n", suite_value);
            fmt::print("Available suites: single, realistic, pathological, combined\n");
            return 1;
        }
    }

    if (const char* data_mode_value = cmd_data_mode.get())
    {
        if (!parse_data_mode(data_mode_value, DATA_MODE))
        {
            fmt::print("Invalid data mode: {}\n", data_mode_value);
            fmt::print("Available data modes: random, synthetic_realistic\n");
            return 1;
        }
    }
    if (const char* corpus_value = cmd_corpus.get())
    {
        if (std::strcmp(corpus_value, "all") == 0)
        {
            run_all_corpora = true;
        }
        else if (!parse_synthetic_corpus(corpus_value, SYNTHETIC_CORPUS))
        {
            fmt::print("Invalid corpus: {}\n", corpus_value);
            fmt::print("Available corpora: mixed, code, structured, text, padding, entropy, all\n");
            return 1;
        }
    }

    PATHOLOGICAL_MODE = false;
    PATHOLOGICAL_CASE = "off";

#if defined(_WIN32)
    if (pin_result.pinned)
    {
        if (LOG_LEVEL > 0)
        {
            fmt::print(
                "Pinned benchmark thread to group {} mask 0x{:X} (efficiency class {})\n", pin_result.group,
                static_cast<uint64_t>(pin_result.mask), static_cast<uint32_t>(pin_result.efficiency_class));
        }
    }
    else if (LOG_LEVEL > 0)
    {
        fmt::print("Failed to pin benchmark thread to a preferred core\n");
    }
#endif

    const char* filter = cmd_filter.get();
    apply_scanner_filter(filter);

    if (PATTERN_SCANNERS.empty())
    {
        if (filter)
            fmt::print("No scanners matched filter '{}'\n", filter);
        else
            fmt::print("No Scanners\n");

        return 1;
    }

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

    uint32_t seed = 0;

    if (!cmd_rng_seed.get(seed))
    {
        seed = std::random_device {}();
    }

    scan_bench reg(seed);
    failure_logger failures(argc, argv);
    if (failures.ready())
        fmt::print("Failure log file: {}\n", failures.log_path());
    else
        fmt::print("Failure log file: unavailable (failed to open)\n");

    const size_t test_count = cmd_test_count.get_or<size_t>(256);
    const bool skip_fails = !cmd_full_scan.get<bool>();
    const size_t test_index = cmd_test_index.get_or<size_t>(SIZE_MAX);
    const char* file_name = cmd_test_file.get();

    if (file_name)
    {
        if (BENCH_SUITE != bench_suite::single)
        {
            fmt::print("Suite '{}' does not support --file.\n", bench_suite_name(BENCH_SUITE));
            return 1;
        }

        fmt::print("Scanning file: {}\n", file_name);
        if (DATA_MODE != data_mode::random)
            fmt::print("Data mode '{}' ignored because --file is set\n", data_mode_name(DATA_MODE));

        reg.reset(file_name);
        const bench_run_summary summary = run_benchmark(reg, test_count, skip_fails, test_index, "file", failures);
        print_run_summary(summary, skip_fails);
        fmt::print("Failure records: {}\n", failures.failure_count());
        return 0;
    }

    const size_t region_size = cmd_region_size.get_or<size_t>(32 * 1024 * 1024);
    if (region_size == 0)
    {
        fmt::print("Invalid region size\n");
        return 1;
    }

    auto all_corpora = []() {
        std::vector<synthetic_corpus> out;
        out.push_back(synthetic_corpus::mixed);
        out.push_back(synthetic_corpus::code);
        out.push_back(synthetic_corpus::structured);
        out.push_back(synthetic_corpus::text);
        out.push_back(synthetic_corpus::padding);
        out.push_back(synthetic_corpus::entropy);
        return out;
    };

    auto run_realistic = [&](std::vector<bench_run_summary>& runs, bool force_all_corpora) {
        std::vector<synthetic_corpus> corpora;
        if (force_all_corpora || run_all_corpora || !cmd_corpus.get())
        {
            corpora = all_corpora();
        }
        else
        {
            corpora.push_back(SYNTHETIC_CORPUS);
        }

        fmt::print("Running suite '{}' with {} corpus profile(s)\n", bench_suite_name(BENCH_SUITE), corpora.size());

        for (size_t i = 0; i < corpora.size(); ++i)
        {
            SYNTHETIC_CORPUS = corpora[i];
            DATA_MODE = data_mode::synthetic_realistic;
            PATHOLOGICAL_MODE = false;
            PATHOLOGICAL_CASE = "off";

            fmt::print(
                "\nCorpus {}/{}: {}\n", i + 1, corpora.size(), synthetic_corpus_name(SYNTHETIC_CORPUS));
            fmt::print("Scanning {} data (corpus: {})\n", data_mode_name(DATA_MODE), synthetic_corpus_name(SYNTHETIC_CORPUS));

            reg.reset(region_size);

            const std::string run_label = fmt::format("corpus:{}", synthetic_corpus_name(SYNTHETIC_CORPUS));
            bench_run_summary summary = run_benchmark(reg, test_count, skip_fails, test_index, run_label.c_str(), failures);
            print_run_summary(summary, skip_fails);
            runs.push_back(std::move(summary));
        }
    };

    auto run_pathological = [&](std::vector<bench_run_summary>& runs) {
        fmt::print("Running suite '{}' with {} pathological case(s)\n", bench_suite_name(BENCH_SUITE), PATHOLOGICAL_CASES.size());

        for (size_t i = 0; i < PATHOLOGICAL_CASES.size(); ++i)
        {
            PATHOLOGICAL_MODE = true;
            PATHOLOGICAL_CASE = PATHOLOGICAL_CASES[i];
            DATA_MODE = data_mode::random;

            fmt::print("\nPathological {}/{}: {}\n", i + 1, PATHOLOGICAL_CASES.size(), PATHOLOGICAL_CASE);

            reg.reset(region_size);

            const std::string run_label = fmt::format("pathological:{}", PATHOLOGICAL_CASE);
            bench_run_summary summary = run_benchmark(reg, test_count, skip_fails, test_index, run_label.c_str(), failures);
            print_run_summary(summary, skip_fails);
            runs.push_back(std::move(summary));
        }

        PATHOLOGICAL_MODE = false;
        PATHOLOGICAL_CASE = "off";
    };

    if (BENCH_SUITE == bench_suite::single)
    {
        if (DATA_MODE == data_mode::synthetic_realistic)
            fmt::print("Scanning {} data (corpus: {})\n", data_mode_name(DATA_MODE), synthetic_corpus_name(SYNTHETIC_CORPUS));
        else
            fmt::print("Scanning {} data\n", data_mode_name(DATA_MODE));

        reg.reset(region_size);
        const bench_run_summary summary = run_benchmark(reg, test_count, skip_fails, test_index, "single", failures);
        print_run_summary(summary, skip_fails);
        fmt::print("Failure records: {}\n", failures.failure_count());
        return 0;
    }

    std::vector<bench_run_summary> runs;
    if (BENCH_SUITE == bench_suite::realistic)
    {
        run_realistic(runs, false);
        print_suite_aggregate(runs, skip_fails, "Realistic");
        fmt::print("Failure records: {}\n", failures.failure_count());
        return 0;
    }

    if (BENCH_SUITE == bench_suite::pathological)
    {
        run_pathological(runs);
        print_suite_aggregate(runs, skip_fails, "Pathological");
        fmt::print("Failure records: {}\n", failures.failure_count());
        return 0;
    }

    // combined
    fmt::print("Running suite '{}' (random + realistic + pathological)\n", bench_suite_name(BENCH_SUITE));

    PATHOLOGICAL_MODE = false;
    PATHOLOGICAL_CASE = "off";
    DATA_MODE = data_mode::random;
    fmt::print("\nBaseline run: random\n");
    reg.reset(region_size);
    {
        bench_run_summary summary = run_benchmark(reg, test_count, skip_fails, test_index, "baseline:random", failures);
        print_run_summary(summary, skip_fails);
        runs.push_back(std::move(summary));
    }

    run_realistic(runs, true);
    run_pathological(runs);
    print_suite_aggregate(runs, skip_fails, "Combined");
    fmt::print("Failure records: {}\n", failures.failure_count());
    return 0;
}
