#ifndef BENCH_RDTSC_H
#define BENCH_RDTSC_H

#include <cstdint>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
#  if defined(_MSC_VER)
#    include <intrin.h>
#    pragma intrinsic(__rdtsc)
#  else
#    include <x86intrin.h>
#  endif
inline uint64_t bench_rdtsc() { return __rdtsc(); }
#elif defined(__aarch64__) || defined(_M_ARM64)
#  if defined(__APPLE__)
#    include <mach/mach_time.h>
inline uint64_t bench_rdtsc() { return mach_absolute_time(); }
#  else
inline uint64_t bench_rdtsc() {
    uint64_t val;
    asm volatile("mrs %0, cntvct_el0" : "=r"(val));
    return val;
}
#  endif
#else
#  include <chrono>
inline uint64_t bench_rdtsc() {
    return std::chrono::steady_clock::now().time_since_epoch().count();
}
#endif

#endif
