#pragma once

#include <vector>
#include <string>
#include <sstream>
#include <cstdint>
#include <intrin.h>
#include <immintrin.h>

#include "../util.h"
#include "../pfreq.h"

#ifdef PATTERN16_64BIT
#include "x64/x64.h"
#include "x64/SSE.h"
#include "x64/AVX.h"
#else 
#error 32-bit compilation is not currently supported by Pattern16
#endif

namespace Pattern16 {
	namespace Impl {
		PATTERN16_NO_INLINE const void* scanRegion(const void* regionStart, const void* regionEnd, const SplitSignatureU8& signature) {
			const auto length = signature.first.size();
			const auto begin = reinterpret_cast<const uint8_t*>(regionStart);
			const auto end = reinterpret_cast<const uint8_t*>(regionEnd);
			if (!length || end < begin || static_cast<size_t>(end - begin) < length) return nullptr;

			const auto last = end - length;
			for (auto cur = begin; cur <= last; ++cur) {
				size_t i = 0;
				for (; i < length; ++i) {
					auto potential_match = static_cast<uint8_t>(cur[i] ^ signature.first[i]);
					if (potential_match & signature.second[i]) break;
				}
				if (i == length) return static_cast<const void*>(cur);
			}

			return nullptr;
		}

		alignas(64) inline constexpr const int8_t hexLookup[128] = {
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
			-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,91,-1,93,-1,-1,
			-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		};

		PATTERN16_NO_INLINE SplitSignatureU8 processSignatureString(const std::string& signature) {
			Impl::SplitSignatureU8 splitSignatureBytes{};
			auto& [sig, mask] = splitSignatureBytes;
			std::string byteStr;
			auto bit = -1;
			auto counter = 0;
			for (auto chr : signature) {
				if (chr >= 0) {
					if (chr == ' ');
					else if (chr == '[') bit = 0;
					else if (chr == ']') bit = -1;
					else {
						auto val = hexLookup[chr];
						if (bit < 0) {
							if ((++counter &= 1)) {
								sig.push_back(0);
								mask.push_back(0);
							}
							if (val >= 0) {
								sig.back() |= val << (counter << 2);
								mask.back() |= 0xF << (counter << 2);
							}
						}
						else {
							if (--bit < 0) {
								sig.push_back(0);
								mask.push_back(0);
								counter = 0;
								bit &= 7;
							}
							if (val >= 0) {
								sig.back() |= (val & 1) << bit;
								mask.back() |= 1 << bit;
							}
						}
					}
				}
			}
			return splitSignatureBytes;
		}

		template <typename T>
		PATTERN16_NO_INLINE auto processSignatureBytes(SplitSignatureU8 signature) {
			auto& signatureBytes = signature.first;
			auto& maskBytes = signature.second;
			auto new_size = alignUp<alignof(T)>(signatureBytes.size()) / sizeof(T);
			signatureBytes.resize(new_size * sizeof(T), 0);
			maskBytes.resize(new_size * sizeof(T), 0);
			SplitSignature<T> processed{ std::vector<T>(new_size), std::vector<T>(new_size) };
			std::memcpy((void*)processed.first.data(), (void*)signatureBytes.data(), signatureBytes.size());
			std::memcpy((void*)processed.second.data(), (void*)maskBytes.data(), maskBytes.size());
			return processed;
		}

		template <BMI_VERSION version>
		PATTERN16_NO_INLINE auto getSigStartPos(const SplitSignatureU8& signature, const Frequencies16& cache) {
			std::vector<uint16_t> frequencies(signature.first.size() - 1);
			int offset = 0;
			for (auto& fq : frequencies) {
				auto index = *reinterpret_cast<const uint16_t*>(signature.first.data() + offset);
				index = _pext_u32_BMI<version>(index, ~0b0001'0000'0000'0011);
				fq = cache[index];
				fq = *reinterpret_cast<const uint16_t*>(signature.second.data() + offset) != 0xFFFF ? 0xFFFF : fq;
				++offset;
			}
			return std::distance(frequencies.begin(), std::min_element(frequencies.begin(), frequencies.end()));
		}

		template <typename T, SSE_VERSION version = SSE4_1>
		PATTERN16_NO_INLINE const void* scanT(const void* regionStart, size_t regionSize, SplitSignatureU8& signature, const Frequencies16& frequencies) {
			if (signature.first.empty() || signature.first.size() > regionSize) return nullptr;

			const auto regionBegin = reinterpret_cast<const uint8_t*>(regionStart);
			const auto regionEnd = regionBegin + regionSize;

			auto alignedStart = alignUpCacheline(regionStart);
			if (reinterpret_cast<const uint8_t*>(alignedStart) > regionEnd) alignedStart = regionEnd;
			auto prefixEnd = reinterpret_cast<const uint8_t*>(alignedStart);
			const auto overlap = signature.first.size() - 1;
			if (prefixEnd + overlap < regionEnd) prefixEnd += overlap;
			else prefixEnd = regionEnd;

			if (auto address = scanRegion(regionStart, prefixEnd, signature)) return address;
			if (reinterpret_cast<const uint8_t*>(alignedStart) >= regionEnd) return nullptr;
			if (signature.first.size() < 2) return scanRegion(alignedStart, regionEnd, signature);

			size_t sigStartPos;
			std::array<int, 4> cpuInfo;
			{
				PATTERN16_CPUID_LEAF7(cpuInfo);
				if (PATTERN16_FEATURE_TEST(cpuInfo, PATTERN16_FEATURE_BMI2)) sigStartPos = getSigStartPos<BMI2>(signature, frequencies);
				else if (PATTERN16_FEATURE_TEST(cpuInfo, PATTERN16_FEATURE_BMI1)) sigStartPos = getSigStartPos<BMI1>(signature, frequencies);
				else sigStartPos = getSigStartPos<BMI_NONE>(signature, frequencies);
			}
			auto sig = processSignatureBytes<T>(signature);
			if constexpr (version == SSE4_1) return scanRegion(alignedStart, regionEnd, sigStartPos, 0, sig, sig.first.size());
			else return scanRegion<version>(alignedStart, regionEnd, sigStartPos, 0, sig, sig.first.size());
		}

		PATTERN16_NO_INLINE const void* scan(const void* regionStart, size_t regionSize, SplitSignatureU8& signature, const Frequencies16& frequencies) {
			if (regionSize <= 1024) {
				return scanRegion(regionStart, reinterpret_cast<const uint8_t*>(regionStart) + regionSize, signature);
			}

			std::array<int, 4> cpuInfo;
			PATTERN16_CPUID_LEAF7(cpuInfo);
			if (PATTERN16_FEATURE_TEST(cpuInfo, PATTERN16_FEATURE_AVX2)) {
				return scanT<__m256i>(regionStart, regionSize, signature, frequencies);
			}
			PATTERN16_CPUID_LEAF1(cpuInfo);
			if (PATTERN16_FEATURE_TEST(cpuInfo, PATTERN16_FEATURE_SSE4_1)) {
				return scanT<__m128i, SSE4_1>(regionStart, regionSize, signature, frequencies);
			}
			else if (PATTERN16_FEATURE_TEST(cpuInfo, PATTERN16_FEATURE_SSE2)) {
				return scanT<__m128i, SSE2>(regionStart, regionSize, signature, frequencies);
			}
			else {
				return scanT<uint64_t>(regionStart, regionSize, signature, frequencies);
			}
		}
	}
}
