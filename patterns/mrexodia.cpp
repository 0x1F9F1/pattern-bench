// https://github.com/learn-more/findpattern-bench/blob/master/patterns/mrexodia_horspool.h

#include "pattern_entry.h"

// based on: https://en.wikipedia.org/wiki/Boyer%E2%80%93Moore%E2%80%93Horspool_algorithm

bool matches(const byte haystack_ch, const byte needle_ch, const byte wildcard)
{
    return needle_ch == wildcard || haystack_ch == needle_ch;
}

std::vector<const byte*> boyermoore_horspool_memmem(
    const byte* haystack, size_t hlen, const byte* needle, size_t nlen, const byte wildcard = '\0')
{
    size_t bad_char_skip[UCHAR_MAX + 1]; /* Officially called: bad character shift */

    /* Sanity checks on the parameters */
    if (nlen <= 0 || !haystack || !needle)
        return {};

    /* ---- Preprocess ---- */
    /* Initialize the table to default value */
    /* When a character is encountered that does not occur
     * in the needle, we can safely skip ahead for the whole
     * length of the needle.
     */
    for (size_t scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
    {
        bad_char_skip[scan] = nlen;
    }

    /* C arrays have the first byte at [0], therefore:
     * [nlen - 1] is the last byte of the array. */
    size_t last = nlen - 1;

    /* Then populate it with the analysis of the needle */
    for (size_t scan = 0; scan < last; scan = scan + 1)
    {
        byte needleByte = needle[scan];
        bad_char_skip[needleByte] = last - scan;
    }

    /* ---- Do the matching ---- */

    std::vector<const byte*> results;

    /* Search the haystack, while the needle can still be within it. */
    while (hlen >= nlen)
    {
        /* scan from the end of the needle */
        for (size_t scan = last; matches(haystack[scan], needle[scan], wildcard); scan = scan - 1)
        {
            if (scan == 0) /* If the first byte matches, we've found it. */
                results.push_back(haystack);
        }

        /* otherwise, we need to skip some bytes and start again.
        Note that here we are getting the skip value based on the last byte
        of needle, no matter where we didn't match. So if needle is: "abcd"
        then we are skipping based on 'd' and that value will be 4, and
        for "abcdd" we again skip on 'd' but the value will be only 1.
        The alternative of pretending that the mismatched character was
        the last character is slower in the normal case (E.g. finding
        "abcd" in "...azcd..." gives 4 by using 'd' but only
        4-2==2 using 'z'. */
        byte lastByte = haystack[last];
        hlen -= bad_char_skip[lastByte];
        haystack += bad_char_skip[lastByte];
    }

    return results;
}

struct mrexodia_pattern_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        return boyermoore_horspool_memmem(data, length, pattern, strlen(mask), 0);
    }

    virtual const char* GetName() const override
    {
        return "mrexodia (horspool)";
    }
};

REGISTER_PATTERN(mrexodia_pattern_scanner);
