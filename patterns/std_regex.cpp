#include "pattern_entry.h"

#include <regex>
#include <string>

struct std_regex_scanner : pattern_scanner
{
    virtual std::vector<const byte*> Scan(
        const byte* pattern, const char* mask, const byte* data, size_t length) const override
    {
        std::string pattern_str;

        static constexpr const char HexChars[] = "0123456789ABCDEF";

        for (size_t i = 0, len = strlen(mask); i < len; ++i)
        {
            if (mask[i] != '?')
            {
                pattern_str += "\\x";
                pattern_str += HexChars[pattern[i] >> 4];
                pattern_str += HexChars[pattern[i] & 0xF];
            }
            else
            {
                pattern_str += "[^]";
            }
        }

        std::regex pattern_reg(pattern_str, std::regex_constants::optimize);

        std::vector<const byte*> results;
        std::cmatch cm;

        for (size_t i = 0; i < length; i += cm.position() + 1)
        {
            if (!std::regex_search((const char*) data + i, (const char*) data + length, cm, pattern_reg))
                break;

            results.push_back(data + i + cm.position());
        }

        return results;
    }

    virtual const char* GetName() const override
    {
        return "std::regex";
    }
};

// REGISTER_PATTERN(std_regex_scanner);
