/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNET_UTIL_STRING_H_
#define _VNET_UTIL_STRING_H_

#include <string>
#include <string_view>
#include <algorithm>
#include <cctype>
#include <vector>

/**
 * 
 * 
 * @param lhs
 * @param rhs
 * @returns
 */
inline bool EqualsIgnoreCase(const std::string_view lhs, const std::string_view rhs) {

    if (lhs.length() != rhs.length()) return false;

    return std::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end(), [] (char a, char b) -> bool {
        if ((a >= 0) && (a <= 0x7F)) a = std::tolower(a);
        if ((b >= 0) && (b <= 0x7F)) b = std::tolower(b);
        return (a == b);
    });

}

/**
 * 
 * 
 * @param begin
 * @param end
 */
inline void ToLowercase(const std::string::iterator begin, const std::string::iterator end) {
    
    std::transform(begin, end, begin, [] (const unsigned char ch) -> unsigned char {
        if ((ch >= 0) && (ch <= 0x7F)) return static_cast<unsigned char>(std::tolower(ch));
        return ch;
    });

}

/**
 * 
 * 
 * @param str
 * @returns
 */
inline std::string ToLowercase(const std::string_view str) {
    std::string s = std::string(str);
    ToLowercase(s.begin(), s.end());
    return s;
}

/**
 * 
 * 
 * @param begin
 * @param end
 */
inline void ToUppercase(const std::string::iterator begin, const std::string::iterator end) {

    std::transform(begin, end, begin, [] (const unsigned char ch) -> unsigned char {
        if ((ch >= 0) && (ch <= 0x7F)) return static_cast<unsigned char>(std::toupper(ch));
        return ch;
    });

}

/**
 * 
 * 
 * @param str
 * @returns
 */
inline std::string ToUppercase(const std::string_view str) {
    std::string s = std::string(str);
    ToUppercase(s.begin(), s.end());
    return s;
}

/**
 * 
 * 
 * @param str
 * @param prefix
 * @returns
 */
inline bool CaseInsensitiveStartsWith(const std::string_view str, const std::string_view prefix) {

    if (prefix.length() > str.length()) return false;

    return std::equal(prefix.begin(), prefix.end(), str.begin(), [] (char a, char b) -> bool {
        if ((a >= 0) && (a <= 0x7F)) a = std::tolower(a);
        if ((b >= 0) && (b <= 0x7F)) b = std::tolower(b);
        return (a == b);
    });

}

/**
 * 
 * 
 * @param str
 * @param suffix
 * @returns
 */
inline bool CaseInsensitiveEndsWith(const std::string_view str, const std::string_view suffix) {

    if (suffix.length() > str.length()) return false;

    return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin(), [] (char a, char b) -> bool {
        if ((a >= 0) && (a <= 0x7F)) a = std::tolower(a);
        if ((b >= 0) && (b <= 0x7F)) b = std::tolower(b);
        return (a == b);
    });

}

/**
 * 
 * 
 * @param str
 * @param delim
 * @returns
 */
inline std::vector<std::string> Split(std::string_view str, const char delim) {

    std::size_t pos = 0;
    std::vector<std::string> tokens = { };

    while ((pos = str.find(delim)) != std::string_view::npos) {
        tokens.emplace_back(std::string(str.substr(0, pos)));
        str = str.substr((pos + 1));
    }
    tokens.emplace_back(std::string(str));

    return tokens;
}

/**
 * 
 * 
 * @param str
 * @param delim
 * @returns
 */
inline std::vector<std::string> Split(std::string_view str, const std::string_view delim) {

    std::size_t pos = 0;
    std::vector<std::string> tokens = { };

    while ((pos = str.find(delim)) != std::string_view::npos) {
        tokens.emplace_back(std::string(str.substr(0, pos)));
        str = str.substr((pos + delim.length()));
    }
    tokens.emplace_back(std::string(str));

    return tokens;
}

/**
 * 
 * 
 * @param str
 * @param delim
 * @returns
 */
inline std::vector<std::string_view> SplitNonOwning(std::string_view str, const char delim) {
    
    std::size_t pos = 0;
    std::vector<std::string_view> tokens = { };

    while ((pos = str.find(delim)) != std::string_view::npos) {
        tokens.emplace_back(str.substr(0, pos));
        str = str.substr((pos + 1));
    }
    tokens.emplace_back(str);

    return tokens;
}

/**
 * 
 * 
 * @param str
 * @param delim
 * @returns
 */
inline std::vector<std::string_view> SplitNonOwning(std::string_view str, const std::string_view delim) {

    std::size_t pos = 0;
    std::vector<std::string_view> tokens = { };

    while ((pos = str.find(delim)) != std::string_view::npos) {
        tokens.emplace_back(str.substr(0, pos));
        str = str.substr((pos + delim.length()));
    }
    tokens.emplace_back(str);

    return tokens;
}

#endif // _VNET_UTIL_STRING_H_