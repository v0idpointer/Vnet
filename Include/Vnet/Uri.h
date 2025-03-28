/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_URI_H_
#define _VNETHTTP_URI_H_

#include <Vnet/Exports.h>

#include <string>
#include <string_view>
#include <cstdint>
#include <utility>
#include <optional>

namespace Vnet {

    /**
     * Represents a Uniform Resource Identifier (URI).
     */
    class VNETHTTPAPI Uri {

    private:
        std::optional<std::string> m_scheme;
        std::optional<std::string> m_userInfo;
        std::optional<std::string> m_host;
        std::optional<std::uint16_t> m_port;
        std::optional<std::string> m_path;
        std::optional<std::string> m_query;
        std::optional<std::string> m_fragment;

    public:

        /**
         * Constructs a new Uri object.
         */
        Uri(void);

        /**
         * Constructs a new Uri object by copying an existing one.
         * 
         * @param uri A Uri object to copy.
         */
        Uri(const Uri& uri);

        /**
         * Constructs a new Uri object by combining an absolute
         * and a relative Uri into one.
         * 
         * @param absolute An absolute URI.
         * @param relative A relative URI.
         * @exception std::invalid_argument - The 'absolute' parameter contains
         * a relative URI, or the 'relative' parameter contains an absolute URI.
         */
        Uri(const Uri& absolute, const Uri& relative);

        Uri(Uri&& uri) noexcept;
        virtual ~Uri(void);

        /**
         * Assigns the value from an existing Uri object to this object.
         * 
         * @param uri A Uri object to copy.
         */
        Uri& operator= (const Uri& uri);

        Uri& operator= (Uri&& uri) noexcept;

        /**
         * Compares this Uri object with another for equality.
         * 
         * @param uri A Uri.
         * @returns true if the Uri objects are equal; otherwise, false.
         */
        bool operator== (const Uri& uri) const;

    public:

        /**
         * Returns the URI scheme.
         * 
         * @returns An optional string.
         */
        const std::optional<std::string>& GetScheme(void) const;

        /**
         * Returns the username and password.
         * 
         * @returns An optional string.
         */
        const std::optional<std::string>& GetUserInfo(void) const;

        /**
         * Returns the hostname.
         * 
         * @returns An optional string.
         */
        const std::optional<std::string>& GetHost(void) const;

        /**
         * Returns the port number.
         * 
         * @returns An optional 16-bit unsigned integer.
         */
        const std::optional<std::uint16_t> GetPort(void) const;

        /**
         * Returns the path.
         * 
         * @returns An optional string.
         */
        const std::optional<std::string>& GetPath(void) const;

        /**
         * Returns the query string.
         * 
         * @returns An optional string.
         */
        const std::optional<std::string>& GetQuery(void) const;

        /**
         * Returns the fragment.
         * 
         * @returns An optional string.
         */
        const std::optional<std::string>& GetFragment(void) const;

        /**
         * Returns true if the URI is an absolute URI.
         * 
         * @returns A boolean.
         */
        bool IsAbsoluteUri(void) const;

        /**
         * Returns true if the URI is a relative URI.
         * 
         * @returns A boolean.
         */
        bool IsRelativeUri(void) const;

        /**
         * Returns the string representation of the URI.
         * 
         * @returns A string.
         */
        std::string ToString(void) const;

        /**
         * Splits the URI into two URIs.
         * 
         * @returns A pair of URIs, the first one is an absolute URI, and the second is a relative URI.
         */
        std::pair<std::optional<Uri>, Uri> Split(void) const;

    private:
        static bool ContainsInvalidCharacters(const std::string_view uri);
        static bool IsValidHostname(std::string_view hostname);
        static std::optional<Uri> ParseUri(std::string_view str, const bool exceptions);

    public:

        /**
         * Parses a URI.
         * 
         * @param str A string containing a URI.
         * @returns A Uri.
         * @exception std::invalid_argument - The 'str' parameter is an empty string.
         * @exception BadUriException - URI malformed.
         */
        static Uri Parse(const std::string_view str);

        /**
         * Tries to parse a URI.
         * 
         * @param str A string containing a URI.
         * @returns If successful, a Uri is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<Uri> TryParse(const std::string_view str);

        /**
         * Percent-encodes a string.
         * 
         * @param str A string to percent-encode.
         * @returns A percent-encoded string.
         */
        static std::string Encode(const std::string_view str);

        /**
         * Percent-encodes a string.
         * 
         * @param str A string to percent-encode.
         * @param encodePathDelimiters If true, path delimiters ('/') will be percent-encoded.
         * @returns A percent-encoded string.
         */
        static std::string Encode(const std::string_view str, const bool encodePathDelimiters);

        /**
         * Percent-decodes a string.
         * 
         * @param str A percent-encoded string.
         * @returns A percent-decoded string.
         * @exception BadUriException - Bad percent-encoding.
         */
        static std::string Decode(const std::string_view str);

        /**
         * Tries to percent-decode a string.
         * 
         * @param str A percent-encoded string.
         * @returns If successful, a percent-decoded string is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<std::string> TryDecode(const std::string_view str);

    };

}

#endif // _VNETHTTP_URI_H_