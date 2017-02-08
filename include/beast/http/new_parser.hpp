//
// Copyright (c) 2013-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BEAST_HTTP_NEW_PARSER_HPP
#define BEAST_HTTP_NEW_PARSER_HPP

#include <beast/core/error.hpp>
#include <beast/http/fields.hpp>
#include <beast/http/message.hpp>
#include <beast/http/rfc7230.hpp>
#include <beast/http/string_body.hpp>
#include <beast/core/detail/ci_char_traits.hpp>
#include <beast/core/detail/clamp.hpp>
#include <beast/core/detail/type_traits.hpp>
#include <boost/algorithm/searching/boyer_moore.hpp>
#include <boost/asio/buffers_iterator.hpp>
#include <boost/version.hpp>
#include <algorithm>
#include <iterator>

namespace beast {
namespace http {

enum class error
{
    /** More input is necessary to continue parsing.
    */
    need_more = 1,

    /// The method is invalid.
    bad_method,

    /// The request-target is invalid.
    bad_path,

    /// The HTTP-version is invalid.
    bad_version,

    /// The status-code is invalid.
    bad_status,

    /// The reason-phrase is invalid.
    bad_reason,

    /// The field name is invalid.
    bad_field,

    /// The field value is invalid.
    bad_value,

    /// The Content-Length is invalid.
    bad_content_length,

    /// The Transfer-Encoding is invalid.
    bad_transfer_encoding,

    /// The chunk size is invalid.
    bad_chunk_size,

    /// The chunk extension is invalid.
    bad_chunk_extension,

    /// The chunk data is invalid.
    bad_chunk_data,

    /// Unexpected end of message
    short_read
};

} // http
} // beast

namespace boost {
namespace system {
template<>
struct is_error_code_enum<beast::http::error>
{
    static bool const value = true;
};
} // system
} // boost

namespace beast {
namespace http {

namespace detail {

class http_error_category : public error_category
{
public:
    const char*
    name() const noexcept override
    {
        return "http";
    }

    std::string
    message(int ev) const override
    {
        switch(static_cast<error>(ev))
        {
        default:
        case error::need_more: return "more input needed";
        case error::bad_method: return "bad method";
        case error::bad_path: return "bad path";
        case error::bad_version: return "bad version";
        case error::bad_status: return "bad status";
        case error::bad_reason: return "bad reason";
        case error::bad_field: return "bad field";
        case error::bad_value: return "bad value";
        case error::bad_content_length: return "bad Content-Length";
        case error::bad_transfer_encoding: return "bad Transfer-Encoding";
        case error::bad_chunk_size: return "bad chunk size";
        case error::bad_chunk_extension: return "bad chunk extension";
        case error::bad_chunk_data: return "bad chunk data";
        case error::short_read: return "unexpected end of message";
        }
    }

    error_condition
    default_error_condition(int ev) const noexcept override
    {
        return error_condition{ev, *this};
    }

    bool
    equivalent(int ev,
        error_condition const& condition
            ) const noexcept override
    {
        return condition.value() == ev &&
            &condition.category() == this;
    }

    bool
    equivalent(error_code const& error, int ev) const noexcept override
    {
        return error.value() == ev &&
            &error.category() == this;
    }
};

inline
error_category const&
get_http_error_category()
{
    static http_error_category const cat{};
    return cat;
}

} // detail

inline
error_code
make_error_code(error ev)
{
    return error_code{
        static_cast<std::underlying_type<error>::type>(ev),
            detail::get_http_error_category()};
}

//------------------------------------------------------------------------------

struct new_basic_parser_v1_base
{
    // any OCTET except CTLs and LWS
    static
    inline
    bool
    is_value_char(char c)
    {
        static std::array<bool, 256> constexpr tab = {{
            0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 0
            0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 16
            0, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 32
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 48
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 64
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 80
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 96
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 0, // 112
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 128
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 144
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 160
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 176
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 192
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 208
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 224
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1  // 240
        }};
        return tab[static_cast<std::uint8_t>(c)];
    }
};

template<class Iter, class Unsigned>
bool
parse_dec(Iter it, Iter last, Unsigned& v)
{
    if(! detail::is_digit(*it))
        return false;
    v = *it - '0';
    for(;;)
    {
        if(! detail::is_digit(*++it))
            break;
        auto const d = *it - '0';
        if(v > ((std::numeric_limits<
                Unsigned>::max)() - 10) / 10)
            return false;
        v = 10 * v + d;
    }
    return true;
}

template<class Iter, class Unsigned>
bool
parse_hex(Iter& it, Unsigned& v)
{
    auto d = detail::unhex(*it);
    if(d == -1)
        return false;
    v = d;
    for(;;)
    {
        d = detail::unhex(*++it);
        if(d == -1)
            break;
        if(v > ((std::numeric_limits<
                Unsigned>::max)() - 16) / 16)
            return false;
        v = 16 * v + d;
    }
    return true;
}

//------------------------------------------------------------------------------

template<
    bool isRequest,
    class Derived>
class new_basic_parser_v1
    : private new_basic_parser_v1_base
{
    static unsigned constexpr flagContentLength = 1;
    static unsigned constexpr flagChunked = 2;
    static unsigned constexpr flagUpgrade = 4;
    static unsigned constexpr flagHeader = 8;
    static unsigned constexpr flagDone = 16;
    static unsigned constexpr flagNextChunk = 32;
    static unsigned constexpr flagFinalChunk = 64;
    static unsigned constexpr flagSkipBody = 128;

    std::uint64_t len_ =
        (std::numeric_limits<std::uint64_t>::max)();
    std::uint32_t skip_ = 0;
    std::uint8_t f_ = 0;
    char* p_ = nullptr;

public:
    ~new_basic_parser_v1()
    {
        if(p_)
            delete[] p_;
    }

    /** Returns `true` if a complete message has been received.
    */
    bool
    done() const
    {
        return (f_ & flagDone) != 0;
    }

    /// Returns true if we have already received a complete header.
    bool
    have_header() const
    {
        return (f_ & flagHeader) != 0;
    }

    /** Returns the optional value of Content-Length if known.

        The return value is undefined until `on_header` is called.
    */
    boost::optional<std::uint64_t>
    content_length() const
    {
        if(! (f_ & flagContentLength))
            return boost::none;
        return len_;
    }

    /** Returns `true` if the message body is chunk encoded.

        The return value is undefined until `on_header` is called.
    */
    bool
    chunked() const
    {
        return f_ & flagChunked;
    }

    /** Returns the number of body bytes remaining in this chunk.
    */
    std::uint64_t
    remain() const
    {
        if(f_ & (flagContentLength | flagChunked))
            return len_;
        return 65536;
    }

    /** Returns `true` if eof is needed to determine the end of message.
    */
    bool
    needs_eof() const
    {
        return ! (f_ & (flagChunked + flagContentLength));
    }

    template<class ConstBufferSequence>
    std::size_t
    write(ConstBufferSequence const& buffers, error_code& ec)
    {
        using boost::asio::buffer_cast;
        using boost::asio::buffer_size;
        auto const it = buffers.begin();
        auto const last = buffers.end();
        if(it == last)
        {
            ec = error::need_more;
            return 0;
        }
        if(! (f_ & flagHeader))
        {
            if(std::next(it) == last)
            {
                auto const b = *it;
                return try_header(
                    buffer_cast<char const*>(b),
                    buffer_cast<char const*>(b) +
                        buffer_size(b), ec);
            }
            return try_header(buffers, ec);
        }
        if(! (f_ & flagChunked))
            return 0;
        //parse_chunked(buffer, ec);
        return 0;
    }

    /** Indicate that the end of stream is reached.
    */
    void
    write_eof(error_code& ec)
    {
        if(f_ & (flagContentLength | flagChunked))
        {
            if(! (f_ & flagDone))
            {
                ec = error::short_read;
                return;
            }
        }
        else
        {
            f_ |= flagDone;
        }
    }

    /** Transfer body octets from buffer to the reader
    */
    template<class Reader, class DynamicBuffer>
    void
    write_body(Reader& r,
        DynamicBuffer& dynabuf, error_code& ec)
    {
        using boost::asio::buffer_copy;
        auto const n = beast::detail::clamp(
            len_, dynabuf.size());
        auto const b = r.prepare(n, ec);
        if(ec)
            return;
        auto const len = buffer_copy(
            b, dynabuf.data(), n);
        r.commit(len, ec);
        if(ec)
            return;
        dynabuf.consume(len);
        if(f_ & flagContentLength)
        {
            len_ -= len;
            if(len_ == 0)
                f_ |= flagDone;
        }
        else if(f_ & flagChunked)
        {
            len_ -= len;
        }
    }

    /** Consume body bytes from the current chunk.
    */
    void
    consume(std::uint64_t n)
    {
        len_ -= n;
    }

private:
    inline
    Derived&
    impl()
    {
        return *static_cast<Derived*>(this);
    }

    static
    inline
    boost::string_ref
    str(char const* first, char const* last)
    {
        return {first, static_cast<
            std::size_t>(last - first)};
    }

    static
    inline
    bool
    is_print(char c)
    {
        return static_cast<unsigned char>(c-33) < 94;
    }

    static
    inline
    bool
    is_pathchar(char c)
    {
        // TEXT = <any OCTET except CTLs, and excluding LWS>
        static std::array<char, 256> constexpr tab = {{
            0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 0
            0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 16
            0, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 32
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 48
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 64
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 80
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 96
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 0, // 112
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 128
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 144
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 160
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 176
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 192
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 208
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 224
            1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1  // 240
        }};
        return tab[static_cast<std::uint8_t>(c)] != 0;
    }

    template<class Iter>
    static
    std::pair<Iter, Iter>
    find_crlf(Iter first, Iter last)
    {
        static char const pat[] = "\r\n";
        static boost::algorithm::boyer_moore<
            char const*> const bm{pat, pat+2};
    #if BOOST_VERSION >= 106200
        return bm(first, last);
    #else
        auto const it = bm(first, last);
        return {it, it+2};
    #endif
    }

    template<class Iter>
    static
    std::pair<Iter, Iter>
    find_2x_crlf(Iter first, Iter last)
    {
        static char const pat[] = "\r\n\r\n";
        static boost::algorithm::boyer_moore<
            char const*> const bm{pat, pat+4};
    #if BOOST_VERSION >= 106200
        return bm(first, last);
    #else
        auto const it = bm(first, last);
        return {it, it+4};
    #endif
    }

    static
    bool
    get_crlf(char const*& it)
    {
        if(*it != '\r')
            return false;
        if(*++it != '\n')
            return false;
        ++it;
        return true;
    }

    template<class F>
    static
    std::pair<char const*, char const*>
    get_token(char const*& it, F const& f)
    {
        auto const first = it;
        while(f(*it))
            ++it;
        if(*it != ' ')
            return { it, it };
        return { first, it };
    }

    static
    int
    get_version(char const*& it)
    {
        if(*it != 'H')
            return -1;
        if(*++it != 'T')
            return -1;
        if(*++it != 'T')
            return -1;
        if(*++it != 'P')
            return -1;
        if(*++it != '/')
            return -1;
        if(! detail::is_digit(*++it))
            return -1;
        int v = 10 * (*it - '0');
        if(*++it != '.')
            return -1;
        if(! detail::is_digit(*++it))
            return -1;
        v += *it++ - '0';
        return v;
    }

    static
    int
    get_status(char const*& it)
    {
        int v;
        if(! detail::is_digit(*it))
            return -1;
        v = 100 * (*it - '0');
        if(! detail::is_digit(*++it))
            return -1;
        v += 10 * (*it - '0');
        if(! detail::is_digit(*++it))
            return -1;
        v += (*it++ - '0');
        return v;
    }
    
    static
    boost::string_ref
    get_reason(char const*& it)
    {
        auto const first = it;
        while(*it != '\r')
        {
            if(! detail::is_text(*it))
                return {};
            ++it;
        }
        return {first, static_cast<
            std::size_t>(it - first)};
    }

    void
    parse_startline(char const*& it,
        error_code& ec, std::true_type)
    {
        // method
        {
            auto const t = get_token(it, &detail::is_tchar);
            if(t.first == t.second)
            {
                ec = error::bad_method;
                return;
            }
            impl().on_method(str(t.first, t.second), ec);
            if(ec)
                return;
            it = t.second + 1;
        }

        // path
        {
            auto const t = get_token(it, &is_pathchar);
            if(t.first == t.second)
            {
                ec = error::bad_path;
                return;
            }
            impl().on_path(str(t.first, t.second), ec);
            if(ec)
                return;
            it = t.second + 1;
        }

        // version
        auto const v = get_version(it);
        if(v < 0 || ! get_crlf(it))
        {
            ec = error::bad_version;
            return;
        }
        impl().on_version(v, ec);
        if(ec)
            return;
    }

    void
    parse_startline(char const*& it,
        error_code& ec, std::false_type)
    {
        // version
        {
            auto const v = get_version(it);
            if(v < 0 || *it != ' ')
            {
                ec = error::bad_version;
                return;
            }
            impl().on_version(v, ec);
            if(ec)
                return;
            ++it;
        }

        // status
        {
            auto const s = get_status(it);
            if( s < 0 || *it != ' ')
            {
                ec = error::bad_status;
                return;
            }
            impl().on_status(s, ec);
            if(ec)
                return;
            ++it;
        }

        // reason
        {
            auto const r = get_reason(it);
            if(r.empty() || ! get_crlf(it))
            {
                ec = error::bad_reason;
                return;
            }
            impl().on_reason(r, ec);
            if(ec)
                return;
        }
    }

    void
    parse_fields(char const*& it, error_code& ec)
    {
        for(;;)
        {
            if(*it == '\r')
            {
                if(*++it != '\n')
                {
                    ec = error::bad_field;
                    return;
                }
                ++it;
                return;
            }
            auto first = it;
            boost::string_ref name;
            for(;;)
            {
                if(*it == ':')
                {
                    name = str(first, it++);
                    break;
                }
                if(! detail::to_field_char(*it))
                {
                    ec = error::bad_field;
                    return;
                }
                ++it;
            }
            while(*it == ' ' || *it == '\t')
                ++it;
            first = it;
            auto last = it;
            for(;;)
            {
                if(*it == '\r')
                {
                    if(*++it != '\n')
                    {
                        ec = error::bad_field;
                        return;
                    }
                    ++it;
                    break;
                }
                if(is_value_char(*it))
                {
                    last = ++it;
                }
                else if(*it == ' ' || *it == '\t')
                {
                    ++it;
                }
                else
                {
                    ec = error::bad_value;
                    return;
                }
            }
            auto const value = str(first, last);
            handle_field(name, value, ec);
            if(ec)
                return;
            impl().on_field(name, str(first, last), ec);
            if(ec)
                return;
        }
    }

    void
    handle_field(boost::string_ref name, boost::string_ref value,
        error_code& ec)
    {
        // Content-Length
        if(beast::detail::ci_equal(name, "Content-Length"))
        {
            if(f_ & flagChunked)
            {
                ec = error::bad_content_length;
                return;
            }

            if(f_ & flagContentLength)
            {
                ec = error::bad_content_length;
                return;
            }

            std::uint64_t v;
            if(! parse_dec(value.begin(), value.end(), v))
            {
                ec = error::bad_content_length;
                return;
            }
            len_ = v;
            f_ |= flagContentLength;
            return;
        }

        // Connection
        if(beast::detail::ci_equal(name, "Connection"))
        {
            ec = {};
            return;
        }

        // Transfer-Encoding
        if(beast::detail::ci_equal(name, "Transfer-Encoding"))
        {
            if(f_ & flagContentLength)
            {
                ec = error::bad_transfer_encoding;
                return;
            }

            if(f_ & flagChunked)
            {
                ec = error::bad_transfer_encoding;
                return;
            }

            auto const v = token_list{value};
            auto const it = std::find_if(v.begin(), v.end(),
                [&](typename token_list::value_type const& s)
                {
                    return beast::detail::ci_equal(s, "chunked");
                });
            if(std::next(it) != v.end())
            {
                ec = error::bad_transfer_encoding;
                return;
            }
            f_ |= flagChunked;
            return;
        }
        if(beast::detail::ci_equal(name, "Upgrade"))
        {
            ec = {};
            return;
        }
        if(beast::detail::ci_equal(name, "Proxy-Connection"))
        {
            ec = {};
            return;
        }
    }

    template<class ConstBufferSequence>
    std::size_t
    try_header(
        ConstBufferSequence const& buffers, error_code& ec)
    {
        using boost::asio::buffer;
        using boost::asio::buffer_copy;
        using boost::asio::buffer_size;
        using boost::asio::buffers_begin;
        using boost::asio::buffers_end;
        auto const first = buffers_begin(buffers);
        auto const last = buffers_end(buffers);

        auto const result =
            find_2x_crlf(first + skip_, last);
        if(result.first == last)
        {
            if(first != last)
                skip_ = buffer_size(buffers) - 3;
            ec = error::need_more;
            return 0;
        }
        skip_ = 0;

        auto const n = result.second - first;
        p_ = new char[n];
        buffer_copy(buffer(p_, n), buffers);
        parse_header(p_, p_ + n, ec);
        // delete[] p_;  // ?
        // p_ = nullptr; // ?
        return n;
    }

    std::size_t
    try_header(
        char const* first, char const* last,
            error_code& ec)
    {
        auto const result =
            find_2x_crlf(first + skip_, last);
        if(result.first == last)
        {
            if(first != last)
                skip_ = (last - first) - 3;
            ec = error::need_more;
            return 0;
        }
        skip_ = 0;

        parse_header(first, result.second, ec);
        if(ec)
            return 0;
        return result.second - first;
    }

    void
    parse_header(
        char const* first, char const* last,
            error_code& ec)
    {
        auto it = first;
        parse_startline(it, ec,
            std::integral_constant<bool, isRequest>{});
        if(ec)
            return;
        parse_fields(it, ec);
        if(ec)
            return;
        if(it != last)
        {
            ec = error::bad_value;
            return;
        }
        impl().on_header(ec);
        if(ec)
            return;
        f_ |= flagHeader;
    }

    template<class ParseBuffer>
    void
    parse_chunked(
        ParseBuffer& buffer, error_code& ec)
    {
    /*
        chunked-body   = *chunk
                         last-chunk
                         trailer-part
                         CRLF

        chunk          = chunk-size [ chunk-ext ] CRLF
                         chunk-data CRLF
        chunk-size     = 1*HEXDIG
        last-chunk     = 1*("0") [ chunk-ext ] CRLF

        chunk-data     = 1*OCTET ; a sequence of chunk-size octets

        5;x=1;y=z\r\n

            <size> *(;<ext>) CRLF<data>CRLF
        
        CRLF<size> *(;<ext>) CRLF<data>CRLF

             1*("0") *(;<ext>) CRLF *(<trailer>CRLF) CRLF

        CRLF 1*("0") *(;<ext>) CRLF *(<trailer>CRLF) CRLF
    */

        using boost::asio::buffer_cast;
        if(f_ & flagNextChunk)
        {
            BOOST_ASSERT(skip_ == 0);
            auto const n = buffer.size();
            if(n < 2)
            {
                ec = error::need_more;
                return;
            }
            auto it = buffer_cast<
                char const*>(buffer.data());
            if(! get_crlf(it))
            {
                ec = error::bad_chunk_data;
                return;
            }
            buffer.consume(2);
            f_ &= ~flagNextChunk;
        }

        if(! (f_ & flagFinalChunk))
        {
            auto const n = buffer.size();
            auto const first = buffer_cast<
                char const*>(buffer.data());
            auto const last = first + n;
            auto const m =
                find_crlf(first + skip_, last);
            if(m.first == last)
            {
                if(n > 1)
                    skip_ = n - 1;
                ec = error::need_more;
                return;
            }

            auto it = first;
            std::uint64_t v;
            if(! parse_hex(it, v))
            {
                ec = error::bad_chunk_size;
                return;
            }
            skip_ = 0;

            if(v != 0)
            {
                if(*it == '\r')
                {
                    if(*++it != '\n')
                    {
                        ec = error::bad_chunk_size;
                        return;
                    }
                }
                else if(*it == ';')
                {
                    impl().on_chunk_extension(str(it, m.first), ec);
                    if(ec)
                        return;

                }
                else if(! get_crlf(it))
                {
                    ec = error::bad_chunk_size;
                    return;
                }
                len_ = v;
                f_ |= flagNextChunk;
                buffer.consume(static_cast<
                    std::size_t>(m.second - first));
            }
            else
            {
                buffer.consume(static_cast<
                    std::size_t>(it - first));
                f_ |= flagFinalChunk;
                goto final_chunk;
            }
        }
        else
        {
        final_chunk:
            auto const n = buffer.size();
            auto const first = buffer_cast<
                char const*>(buffer.data());
            auto const last = first + n;
            auto const m =
                find_2x_crlf(first + skip_, last);
            if(m.first == last)
            {
                if(n > 3)
                    skip_ = n - 3;
                ec = error::need_more;
                return;
            }

            auto it = first;
            if(*it == '\r')
            {
                if(*++it != '\n')
                {
                    ec = error::bad_chunk_size;
                    return;
                }
            }
            else if(*it == ';')
            {
                impl().on_chunk_extension(str(it, m.first), ec);
                if(ec)
                    return;

            }
            f_ |= flagDone;
        }
    }
};

//------------------------------------------------------------------------------

template<bool isRequest, class Fields>
class new_parser_v1
    : public new_basic_parser_v1<isRequest,
        new_parser_v1<isRequest, Fields>>
{
    header<isRequest, Fields>& m_;

public:
    /// The type of header this parser produces.
    using header_type =
        header<isRequest, Fields>;

    // Constructor
    new_parser_v1(
            header<isRequest, Fields>& m)
        : m_(m)
    {
    }

    /// Copy constructor (disallowed)
    new_parser_v1(new_parser_v1 const&) = delete;

    /// Move assignment (disallowed)
    new_parser_v1& operator=(new_parser_v1&&) = delete;

    /// Copy assignment (disallowed)
    new_parser_v1& operator=(new_parser_v1 const&) = delete;

    /** Returns the parsed header.

        Only valid if @ref complete would return `true`.
    */
    header_type const&
    get() const
    {
        return m_;
    }

    /** Returns the parsed header.

        Only valid if @ref complete would return `true`.
    */
    header_type&
    get()
    {
        return m_;
    }

private:
    friend class new_basic_parser_v1<isRequest, new_parser_v1>;

    void
    on_version(int v, error_code& ec)
    {
        m_.version = v;
    }

    void
    on_method(boost::string_ref const& s, error_code& ec)
    {
        m_.method = std::string(s.data(), s.size());
    }

    void
    on_path(boost::string_ref const& s, error_code& ec)
    {
        m_.url = std::string(s.data(), s.size());
    }

    void
    on_status(int s, error_code& ec)
    {
        m_.status = s;
    }

    void
    on_reason(boost::string_ref const& s, error_code& ec)
    {
        m_.reason = std::string(s.data(), s.size());
    }

    void
    on_field(boost::string_ref const& name, boost::string_ref value,
        error_code& ec)
    {
        m_.fields.insert(name, value);
    }

    void
    on_header(error_code& ec)
    {
    }

    void
    on_chunk_extension(boost::string_ref const& s, error_code& ec)
    {
    }
};

} // http
} // beast

#endif
