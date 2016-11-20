//
// Copyright (c) 2013-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

// Test that header file is self-contained.
#include <beast/http/new_parser.hpp>

#include <beast/unit_test/suite.hpp>
#include <beast/test/string_istream.hpp>
#include <beast/test/string_ostream.hpp>
#include <beast/test/yield_to.hpp>
#include <beast/core/flat_streambuf.hpp>
#include <beast/core/streambuf.hpp>

namespace beast {
namespace http {

struct str_body
{
    using value_type = std::string;

    class reader
    {
        std::size_t len_ = 0;
        value_type& body_;

    public:
        template<bool isRequest, class Fields>
        reader(message<isRequest, str_body, Fields>& msg,
            boost::optional<std::uint64_t> content_length)
            : body_(msg.body)
        {
            if(content_length)
            {
                if(*content_length >
                        (std::numeric_limits<std::size_t>::max)())
                    throw std::domain_error{"Content-Length overflow"};
                body_.reserve(*content_length);
            }
        }

        boost::asio::mutable_buffers_1
        prepare(std::size_t n, error_code& ec)
        {
            body_.resize(len_ + n);
            return {&body_[len_], n};
        }

        void
        commit(std::size_t n, error_code& ec)
        {
            if(body_.size() > len_ + n)
                body_.resize(len_ + n);
            len_ = body_.size();
        }

        void
        finish(error_code& ec)
        {
            body_.resize(len_);
        }
    };
};

//------------------------------------------------------------------------------

template<class SyncReadStream, class DynamicBuffer,
    bool isRequest, class Body, class Fields>
void
new_read(SyncReadStream& stream, DynamicBuffer& dynabuf,
    message<isRequest, Body, Fields>& msg, error_code& ec)
{
    using boost::asio::buffer_copy;

    new_parser_v1<isRequest, Fields> p{msg};

    // Read and parse header
    if(dynabuf.size() == 0)
        goto do_read;
    for(;;)
    {
        {
            auto n = p.write(dynabuf.data(), ec);
            if(! ec)
            {
                dynabuf.consume(n);
                break;
            }
            if(ec != error::need_more)
                return;
            ec = {};
        }
    do_read:
        auto const len =
            read_size_helper(dynabuf, 65536);
        auto const bytes_transferred =
            stream.read_some(
                dynabuf.prepare(len) , ec);
        if(ec)
            return;
        dynabuf.commit(bytes_transferred);
    }
    typename Body::reader r{msg, p.content_length()};

    // Read and parse body
    while(! p.complete())
    {
        // maybe read chunk delimiter
        for(;;)
        {
            auto n = p.write(dynabuf.data(), ec);
            if(! ec)
            {
                dynabuf.consume(n);
                break;
            }
            if(ec != error::need_more)
                return;
            ec = {};
            auto const len =
                read_size_helper(dynabuf, 1024);
            auto const bytes_transferred =
                stream.read_some(
                    dynabuf.prepare(len), ec);
            if(ec)
                return;
            dynabuf.commit(bytes_transferred);
        }

        // copy body bytes in buffer
        p.write_body(r, dynabuf, ec);
        if(ec)
            return;

        // read remaining part of chunk
        auto const remain = p.remain();
        if(remain > 0)
        {
            auto const b = r.prepare(remain, ec);
            if(ec)
                return;
            auto const bytes_transferred =
                stream.read_some(b, ec);
            if(ec == boost::asio::error::eof)
            {
                ec = {};
                p.write_eof(ec);
                if(ec)
                    return;
                BOOST_ASSERT(p.complete());
            }
            else
            {
                if(ec)
                    return;
                r.commit(bytes_transferred, ec);
                if(ec)
                    return;
                p.consume(bytes_transferred);
            }
        }
    }
    r.finish(ec);
    if(ec)
        return;
}

/// Efficiently relay one HTTP message between two peers
template<
    bool isRequest,
    class InAsyncStream,
    class OutAsyncStream,
    class MessageTransformation>
void
relay(
    InAsyncStream& si,
    OutAsyncStream& so,
    error_code& ec,
    boost::asio::yield_context yield,
    MessageTransformation const& transform)
{
#if 0
    using namespace beast::http;
    parser_v1<isRequest> p;

    // read the incoming message headers
    for(;;)
    {
        // TODO skip async_read_some if parser already has the next set of headers
        auto const bytes_transferred =
            si.async_read_some(p.prepare(), yield[ec]);
        if(ec)
            return;
        p.commit_header(bytes_transferred, ec);
        if(ec == parse_error::need_more)
        {
            ec = {};
            continue;
        }
        if(ec)
            return;
        break;
    }

    // Create a new message by transforming the input message
    // At minimum this will remove Content-Length and apply Transfer-Encoding: chunked
    auto req = transform(p.get(), ec);
    if(ec)
        return;

    // send the header
    async_write(so, req, yield[ec]);
    if(ec)
        return;

    for(;;)
    {
        // TODO skip async_read_some if we already have body data
        // Read the next part of the body
        auto const bytes_transferred =
            si.async_read_some(p.prepare(), yield[ec]);
        if(ec)
            return;
        p.commit_body(bytes_transferred, ec);
        if(ec == parse_error::end_of_message)
            break;
        if(ec)
            return;

        // Forward this part of the body
        // p.body() removes any chunk encoding
        //
        if(buffer_size(p.body()) > 0)
        {
            async_write(so, chunk_encode(p.body()), yield[ec]);
            if(ec)
                return;
        }
    }

    // Copy promised trailer fields from incoming request
    // that are not already present in the outgoing response:
    //
    for(auto field : token_list{req.fields["Trailer"]})
        if(! req.contains(field))
            req.insert(field, p.get().fields[field]);

    // Send the final chunk, including any promised trailer fields
    //
    streambuf sb;
    write_final_chunk(sb, req);
    async_write(so, sb.data(), yield[ec]);
    if(ec)
        return;
#endif
}

//------------------------------------------------------------------------------

class new_parser_test
    : public beast::unit_test::suite
    , public beast::test::enable_yield_to
{
public:
    template<bool isRequest, class Pred>
    void
    testMatrix(std::string const& s, Pred const& pred)
    {
        beast::test::string_istream ss{get_io_service(), s};
        error_code ec;
    #if 0
        streambuf dynabuf;
    #else
        flat_streambuf dynabuf;
        dynabuf.reserve(1024);
    #endif
        message<isRequest, str_body, fields> m;
        new_read(ss, dynabuf, m, ec);
        if(! BEAST_EXPECTS(! ec, ec.message()))
            return;
        pred(m);
    }

    void
    testRead()
    {
        testMatrix<false>(
            "HTTP/1.0 200 OK\r\n"
            "Server: test\r\n"
            "\r\n"
            "*******",
            [&](message<false, str_body, fields> const& m)
            {
                BEAST_EXPECTS(m.body == "*******",
                    "body='" + m.body + "'");
            }
        );
        testMatrix<false>(
            "HTTP/1.0 200 OK\r\n"
            "Server: test\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\n"
            "*****\r\n"
            "2;a;b=1;c=\"2\"\r\n"
            "--\r\n"
            "0;d;e=3;f=\"4\"\r\n"
            "Expires: never\r\n"
            "MD5-Fingerprint: -\r\n"
            "\r\n",
            [&](message<false, str_body, fields> const& m)
            {
                BEAST_EXPECT(m.body == "*****--");
            }
        );
        testMatrix<false>(
            "HTTP/1.0 200 OK\r\n"
            "Server: test\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "*****",
            [&](message<false, str_body, fields> const& m)
            {
                BEAST_EXPECT(m.body == "*****");
            }
        );
        testMatrix<true>(
            "GET / HTTP/1.1\r\n"
            "User-Agent: test\r\n"
            "\r\n",
            [&](message<true, str_body, fields> const& m)
            {
            }
        );
        testMatrix<true>(
            "GET / HTTP/1.1\r\n"
            "User-Agent: test\r\n"
            "X: \t x \t \r\n"
            "\r\n",
            [&](message<true, str_body, fields> const& m)
            {
                BEAST_EXPECT(m.fields["X"] == "x");
            }
        );
    }

    struct transform
    {
        template<bool isRequest, class Fields>
        void
        operator()(
            header<isRequest, Fields>& msg, error_code& ec) const
        {
        }
    };

    void testRelay(yield_context yield)
    {
        std::string const s =
            "HTTP/1.0 200 OK\r\n"
            "Server: test\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\n"
            "*****\r\n"
            "2;a;b=1;c=\"2\"\r\n"
            "--\r\n"
            "0;d;e=3;f=\"4\"\r\n"
            "Expires: never\r\n"
            "MD5-Fingerprint: -\r\n"
            "\r\n";
        test::string_ostream os{get_io_service()};
        test::string_istream is{get_io_service(), s};
        error_code ec;
        relay<false>(is, os, ec, yield, transform{});
    }

    void run() override
    {
        testRead();
        yield_to(std::bind(
            &new_parser_test::testRelay,
                this, std::placeholders::_1));
        pass();
    }
};

BEAST_DEFINE_TESTSUITE(new_parser,http,beast);

} // http
} // beast
