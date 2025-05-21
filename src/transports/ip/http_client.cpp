//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

//------------------------------------------------------------------------------
//
// Example: HTTP client, asynchronous
//
//------------------------------------------------------------------------------

#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>

#include "simpleio/transports/ip/http.hpp"

int main(int argc, char** argv) {
  // Check command line arguments.
  if (argc != 4 && argc != 5) {
    std::cerr << "Usage: http-client-async <host> <port> <target> [<HTTP "
                 "version: 1.0 or 1.1(default)>]\n"
              << "Example:\n"
              << "    http-client-async www.example.com 80 /\n"
              << "    http-client-async www.example.com 80 / 1.0\n";
    return EXIT_FAILURE;
  }

  auto options = simpleio::transports::ip::HttpOptions();
  options.method = boost::beast::http::verb::get;
  options.ip_address = std::string(argv[1]);
  options.port = static_cast<uint16_t>(std::atoi(argv[2]));
  options.target = std::string(argv[3]);
  options.version = (argc == 5) && !std::strcmp("1.0", argv[4])
                        ? simpleio::transports::ip::HttpVersion::V1_0
                        : simpleio::transports::ip::HttpVersion::V1_1;

  // The io_context is required for all I/O
  auto ioc = std::make_shared<boost::asio::io_context>();

  // Launch the asynchronous operation
  auto session = std::make_shared<simpleio::transports::ip::HttpClientSession>(
      ioc, options);
  using ServiceType = simpleio::Service<std::string, std::string, 2048, 2048>;

  class SimpleStringSerializer
      : public simpleio::SerializationStrategy<std::string> {
   public:
    std::string serialize(std::string const& entity) override {
      return entity;
    }

    std::string deserialize(std::string const& blob) override {
      return blob;
    }
  };

  auto client_sender =
      std::make_shared<simpleio::transports::ip::HttpClientSendStrategy>(
          session);
  auto client_receiver =
      std::make_shared<simpleio::transports::ip::HttpClientReceiveStrategy>(
          session);
  auto serializer = std::make_shared<SimpleStringSerializer>();
  auto response_cb = [](typename ServiceType::ResponseT const& response) {
    std::cout << "##############################################" << std::endl;
    std::cout << response.entity() << std::endl;
    std::cout << "##############################################" << std::endl;
  };
  auto client = std::make_shared<simpleio::Client<ServiceType>>(
      client_sender, client_receiver, serializer, response_cb);

  // put a timer around the send call
  // to ensure that the client is not blocked
  // for too long.
  auto req = typename ServiceType::RequestT("", serializer);

  // Get the starting timepoint
  auto start = std::chrono::high_resolution_clock::now();

  // Call the send method
  client->send(req);

  // Run the I/O service. The call will return when
  // the get operation is complete.
  ioc->run();

  // Get the ending timepoint
  auto end = std::chrono::high_resolution_clock::now();

  // Calculate the duration
  auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

  // Output the duration in milliseconds
  std::cout << "Operation took " << duration.count() << " milliseconds"
            << std::endl;

  return EXIT_SUCCESS;
}
