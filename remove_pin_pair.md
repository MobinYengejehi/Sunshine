# What is PIN Pair system?
`PIN Pair` system is an strong security system for `Sunshine` game host server. This makes only authorized clients be able to connect to server. And its because this connection between client and server is too dangerous.

# How does PIN Pair system work?
When you start a `Sunshine` server on your host device, your server starts the `HTTP`,  `HTTPS` and `SOCKET` servers. These servers manage any request that comes from clients. When a client starts the `Moonlight` launcher to connect to the host, the launcher sends some requests to server and tries to establish a socket connection with your server. But the server won't let client to connect the system easily so it creates a response and sends it to client which says if the client is authorized or not. If the client authorized before it will be able to connect the `SOCKET` server but if it's not, server will generate a `PIN` code which has 4 digits and sends that to client. After that client launcher will show the `PIN` code to user and the user must give the code to `Server Admin` to be autherized by server.

# How to remove PIN Pair from Sunshine system?
This `PIN Pair` system located on `Sunshine/src/nvhttp.cpp` file. This file includes all `Sunshine`'s API system.
To disable this `PIN Pair` system from `Sunshine` server, we must do the following:

1. At first open the `Sunshine/src/nvhttp.cpp` file.
2. Look for the function which called `serverinfo`. This `API` function called when, client requests to see if the server lets it to connect to the `SOCKET` server or not.
3. At the beginning of the function a variable called `pair_status` is defined which contains `0`. To disable `PIN Pair` system all we have do is just settings that variable to `1`. This means any client which requests to server will be authorized and also will be able to connect to `SOCKET` server via `SOCKET` connections.
4. After that we must look for a function called `accept` at the same file. This function gets called when client socket requests to start session to communicate with server. At this function server will double-check if the client authorized or not. Then we must change the following code:
```cpp
if (verify && !verify(session->connection->socket->native_handle())) {
  this->write(session, on_verify_failed);
} else {
  this->read(session);
}
```

To:
```cpp
this->read(session);
```

Which will bypass the session verification check.

The final function definition must like be:

# Function: serverinfo
```cpp
  template<class T>
  void serverinfo(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response> response, std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    print_req<T>(request);

    int pair_status = 1; // disabling `PIN Pair` system.
    if constexpr (std::is_same_v<SunshineHTTPS, T>) {
      auto args = request->parse_query_string();
      auto clientID = args.find("uniqueid"s);

      if (clientID != std::end(args)) {
        pair_status = 1;
      }
    }

    auto local_endpoint = request->local_endpoint();

    pt::ptree tree;

    tree.put("root.<xmlattr>.status_code", 200);
    tree.put("root.hostname", config::nvhttp.sunshine_name);

    tree.put("root.appversion", VERSION);
    tree.put("root.GfeVersion", GFE_VERSION);
    tree.put("root.uniqueid", http::unique_id);
    tree.put("root.HttpsPort", net::map_port(PORT_HTTPS));
    tree.put("root.ExternalPort", net::map_port(PORT_HTTP));
    tree.put("root.MaxLumaPixelsHEVC", video::active_hevc_mode > 1 ? "1869449984" : "0");

    // Only include the MAC address for requests sent from paired clients over HTTPS.
    // For HTTP requests, use a placeholder MAC address that Moonlight knows to ignore.
    if constexpr (std::is_same_v<SunshineHTTPS, T>) {
      tree.put("root.mac", platf::get_mac_address(net::addr_to_normalized_string(local_endpoint.address())));
    } else {
      tree.put("root.mac", "00:00:00:00:00:00");
    }

    // Moonlight clients track LAN IPv6 addresses separately from LocalIP which is expected to
    // always be an IPv4 address. If we return that same IPv6 address here, it will clobber the
    // stored LAN IPv4 address. To avoid this, we need to return an IPv4 address in this field
    // when we get a request over IPv6.
    //
    // HACK: We should return the IPv4 address of local interface here, but we don't currently
    // have that implemented. For now, we will emulate the behavior of GFE+GS-IPv6-Forwarder,
    // which returns 127.0.0.1 as LocalIP for IPv6 connections. Moonlight clients with IPv6
    // support know to ignore this bogus address.
    if (local_endpoint.address().is_v6() && !local_endpoint.address().to_v6().is_v4_mapped()) {
      tree.put("root.LocalIP", "127.0.0.1");
    } else {
      tree.put("root.LocalIP", net::addr_to_normalized_string(local_endpoint.address()));
    }

    uint32_t codec_mode_flags = SCM_H264;
    if (video::last_encoder_probe_supported_yuv444_for_codec[0]) {
      codec_mode_flags |= SCM_H264_HIGH8_444;
    }
    if (video::active_hevc_mode >= 2) {
      codec_mode_flags |= SCM_HEVC;
      if (video::last_encoder_probe_supported_yuv444_for_codec[1]) {
        codec_mode_flags |= SCM_HEVC_REXT8_444;
      }
    }
    if (video::active_hevc_mode >= 3) {
      codec_mode_flags |= SCM_HEVC_MAIN10;
      if (video::last_encoder_probe_supported_yuv444_for_codec[1]) {
        codec_mode_flags |= SCM_HEVC_REXT10_444;
      }
    }
    if (video::active_av1_mode >= 2) {
      codec_mode_flags |= SCM_AV1_MAIN8;
      if (video::last_encoder_probe_supported_yuv444_for_codec[2]) {
        codec_mode_flags |= SCM_AV1_HIGH8_444;
      }
    }
    if (video::active_av1_mode >= 3) {
      codec_mode_flags |= SCM_AV1_MAIN10;
      if (video::last_encoder_probe_supported_yuv444_for_codec[2]) {
        codec_mode_flags |= SCM_AV1_HIGH10_444;
      }
    }
    tree.put("root.ServerCodecModeSupport", codec_mode_flags);

    auto current_appid = proc::proc.running();
    tree.put("root.PairStatus", pair_status);
    tree.put("root.currentgame", current_appid);
    tree.put("root.state", current_appid > 0 ? "SUNSHINE_SERVER_BUSY" : "SUNSHINE_SERVER_FREE");

    std::ostringstream data;

    pt::write_xml(data, tree);
    response->write(data.str());
    response->close_connection_after_response = true;
  }
```

# Function: accept
```cpp
  void accept() override {
    auto connection = create_connection(*io_service, context);

    acceptor->async_accept(connection->socket->lowest_layer(), [this, connection](const SimpleWeb::error_code &ec) {
      auto lock = connection->handler_runner->continue_lock();
      if (!lock) {
        return;
      }

      if (ec != SimpleWeb::error::operation_aborted) {
        this->accept();
      }

      auto session = std::make_shared<Session>(config.max_request_streambuf_size, connection);

      if (!ec) {
        boost::asio::ip::tcp::no_delay option(true);
        SimpleWeb::error_code ec;
        session->connection->socket->lowest_layer().set_option(option, ec);

        session->connection->set_timeout(config.timeout_request);
        session->connection->socket->async_handshake(boost::asio::ssl::stream_base::server, [this, session](const SimpleWeb::error_code &ec) {
          session->connection->cancel_timeout();
          auto lock = session->connection->handler_runner->continue_lock();
          if (!lock) {
            return;
          }
          if (!ec) {
            // if (verify && !verify(session->connection->socket->native_handle())) {
            //   this->write(session, on_verify_failed);
            // } else {
            //   this->read(session);
            // }

            this->read(session); // here we bypassed the session verification check!
          } else if (this->on_error) {
            this->on_error(session->request, ec);
          }
        });
      } else if (this->on_error) {
        this->on_error(session->request, ec);
      }
    });
  }
```
