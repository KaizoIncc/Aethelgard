#include <gtest/gtest.h>
#include "PeerConnection.hpp"
#include "Message.hpp"
#include <thread>
#include <chrono>
#include <boost/asio.hpp>

using namespace p2p;

// -----------------------
// HELPER FUNCTION
// -----------------------
Message makeMessage(MessageType t = MessageType::PING, const string& payloadStr = "abc") {
    Message msg;
    msg.magic = NETWORK_MAGIC;
    msg.version = PROTOCOL_VERSION;
    msg.type = t;
    msg.payload = vector<uint8_t>(payloadStr.begin(), payloadStr.end());
    return msg;
}

// -----------------------
// BASIC TESTS
// -----------------------
TEST(PeerConnectionTest, PeerInfoAccess) {
    boost::asio::io_context io;
    auto pc = make_shared<PeerConnection>(io);

    PeerInfo pi;
    pi.host = "127.0.0.1";
    pi.port = 9000;

    pc->connectTo(pi);
    EXPECT_EQ(pc->peerInfo().host, "127.0.0.1");
    EXPECT_EQ(pc->peerInfo().port, 9000);
}

TEST(PeerConnectionTest, SetMessageHandler) {
    boost::asio::io_context io;
    auto pc = make_shared<PeerConnection>(io);

    bool called = false;
    pc->setMessageHandler([&called](const PeerInfo&, const Message&){
        called = true;
    });

    Message msg = makeMessage();
    pc->sendMessage(msg); // esto no ejecutará callback real porque socket no conectado
    EXPECT_FALSE(called); // callback aún no se llama
}

// -----------------------
// ASYNCHRONOUS LOOPBACK TEST
// -----------------------
/**
TEST(PeerConnectionTest, SendReceiveLoopback) {
    boost::asio::io_context io;

    // servidor en loopback
    tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 0));
    auto port = acceptor.local_endpoint().port();

    tcp::socket server_sock(io);  // Mismo io_context

    auto server_thread = thread([&](){
        acceptor.accept(server_sock);  // Ahora sí se ejecutará

        // leer mensaje
        vector<uint8_t> buf(1024);
        boost::system::error_code ec;
        size_t len = server_sock.read_some(boost::asio::buffer(buf), ec);
        EXPECT_GT(len, 0);
        EXPECT_FALSE(ec) << "Error reading: " << ec.message();
    });

    auto pc = make_shared<PeerConnection>(io);
    PeerInfo peer;
    peer.host = "127.0.0.1";
    peer.port = port;
    pc->connectTo(peer);

    // Ejecutar el io_context en el main thread
    io.run_for(chrono::milliseconds(100));  // Ejecutar por un tiempo

    // enviar mensaje
    Message msg = makeMessage(MessageType::TX, "test123");
    pc->sendMessage(msg);

    // Dar más tiempo para procesar
    io.run_for(chrono::milliseconds(100));

    server_thread.join();
}


// -----------------------
// STRESS TESTS
// -----------------------
TEST(PeerConnectionTest, StressSendManyMessages) {
    boost::asio::io_context io;

    tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 0));
    auto port = acceptor.local_endpoint().port();

    auto server_thread = thread([&](){
        boost::asio::io_context server_io;
        tcp::socket server_sock(server_io);
        acceptor.accept(server_sock);

        vector<uint8_t> buf(1024);
        for (int i = 0; i < 1000; ++i) {
            boost::system::error_code ec;
            size_t len = server_sock.read_some(boost::asio::buffer(buf), ec);
            if (ec) break;
            EXPECT_GT(len, 0);
        }
    });

    auto pc = make_shared<PeerConnection>(io);
    PeerInfo peer;
    peer.host = "127.0.0.1";
    peer.port = port;
    pc->connectTo(peer);
    this_thread::sleep_for(chrono::milliseconds(50));

    for (int i = 0; i < 1000; ++i) {
        Message msg = makeMessage(MessageType::TX, "msg" + to_string(i));
        pc->sendMessage(msg);
    }

    server_thread.join();
}
 */