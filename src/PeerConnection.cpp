#include "PeerConnection.hpp"
#include <iostream>
#include "Message.hpp"

namespace p2p {

    PeerConnection::PeerConnection(boost::asio::io_context& ctx) : io(ctx), sock(ctx), headerBuf(4 + 1 + 1 + 8) {}

    PeerConnection::~PeerConnection() {
        boost::system::error_code ec;
        sock.close(ec);
    }

    tcp::socket& PeerConnection::socket() { return sock; }

    PeerInfo const& PeerConnection::peerInfo() const { return info; }

    void PeerConnection::setMessageHandler(MessageCallback cb) { onMessage = move(cb); }

    void PeerConnection::start() {
        // start read loop
        asyncReadHeader();
    }

    void PeerConnection::connectTo(const PeerInfo& peer) {
        info = peer;
        auto self = shared_from_this();
        tcp::resolver resolver(io);
        resolver.async_resolve(peer.host, to_string(peer.port),
            [this, self, peer](const boost::system::error_code& ec, tcp::resolver::results_type results){
                if (ec) {
                    // resolve failed
                    return;
                }
                boost::asio::async_connect(sock, results,
                    [this, self, peer](const boost::system::error_code& ec2, const tcp::endpoint&){
                        if (!ec2) {
                            info = peer;
                            start();
                        } else {
                            // connect failed
                        }
                    });
            });
    }

    void PeerConnection::asyncReadHeader() {
        auto self = shared_from_this();
        boost::asio::async_read(sock, boost::asio::buffer(headerBuf),
            [this, self](const boost::system::error_code& ec, size_t){
                if (ec) {
                    handleDisconnect();
                    return;
                }
                Message header;
                uint64_t payloadLen = 0;
                if (!parseMessageHeader(headerBuf, header, payloadLen)) {
                    // malformed header
                    handleDisconnect();
                    return;
                }
                asyncReadPayload(payloadLen);
            });
    }

    void PeerConnection::asyncReadPayload(uint64_t payloadLen) {
        // payload + checksum(4)
        const uint64_t total = payloadLen + 4;
        payloadBuf.resize(static_cast<size_t>(total));
        auto self = shared_from_this();
        boost::asio::async_read(sock, boost::asio::buffer(payloadBuf),
            [this, self, payloadLen](const boost::system::error_code& ec, size_t){
                if (ec) {
                    handleDisconnect();
                    return;
                }
                // reconstruct header + payload to validate crc
                vector<uint8_t> full;
                full.reserve(headerBuf.size() + payloadBuf.size());
                full.insert(full.end(), headerBuf.begin(), headerBuf.end());
                full.insert(full.end(), payloadBuf.begin(), payloadBuf.end());
                // checksum is last 4 bytes of full
                if (full.size() < 4) { handleDisconnect(); return; }
                uint32_t receivedCrc;
                memcpy(&receivedCrc, &full[full.size()-4], 4);
                uint32_t computed = crc32_buf(full.data(), full.size()-4);
                if (receivedCrc != computed) {
                    // corrupted
                    handleDisconnect();
                    return;
                }
                // parse header to get Message header info and payloadLen
                Message headerMsg;
                uint64_t payloadLen = 0;
                if (!parseMessageHeader(headerBuf, headerMsg, payloadLen)) { handleDisconnect(); return; }

                // payload portion (copy from payloadBuf[0..payloadLen-1])
                vector<uint8_t> payload;
                if (payloadLen) payload.assign(payloadBuf.begin(), payloadBuf.begin() + static_cast<size_t>(payloadLen));

                headerMsg.payload = move(payload);
                // call callback
                if (onMessage) {
                    try { onMessage(info, headerMsg); }
                    catch (...) {}
                }
                // continue reading
                asyncReadHeader();
            });
    }

    void PeerConnection::sendRaw(const vector<uint8_t>& buf) {
        auto self = shared_from_this();
        // protect concurrent writes on same socket
        lock_guard<mutex> g(writeMtx);
        boost::asio::async_write(sock, boost::asio::buffer(buf),
            [this, self](const boost::system::error_code& ec, size_t){
                if (ec) {
                    handleDisconnect();
                }
            });
    }

    void PeerConnection::sendMessage(const Message& msg) {
        auto buf = serializeMessage(msg);
        sendRaw(buf);
    }

    void PeerConnection::handleDisconnect() {
        boost::system::error_code ec;
        sock.shutdown(tcp::socket::shutdown_both, ec);
        sock.close(ec);
        // on close the P2PNode should remove this connection (done externally)
    }

} // namespace p2p
