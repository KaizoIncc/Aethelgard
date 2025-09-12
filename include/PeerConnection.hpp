#pragma once
#ifndef P2P_PEER_CONNECTION_HPP
#define P2P_PEER_CONNECTION_HPP

#include "Peer.hpp"
#include "Message.hpp"
#include <boost/asio.hpp>
#include <functional>
#include <memory>
#include <vector>
#include <mutex>

using namespace std;

namespace p2p {
using tcp = boost::asio::ip::tcp;

class PeerConnection : public enable_shared_from_this<PeerConnection> {
public:
    using Ptr = shared_ptr<PeerConnection>;
    using MessageCallback = function<void(const PeerInfo&, const Message&)>;

    /**
     * The PeerConnection constructor initializes the io_context, socket, and header buffer with
     * specific sizes.
     * 
     * @param ctx The `ctx` parameter is a reference to a `boost::asio::io_context` object, which is
     * used for handling asynchronous I/O operations in the Boost.Asio library.
     */
    PeerConnection(boost::asio::io_context& ctx);
    
    /**
     * The PeerConnection destructor closes the socket connection with error handling.
     */
    ~PeerConnection();

    /**
     * The function `socket()` returns a reference to the TCP socket associated with a peer connection.
     * 
     * @return The `sock` object of type `tcp::socket` is being returned.
     */
    tcp::socket& socket();
    
    /**
     * The `start` function of the `PeerConnection` class initiates a read loop by asynchronously
     * reading a header.
     */
    void start(); // comienza io read loop
    
    /**
     * The function `connectTo` in the `PeerConnection` class asynchronously resolves and connects to a
     * peer using Boost.Asio.
     * 
     * @param peer `peer` is an object of type `PeerInfo` which contains information about the peer
     * such as host and port number.
     * 
     * @return In the provided code snippet, if an error occurs during the asynchronous resolution or
     * connection process, the function returns early without further processing. This is indicated by
     * the `return;` statement inside the lambda functions that handle the error cases.
     */
    void connectTo(const PeerInfo& peer); // activa
    
    /**
     * The `sendMessage` function in the `PeerConnection` class serializes a message and sends it raw.
     * 
     * @param msg The `msg` parameter in the `sendMessage` function is of type `Message`, which is a
     * custom data structure representing a message to be sent over a peer-to-peer connection.
     */
    void sendMessage(const Message& msg);
    
    /**
     * The function `peerInfo()` returns a constant reference to the `PeerInfo` object stored in the
     * `info` member variable of the `PeerConnection` class.
     * 
     * @return The function `peerInfo()` is returning a constant reference to an object of type
     * `PeerInfo`.
     */
    PeerInfo const& peerInfo() const;

    /**
     * The function `setMessageHandler` in the `PeerConnection` class sets a message callback function.
     * 
     * @param cb The `cb` parameter is a `MessageCallback` type, which is a callback function used to
     * handle messages in the `PeerConnection` class.
     */
    void setMessageHandler(MessageCallback cb);

private:

    /**
     * The `asyncReadHeader` function asynchronously reads a message header from a socket and then
     * proceeds to read the payload based on the header information.
     * 
     * @return In the provided code snippet, the `handleDisconnect()` function is being called and then
     * a `return` statement is used to exit the `asyncReadHeader()` function if an error occurs during
     * the asynchronous read operation.
     */
    void asyncReadHeader();
    
    /**
     * The `asyncReadPayload` function reads a payload from a peer connection, validates the checksum,
     * parses the header, and calls a callback with the received message.
     * 
     * @param payloadLen The `payloadLen` parameter in the `asyncReadPayload` function represents the
     * length of the payload data that needs to be read asynchronously from the socket. This length is
     * used to determine the total size of the data to be read, which includes the payload itself and a
     * 4-byte checksum appended to
     * 
     * @return In the provided code snippet, the `handleDisconnect()` function is being called and then
     * a `return` statement is used to exit the `asyncReadPayload` function in case of an error
     * condition.
     */
    void asyncReadPayload(uint64_t payloadLen);

    /**
     * The `handleDisconnect` function closes the socket connection and shuts down the peer
     * connection.
     */
    void handleDisconnect();

    /**
     * The `sendRaw` function sends a vector of uint8_t data asynchronously over a socket using
     * Boost Asio, handling errors by disconnecting if necessary.
     * 
     * @param buf The `buf` parameter is a `const` reference to a `vector` of `uint8_t` data, which
     * represents the raw data to be sent over the network.
     */
    void sendRaw(const vector<uint8_t>& buf);

    boost::asio::io_context& io;
    tcp::socket sock;
    PeerInfo info;
    MessageCallback onMessage;

    vector<uint8_t> headerBuf;
    vector<uint8_t> payloadBuf;
    mutex writeMtx;
};

} // namespace p2p

#endif // P2P_PEER_CONNECTION_HPP
