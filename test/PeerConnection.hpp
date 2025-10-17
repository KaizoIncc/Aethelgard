#ifndef P2P_PEER_CONNECTION_HPP
#define P2P_PEER_CONNECTION_HPP

#include "PeerManager.hpp"
#include "Message.hpp"
#include <boost/asio.hpp>
#include <functional>
#include <memory>
#include <vector>
#include <mutex>
#include <string>

namespace p2p {
    
using tcp = boost::asio::ip::tcp;

class PeerConnection : public std::enable_shared_from_this<PeerConnection> {
public:
    using Ptr = std::shared_ptr<PeerConnection>;
    using MessageCallback = std::function<void(const PeerInfo&, const Message&)>;
    using ErrorCallback = std::function<void(const std::string&)>;

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
    const PeerInfo& peerInfo() const;

    /**
     * The function `setMessageHandler` in the `PeerConnection` class sets a message callback function.
     * 
     * @param cb The `cb` parameter is a `MessageCallback` type, which is a callback function used to
     * handle messages in the `PeerConnection` class.
     */
    void setMessageHandler(MessageCallback cb);

    /**
     * The function `setErrorHandler` sets a callback for handling connection errors.
     * 
     * @param cb The `cb` parameter is a function that will be called when an error occurs in the
     * PeerConnection. It takes a `std::string` parameter which contains the error message.
     */
    void setErrorHandler(ErrorCallback cb);

    /**
     * The function `isConnected` checks if the socket is still open and connected.
     * 
     * @return A boolean value indicating whether the socket is open and connected.
     */
    bool isConnected() const;

private:
    /**
     * The `asyncReadHeader` function asynchronously reads a message header from a socket and then
     * proceeds to read the payload based on the header information.
     */
    void asyncReadHeader();
    
    /**
     * The `asyncReadPayload` function reads a payload from a peer connection, validates the checksum,
     * parses the header, and calls a callback with the received message.
     * 
     * @param payloadLen The `payloadLen` parameter represents the length of the payload data that 
     * needs to be read asynchronously from the socket.
     */
    void asyncReadPayload(uint64_t payloadLen);

    /**
     * The `handleDisconnect` function closes the socket connection and shuts down the peer
     * connection.
     */
    void handleDisconnect(const std::string& reason = "");

    /**
     * The `sendRaw` function sends a vector of uint8_t data asynchronously over a socket using
     * Boost Asio, handling errors by disconnecting if necessary.
     * 
     * @param buf The `buf` parameter is a `const` reference to a `vector` of `uint8_t` data, which
     * represents the raw data to be sent over the network.
     */
    void sendRaw(const std::vector<uint8_t>& buf);

    /**
     * The `handleError` function processes errors and calls the error callback if set.
     * 
     * @param error_msg The error message to handle.
     */
    void handleError(const std::string& error_msg);

    boost::asio::io_context& io;
    tcp::socket sock;
    PeerInfo info;
    MessageCallback onMessage;
    ErrorCallback onError;

    std::vector<uint8_t> headerBuf;
    std::vector<uint8_t> payloadBuf;
    mutable std::mutex writeMtx;
    std::atomic<bool> connected{false};
};

} // namespace p2p

#endif // P2P_PEER_CONNECTION_HPP