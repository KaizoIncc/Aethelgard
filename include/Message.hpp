#pragma once
#ifndef P2P_MESSAGE_HPP
#define P2P_MESSAGE_HPP

#include <cstdint>
#include <vector>
#include <string>

using namespace std;

namespace p2p {

    enum class MessageType : uint8_t {
        HANDSHAKE = 1,
        HANDSHAKE_ACK = 2,
        PING = 3,
        PONG = 4,
        PEER_LIST = 5,
        INV = 6,
        GETDATA = 7,
        TX = 8,
        BLOCK = 9,
        DISCONNECT = 255
    };

    struct Message {
        uint32_t magic = 0;
        uint8_t version = 1;
        MessageType type = MessageType::PING;
        vector<uint8_t> payload; // raw binary payload
    };

    // Helpers
    
    /**
     * The `serializeMessage` function serializes a `Message` object into a vector of uint8_t bytes,
     * including magic, version, type, payload length, payload, and checksum.
     * 
     * @param msg The `serializeMessage` function takes a `Message` object as input and serializes it
     * into a `vector<uint8_t>` for transmission or storage. The `Message` object likely contains
     * fields such as `magic`, `version`, `type`, `payload`, and possibly other fields.
     * 
     * @return The `serializeMessage` function returns a `vector<uint8_t>` containing the serialized
     * message data.
     */
    vector<uint8_t> serializeMessage(const Message& msg);

    /**
     * The function `parseMessageHeader` extracts message header information and payload length from a
     * given buffer.
     * 
     * @param headerBuf `headerBuf` is a vector of unsigned 8-bit integers, which represents the
     * message header data.
     * @param outHeader `outHeader` is a struct of type `Message` that contains information about a
     * message, including `magic`, `version`, and `type` fields.
     * @param payloadLen The `payloadLen` parameter in the `parseMessageHeader` function is an output
     * parameter of type `uint64_t`. It is used to store the length of the payload extracted from the
     * message header buffer.
     * 
     * @return The function `parseMessageHeader` returns a boolean value indicating whether the parsing
     * of the message header was successful. If the size of the `headerBuf` is less than `HEADER_SIZE`,
     * it returns `false`. Otherwise, it returns `true` after parsing the message header and populating
     * the `outHeader` and `payloadLen` variables.
     */
    bool parseMessageHeader(const vector<uint8_t>& headerBuf, Message& outHeader, uint64_t& payloadLen);
    
    /**
     * The function `crc32_buf` calculates the CRC-32 checksum for a given data buffer.
     * 
     * @param data The `data` parameter is a pointer to the start of the data buffer that you want to
     * calculate the CRC32 checksum for.
     * @param len The `len` parameter in the `crc32_buf` function represents the length of the data
     * buffer that is being passed for CRC32 calculation. It specifies the number of bytes in the data
     * buffer that should be considered for the CRC32 calculation.
     * 
     * @return The function `crc32_buf` returns a `uint32_t` value, which is the result of calculating
     * the CRC-32 checksum for the input data buffer.
     */
    uint32_t crc32_buf(const void* data, size_t len);

} // namespace p2p

#endif // P2P_MESSAGE_HPP
