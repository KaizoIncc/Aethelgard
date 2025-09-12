#include "Message.hpp"
#include <cstring>
#include <zlib.h> // crc32
#include <stdexcept>

namespace p2p {

    static constexpr size_t HEADER_SIZE = 4 + 1 + 1 + 8; // magic(4) + version(1) + type(1) + payload_len(8)

    uint32_t crc32_buf(const void* data, size_t len) {
        return static_cast<uint32_t>(::crc32(0L, reinterpret_cast<const unsigned char*>(data), static_cast<uInt>(len)));
    }

    vector<uint8_t> serializeMessage(const Message& msg) {
        vector<uint8_t> out;
        out.reserve(HEADER_SIZE + msg.payload.size() + 4);

        // magic (4)
        uint32_t magic = msg.magic;
        out.insert(out.end(), reinterpret_cast<uint8_t*>(&magic), reinterpret_cast<uint8_t*>(&magic) + 4);

        // version (1)
        out.push_back(msg.version);

        // type (1)
        out.push_back(static_cast<uint8_t>(msg.type));

        // payload length (8)
        uint64_t len = static_cast<uint64_t>(msg.payload.size());
        out.insert(out.end(), reinterpret_cast<uint8_t*>(&len), reinterpret_cast<uint8_t*>(&len) + 8);

        // payload
        if (!msg.payload.empty()) out.insert(out.end(), msg.payload.begin(), msg.payload.end());

        // checksum (crc32 over everything so far)
        uint32_t c = crc32_buf(out.data(), out.size());
        out.insert(out.end(), reinterpret_cast<uint8_t*>(&c), reinterpret_cast<uint8_t*>(&c) + 4);
        return out;
    }

    bool parseMessageHeader(const vector<uint8_t>& headerBuf, Message& outHeader, uint64_t& payloadLen) {
        if (headerBuf.size() < HEADER_SIZE) return false;

        size_t pos = 0;
        uint32_t magic;
        memcpy(&magic, &headerBuf[pos], 4); 
        pos += 4;
        outHeader.magic = magic;
        outHeader.version = headerBuf[pos++];
        outHeader.type = static_cast<MessageType>(headerBuf[pos++]);
        memcpy(&payloadLen, &headerBuf[pos], 8);
        return true;
    }

} // namespace p2p
