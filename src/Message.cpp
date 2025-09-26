#include "Message.hpp"
#include <cstring>
#include <zlib.h>      // crc32
#include <stdexcept>
#if defined(_WIN32)
    #include <winsock2.h> // htonl, ntohl on Windows
#else
    #include <arpa/inet.h> // htonl, ntohl on Unix-like systems
#endif

namespace p2p {

    // ------------------------------------------------------------
    // Helpers de endianness para 64 bits
    // ------------------------------------------------------------
    static inline uint64_t hostToBigEndian64(uint64_t x) {
        // Convierte uint64_t a big-endian independientemente de la plataforma
        uint64_t r = 0;
        for (int i = 0; i < 8; ++i) {
            r |= ((x >> (56 - i*8)) & 0xFFULL) << (i*8);
        }
        return r;
    }
    static inline uint64_t bigEndianToHost64(uint64_t x) {
        // Inversa de la anterior
        uint64_t r = 0;
        for (int i = 0; i < 8; ++i) {
            r |= ((x >> (i*8)) & 0xFFULL) << (56 - i*8);
        }
        return r;
    }

    uint32_t crc32_buf(const void* data, size_t len) {
        return static_cast<uint32_t>(::crc32(0L, reinterpret_cast<const unsigned char*>(data), static_cast<uInt>(len)));
    }

    // ------------------------------------------------------------
    // SERIALIZACIÓN
    // ------------------------------------------------------------
    vector<uint8_t> serializeMessage(const Message& msg) {
        vector<uint8_t> out;
        uint64_t payloadLen = msg.payload.size();
        out.reserve(MESSAGE_HEADER_SIZE + payloadLen + CHECKSUM_SIZE);

        // magic (4) en big-endian
        uint32_t magicBE = htonl(msg.magic);
        out.insert(out.end(), reinterpret_cast<uint8_t*>(&magicBE), reinterpret_cast<uint8_t*>(&magicBE) + 4);

        // version (1)
        out.push_back(msg.version);

        // type (1)
        out.push_back(static_cast<uint8_t>(msg.type));

        // payload length (8) en big-endian
        uint64_t lenBE = hostToBigEndian64(payloadLen);
        out.insert(out.end(), reinterpret_cast<uint8_t*>(&lenBE), reinterpret_cast<uint8_t*>(&lenBE) + 8);

        // payload
        if (!msg.payload.empty()) out.insert(out.end(), msg.payload.begin(), msg.payload.end());

        // checksum CRC32 sobre TODO lo anterior
        uint32_t c = crc32_buf(out.data(), out.size());
        uint32_t cBE = htonl(c);
        out.insert(out.end(), reinterpret_cast<uint8_t*>(&cBE), reinterpret_cast<uint8_t*>(&cBE) + 4);

        return out;
    }

    // ------------------------------------------------------------
    // PARSEO SOLO DE CABECERA
    // ------------------------------------------------------------
    bool parseMessageHeader(const vector<uint8_t>& headerBuf, Message& outHeader, uint64_t& payloadLen)
    {
        if (headerBuf.size() < MESSAGE_HEADER_SIZE) return false;

        size_t pos = 0;
        uint32_t magicBE;
        memcpy(&magicBE, &headerBuf[pos], 4);
        pos += 4;
        outHeader.magic = ntohl(magicBE);

        outHeader.version = headerBuf[pos++];
        outHeader.type = static_cast<MessageType>(headerBuf[pos++]);

        uint64_t lenBE;
        memcpy(&lenBE, &headerBuf[pos], 8);
        payloadLen = bigEndianToHost64(lenBE);

        // Validaciones básicas
        if (outHeader.magic != NETWORK_MAGIC) return false;
        if (outHeader.version != PROTOCOL_VERSION) return false;
        if (payloadLen > MAX_PAYLOAD_SIZE) return false;

        return true;
    }

    // ------------------------------------------------------------
    // PARSEO COMPLETO (cabecera + payload + checksum)
    // ------------------------------------------------------------
    bool parseFullMessage(const vector<uint8_t>& buf, Message& outMsg) {
        if (buf.size() < MESSAGE_HEADER_SIZE + CHECKSUM_SIZE) return false;

        // 1. Parsear cabecera
        Message header;
        uint64_t payloadLen;
        if (!parseMessageHeader(buf, header, payloadLen)) return false;

        // 2. Verificar que tenemos el mensaje completo
        size_t totalLen = MESSAGE_HEADER_SIZE + payloadLen + CHECKSUM_SIZE;
        if (buf.size() < totalLen) return false; // datos incompletos

        // 3. Extraer y validar CRC32
        uint32_t crcReceivedBE;
        memcpy(&crcReceivedBE, &buf[MESSAGE_HEADER_SIZE + payloadLen], 4);
        uint32_t crcReceived = ntohl(crcReceivedBE);

        uint32_t crcCalc = crc32_buf(buf.data(), MESSAGE_HEADER_SIZE + payloadLen);
        if (crcCalc != crcReceived) return false; // corrupción

        // 4. Construir mensaje final
        outMsg = header;
        outMsg.payload.assign(buf.begin() + MESSAGE_HEADER_SIZE, buf.begin() + MESSAGE_HEADER_SIZE + payloadLen);
        
        return true;
    }

    // ------------------------------------------------------------
    // UTILIDAD: convertir MessageType a string
    // ------------------------------------------------------------
    string messageTypeToString(MessageType t) {
        switch (t) {
            case MessageType::HANDSHAKE:     return "HANDSHAKE";
            case MessageType::HANDSHAKE_ACK: return "HANDSHAKE_ACK";
            case MessageType::PING:          return "PING";
            case MessageType::PONG:          return "PONG";
            case MessageType::PEER_LIST:     return "PEER_LIST";
            case MessageType::INV:           return "INV";
            case MessageType::GETDATA:       return "GETDATA";
            case MessageType::TX:            return "TX";
            case MessageType::BLOCK:         return "BLOCK";
            case MessageType::DISCONNECT:    return "DISCONNECT";
            default:                          return "UNKNOWN";
        }
    }

} // namespace p2p
