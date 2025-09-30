#include "Message.hpp"

namespace p2p {

    // ------------------------------------------------------------
    // Funciones portables de endianness
    // ------------------------------------------------------------
    inline uint32_t hton32(uint32_t value) {
        return ((value & 0xFF000000) >> 24) |
            ((value & 0x00FF0000) >> 8)  |
            ((value & 0x0000FF00) << 8)  |
            ((value & 0x000000FF) << 24);
    }

    inline uint32_t ntoh32(uint32_t value) { 
        return hton32(value); 
    }

    inline uint64_t hton64(uint64_t value) {
        return ((value & 0xFF00000000000000ULL) >> 56) |
            ((value & 0x00FF000000000000ULL) >> 40) |
            ((value & 0x0000FF0000000000ULL) >> 24) |
            ((value & 0x000000FF00000000ULL) >> 8)  |
            ((value & 0x00000000FF000000ULL) << 8)  |
            ((value & 0x0000000000FF0000ULL) << 24) |
            ((value & 0x000000000000FF00ULL) << 40) |
            ((value & 0x00000000000000FFULL) << 56);
    }

    inline uint64_t ntoh64(uint64_t value) { 
        return hton64(value); 
    }

    // ------------------------------------------------------------
    // CRC32
    // ------------------------------------------------------------
    uint32_t crc32_buf(const void* data, size_t length) {
        return static_cast<uint32_t>(::crc32(0L, 
            reinterpret_cast<const unsigned char*>(data), 
            static_cast<uInt>(length)));
    }

    // ------------------------------------------------------------
    // SERIALIZACIÓN
    // ------------------------------------------------------------
    vector<uint8_t> serializeMessage(const Message& message) {
        vector<uint8_t> buffer;
        const uint64_t payloadLength = message.payload.size();
        buffer.reserve(MESSAGE_HEADER_SIZE + payloadLength + CHECKSUM_SIZE);

        // magic (4) en big-endian
        uint32_t magicBigEndian = hton32(message.magic);
        buffer.insert(buffer.end(), 
            reinterpret_cast<uint8_t*>(&magicBigEndian), 
            reinterpret_cast<uint8_t*>(&magicBigEndian) + 4);

        // version (1)
        buffer.push_back(message.version);

        // type (1)
        buffer.push_back(static_cast<uint8_t>(message.type));

        // payload length (8) en big-endian
        uint64_t lengthBigEndian = hton64(payloadLength);
        buffer.insert(buffer.end(), 
            reinterpret_cast<uint8_t*>(&lengthBigEndian), 
            reinterpret_cast<uint8_t*>(&lengthBigEndian) + 8);

        // payload
        if (!message.payload.empty()) {
            buffer.insert(buffer.end(), message.payload.begin(), message.payload.end());
        }

        // checksum CRC32 sobre TODO lo anterior
        uint32_t checksum = crc32_buf(buffer.data(), buffer.size());
        uint32_t checksumBigEndian = hton32(checksum);
        buffer.insert(buffer.end(), 
            reinterpret_cast<uint8_t*>(&checksumBigEndian), 
            reinterpret_cast<uint8_t*>(&checksumBigEndian) + 4);

        return buffer;
    }

    // ------------------------------------------------------------
    // PARSEO SOLO DE CABECERA
    // ------------------------------------------------------------
    bool parseMessageHeader(const vector<uint8_t>& headerBuffer, Message& outputHeader, uint64_t& payloadLength) {
        if (headerBuffer.size() < MESSAGE_HEADER_SIZE) return false;

        size_t position = 0;
        uint32_t magicBigEndian;
        memcpy(&magicBigEndian, &headerBuffer[position], 4);
        position += 4;
        outputHeader.magic = ntoh32(magicBigEndian);

        outputHeader.version = headerBuffer[position++];
        outputHeader.type = static_cast<MessageType>(headerBuffer[position++]);

        uint64_t lengthBigEndian;
        memcpy(&lengthBigEndian, &headerBuffer[position], 8);
        payloadLength = ntoh64(lengthBigEndian);

        // Validaciones básicas
        if (outputHeader.magic != NETWORK_MAGIC) return false;
        if (outputHeader.version != PROTOCOL_VERSION) return false;
        if (payloadLength > MAX_PAYLOAD_SIZE) return false;

        return true;
    }

    // ------------------------------------------------------------
    // PARSEO COMPLETO (cabecera + payload + checksum)
    // ------------------------------------------------------------
    bool parseFullMessage(const vector<uint8_t>& buffer, Message& outputMessage) {
        if (buffer.size() < MESSAGE_HEADER_SIZE + CHECKSUM_SIZE) return false;

        // 1. Parsear cabecera
        Message header;
        uint64_t payloadLength;
        if (!parseMessageHeader(buffer, header, payloadLength)) return false;

        // 2. Verificar que tenemos el mensaje completo
        const size_t totalLength = MESSAGE_HEADER_SIZE + payloadLength + CHECKSUM_SIZE;
        if (buffer.size() < totalLength) return false; // datos incompletos

        // 3. Extraer y validar CRC32
        uint32_t receivedChecksumBigEndian;
        memcpy(&receivedChecksumBigEndian, &buffer[MESSAGE_HEADER_SIZE + payloadLength], 4);
        uint32_t receivedChecksum = ntoh32(receivedChecksumBigEndian);

        uint32_t calculatedChecksum = crc32_buf(buffer.data(), MESSAGE_HEADER_SIZE + payloadLength);
        if (calculatedChecksum != receivedChecksum) return false; // corrupción

        // 4. Construir mensaje final
        outputMessage = header;
        outputMessage.payload.assign(
            buffer.begin() + MESSAGE_HEADER_SIZE, 
            buffer.begin() + MESSAGE_HEADER_SIZE + payloadLength);
        
        return true;
    }

    // ------------------------------------------------------------
    // UTILIDAD: convertir MessageType a string
    // ------------------------------------------------------------
    string messageTypeToString(MessageType type) {
        switch (type) {
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
            default:                         return "UNKNOWN";
        }
    }

} // namespace p2p