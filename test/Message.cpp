#include "Message.hpp"

namespace p2p {

    // Cache para prevención de replay attacks
    static std::unordered_set<std::string> used_nonces;
    static std::mutex nonce_mutex;

    // ------------------------------------------------------------
    // Funciones portables de endianness
    // ------------------------------------------------------------
    uint32_t hton32(uint32_t value) {
        return ((value & 0xFF000000) >> 24) |
               ((value & 0x00FF0000) >> 8)  |
               ((value & 0x0000FF00) << 8)  |
               ((value & 0x000000FF) << 24);
    }

    uint32_t ntoh32(uint32_t value) { 
        return hton32(value); 
    }

    uint64_t hton64(uint64_t value) {
        return ((value & 0xFF00000000000000ULL) >> 56) |
               ((value & 0x00FF000000000000ULL) >> 40) |
               ((value & 0x0000FF0000000000ULL) >> 24) |
               ((value & 0x000000FF00000000ULL) >> 8)  |
               ((value & 0x00000000FF000000ULL) << 8)  |
               ((value & 0x0000000000FF0000ULL) << 24) |
               ((value & 0x000000000000FF00ULL) << 40) |
               ((value & 0x00000000000000FFULL) << 56);
    }

    uint64_t ntoh64(uint64_t value) { 
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
    std::vector<uint8_t> serializeMessage(const Message& message) {
        std::vector<uint8_t> buffer;
        const uint64_t payloadLength = message.payload.size();
        
        // Validar tamaño máximo
        if (payloadLength > MAX_PAYLOAD_SIZE) {
            throw std::runtime_error("Payload size exceeds maximum allowed");
        }
        
        buffer.reserve(MESSAGE_HEADER_SIZE + payloadLength + CHECKSUM_SIZE);

        // magic (4) en big-endian
        uint32_t magicBigEndian = hton32(message.magic);
        buffer.insert(buffer.end(), 
            reinterpret_cast<const uint8_t*>(&magicBigEndian), 
            reinterpret_cast<const uint8_t*>(&magicBigEndian) + 4);

        // version (1)
        buffer.push_back(message.version);

        // type (1)
        buffer.push_back(static_cast<uint8_t>(message.type));

        // payload length (8) en big-endian
        uint64_t lengthBigEndian = hton64(payloadLength);
        buffer.insert(buffer.end(), 
            reinterpret_cast<const uint8_t*>(&lengthBigEndian), 
            reinterpret_cast<const uint8_t*>(&lengthBigEndian) + 8);

        // payload
        if (!message.payload.empty()) {
            buffer.insert(buffer.end(), message.payload.begin(), message.payload.end());
        }

        // checksum CRC32 sobre TODO lo anterior
        uint32_t checksum = crc32_buf(buffer.data(), buffer.size());
        uint32_t checksumBigEndian = hton32(checksum);
        buffer.insert(buffer.end(), 
            reinterpret_cast<const uint8_t*>(&checksumBigEndian), 
            reinterpret_cast<const uint8_t*>(&checksumBigEndian) + 4);

        return buffer;
    }

    // ------------------------------------------------------------
    // PARSEO SOLO DE CABECERA
    // ------------------------------------------------------------
    bool parseMessageHeader(const std::vector<uint8_t>& headerBuffer, Message& outputHeader, uint64_t& payloadLength) {
        if (headerBuffer.size() < MESSAGE_HEADER_SIZE) {
            return false;
        }

        size_t position = 0;
        uint32_t magicBigEndian;
        std::memcpy(&magicBigEndian, &headerBuffer[position], 4);
        position += 4;
        outputHeader.magic = ntoh32(magicBigEndian);

        outputHeader.version = headerBuffer[position++];
        outputHeader.type = static_cast<MessageType>(headerBuffer[position++]);

        uint64_t lengthBigEndian;
        std::memcpy(&lengthBigEndian, &headerBuffer[position], 8);
        payloadLength = ntoh64(lengthBigEndian);

        // Validaciones básicas de seguridad
        if (outputHeader.magic != NETWORK_MAGIC) {
            std::cerr << "Warning: Invalid network magic in message header" << std::endl;
            return false;
        }
        
        if (outputHeader.version != PROTOCOL_VERSION) {
            std::cerr << "Warning: Unsupported protocol version: " << static_cast<int>(outputHeader.version) << std::endl;
            return false;
        }
        
        if (payloadLength > MAX_PAYLOAD_SIZE) {
            std::cerr << "Warning: Payload size too large: " << payloadLength << std::endl;
            return false;
        }

        return true;
    }

    // ------------------------------------------------------------
    // PARSEO COMPLETO (cabecera + payload + checksum)
    // ------------------------------------------------------------
    bool parseFullMessage(const std::vector<uint8_t>& buffer, Message& outputMessage) {
        if (buffer.size() < MESSAGE_HEADER_SIZE + CHECKSUM_SIZE) {
            return false;
        }

        // 1. Parsear cabecera
        Message header;
        uint64_t payloadLength;
        if (!parseMessageHeader(buffer, header, payloadLength)) {
            return false;
        }

        // 2. Verificar que tenemos el mensaje completo
        const size_t totalLength = MESSAGE_HEADER_SIZE + payloadLength + CHECKSUM_SIZE;
        if (buffer.size() < totalLength) {
            return false; // datos incompletos
        }

        // 3. Extraer y validar CRC32
        uint32_t receivedChecksumBigEndian;
        std::memcpy(&receivedChecksumBigEndian, &buffer[MESSAGE_HEADER_SIZE + payloadLength], 4);
        uint32_t receivedChecksum = ntoh32(receivedChecksumBigEndian);

        uint32_t calculatedChecksum = crc32_buf(buffer.data(), MESSAGE_HEADER_SIZE + payloadLength);
        if (calculatedChecksum != receivedChecksum) {
            std::cerr << "Warning: Message checksum verification failed" << std::endl;
            return false; // corrupción
        }

        // 4. Construir mensaje final
        outputMessage = header;
        outputMessage.payload.assign(
            buffer.begin() + MESSAGE_HEADER_SIZE, 
            buffer.begin() + MESSAGE_HEADER_SIZE + payloadLength);
        
        return true;
    }

    // ------------------------------------------------------------
    // FUNCIONES DE HANDSHAKE SEGURO
    // ------------------------------------------------------------
    HandshakeData createHandshakeData(const std::vector<uint8_t>& node_id, 
                                     const std::vector<uint8_t>& private_key) {
        HandshakeData handshake;
        
        // Validar parámetros
        if (node_id.size() != NODE_ID_SIZE) {
            throw std::invalid_argument("Invalid node ID size");
        }
        
        handshake.node_id = node_id;
        
        // Generar nonce aleatorio
        handshake.nonce.resize(NONCE_SIZE);
        randombytes_buf(handshake.nonce.data(), NONCE_SIZE);
        
        // Timestamp actual
        handshake.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        
        // Capabilities (por defecto)
        handshake.capabilities = 0x01; // Soporte básico
        
        // User agent
        handshake.user_agent = "AethelgardNode/1.0";
        
        return handshake;
    }

    bool verifyHandshakeData(const HandshakeData& handshake, const HandshakeAuth& auth) {
        // Verificar timestamp (no demasiado antiguo)
        auto now = std::chrono::system_clock::now().time_since_epoch();
        auto current_time = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
        
        if (handshake.timestamp > current_time + 60000) { // 1 minuto de tolerancia
            std::cerr << "Warning: Handshake timestamp in the future" << std::endl;
            return false;
        }
        
        if (current_time - handshake.timestamp > HANDSHAKE_TIMEOUT_MS) {
            std::cerr << "Warning: Handshake timestamp too old" << std::endl;
            return false;
        }
        
        // Verificar nonce (prevención de replay)
        if (!isNonceValid(handshake.nonce, handshake.timestamp)) {
            std::cerr << "Warning: Handshake nonce already used or invalid" << std::endl;
            return false;
        }
        
        // Verificar firma (si se proporciona autenticación)
        if (!auth.signature.empty() && !auth.public_key.empty()) {
            // Serializar datos del handshake para verificación
            std::vector<uint8_t> handshake_data = serializeHandshakeData(handshake);
            
            // Verificar firma
            if (!SignatureManager::verifySignature(auth.public_key, handshake_data, auth.signature)) {
                std::cerr << "Warning: Handshake signature verification failed" << std::endl;
                return false;
            }
        }
        
        return true;
    }

    // ------------------------------------------------------------
    // VALIDACIONES DE SEGURIDAD
    // ------------------------------------------------------------
    bool validateMessageSecurity(const Message& msg, const std::vector<uint8_t>& peer_id) {
        // Validaciones básicas ya realizadas en parseFullMessage
        
        // Validaciones adicionales para tipos específicos de mensaje
        switch (msg.type) {
            case MessageType::HANDSHAKE:
            case MessageType::HANDSHAKE_AUTH:
                // Para handshake, verificar estructura específica
                if (msg.payload.size() < NODE_ID_SIZE + NONCE_SIZE + sizeof(uint64_t)) {
                    return false;
                }
                break;
                
            case MessageType::TX:
                // Para transacciones, podríamos verificar tamaño mínimo
                if (msg.payload.size() < 100) { // Tamaño mínimo estimado
                    return false;
                }
                break;
                
            case MessageType::BLOCK:
                // Para bloques, verificar tamaño razonable
                if (msg.payload.size() > 2 * 1024 * 1024) { // 2MB máximo para bloques
                    return false;
                }
                break;
                
            default:
                // Para otros tipos, no hay validaciones específicas
                break;
        }
        
        return true;
    }

    bool isNonceValid(const std::vector<uint8_t>& nonce, uint64_t timestamp) {
        std::lock_guard<std::mutex> lock(nonce_mutex);
        
        // Verificar que el nonce no haya expirado
        auto now = std::chrono::system_clock::now().time_since_epoch();
        auto current_time = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
        
        if (current_time - timestamp > HANDSHAKE_TIMEOUT_MS) {
            return false; // Nonce expirado
        }
        
        // Crear clave única para el nonce
        std::string nonce_key(nonce.begin(), nonce.end());
        
        // Verificar si el nonce ya fue usado
        if (used_nonces.find(nonce_key) != used_nonces.end()) {
            return false; // Nonce reutilizado
        }
        
        // Añadir a la cache
        used_nonces.insert(nonce_key);
        return true;
    }

    void cleanupExpiredNonces() {
        std::lock_guard<std::mutex> lock(nonce_mutex);
        
        // En una implementación completa, limpiaríamos nonces expirados
        // Por simplicidad, mantenemos un tamaño máximo
        if (used_nonces.size() > 10000) {
            used_nonces.clear();
        }
    }

    // ------------------------------------------------------------
    // UTILIDAD: convertir MessageType a string
    // ------------------------------------------------------------
    std::string messageTypeToString(MessageType type) {
        switch (type) {
            case MessageType::HANDSHAKE:     return "HANDSHAKE";
            case MessageType::HANDSHAKE_ACK: return "HANDSHAKE_ACK";
            case MessageType::HANDSHAKE_AUTH: return "HANDSHAKE_AUTH";
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

    // ------------------------------------------------------------
    // SERIALIZACIÓN/DESERIALIZACIÓN DE HANDSHAKE (implementaciones básicas)
    // ------------------------------------------------------------
    std::vector<uint8_t> serializeHandshakeData(const HandshakeData& data) {
        std::vector<uint8_t> result;
        // Implementación simplificada - serializar campos
        result.insert(result.end(), data.node_id.begin(), data.node_id.end());
        result.insert(result.end(), data.nonce.begin(), data.nonce.end());
        
        uint64_t timestamp_be = hton64(data.timestamp);
        result.insert(result.end(), 
            reinterpret_cast<uint8_t*>(&timestamp_be), 
            reinterpret_cast<uint8_t*>(&timestamp_be) + 8);
            
        uint32_t capabilities_be = hton32(data.capabilities);
        result.insert(result.end(), 
            reinterpret_cast<uint8_t*>(&capabilities_be), 
            reinterpret_cast<uint8_t*>(&capabilities_be) + 4);
            
        // User agent como string con longitud
        uint32_t ua_len = hton32(static_cast<uint32_t>(data.user_agent.size()));
        result.insert(result.end(), 
            reinterpret_cast<uint8_t*>(&ua_len), 
            reinterpret_cast<uint8_t*>(&ua_len) + 4);
        result.insert(result.end(), data.user_agent.begin(), data.user_agent.end());
        
        return result;
    }

    bool deserializeHandshakeData(const std::vector<uint8_t>& data, HandshakeData& out) {
        // Implementación simplificada - deserializar campos
        size_t pos = 0;
        
        if (data.size() < NODE_ID_SIZE + NONCE_SIZE + 8 + 4) {
            return false;
        }
        
        out.node_id.assign(data.begin() + pos, data.begin() + pos + NODE_ID_SIZE);
        pos += NODE_ID_SIZE;
        
        out.nonce.assign(data.begin() + pos, data.begin() + pos + NONCE_SIZE);
        pos += NONCE_SIZE;
        
        uint64_t timestamp_be;
        std::memcpy(&timestamp_be, &data[pos], 8);
        out.timestamp = ntoh64(timestamp_be);
        pos += 8;
        
        uint32_t capabilities_be;
        std::memcpy(&capabilities_be, &data[pos], 4);
        out.capabilities = ntoh32(capabilities_be);
        pos += 4;
        
        // User agent
        if (data.size() > pos + 4) {
            uint32_t ua_len_be;
            std::memcpy(&ua_len_be, &data[pos], 4);
            uint32_t ua_len = ntoh32(ua_len_be);
            pos += 4;
            
            if (data.size() >= pos + ua_len) {
                out.user_agent.assign(data.begin() + pos, data.begin() + pos + ua_len);
            }
        }
        
        return true;
    }

} // namespace p2p