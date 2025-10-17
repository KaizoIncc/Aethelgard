#ifndef MESSAGE_HPP
#define MESSAGE_HPP

#include "Types.hpp"
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>
#include <zlib.h>      // crc32
#include <stdexcept>
#include "CryptoBase.hpp"
#include "SignatureManager.hpp"
#include <chrono>
#include <iostream>
#include <unordered_set>
#include <mutex>

namespace p2p {

    // Funciones de endianness
    uint32_t hton32(uint32_t v);
    uint32_t ntoh32(uint32_t v);
    uint64_t hton64(uint64_t v);
    uint64_t ntoh64(uint64_t v);

    // ============================================================
    //  TIPOS DE MENSAJE
    // ============================================================
    enum class MessageType : uint8_t {
        HANDSHAKE     = 1,
        HANDSHAKE_ACK = 2,
        HANDSHAKE_AUTH = 3,  // Nuevo: mensaje de autenticación
        PING          = 4,
        PONG          = 5,
        PEER_LIST     = 6,
        INV           = 7,
        GETDATA       = 8,
        TX            = 9,
        BLOCK         = 10,
        DISCONNECT    = 255
    };

    // ============================================================
    //  ESTRUCTURAS DE DATOS PARA HANDSHAKE
    // ============================================================
    struct HandshakeData {
        std::vector<uint8_t> node_id;      // Identificador único del nodo
        std::vector<uint8_t> nonce;        // Nonce para prevención de replay
        uint64_t timestamp;                // Timestamp del handshake
        uint32_t capabilities;             // Capacidades del nodo
        std::string user_agent;            // Cliente/user agent
    };

    struct HandshakeAuth {
        std::vector<uint8_t> signature;    // Firma del handshake
        std::vector<uint8_t> public_key;   // Clave pública para verificación
    };

    // ============================================================
    //  ESTRUCTURA DEL MENSAJE
    // ============================================================
    struct Message {
        uint32_t magic   = NETWORK_MAGIC;
        uint8_t  version = PROTOCOL_VERSION;
        MessageType type = MessageType::PING;
        std::vector<uint8_t> payload; // datos binarios
    };

    // ============================================================
    //  FUNCIONES PRINCIPALES
    // ============================================================

    /** Serializa un Message a bytes en formato de red */
    std::vector<uint8_t> serializeMessage(const Message& msg);

    /** Parsea SOLO la cabecera para obtener magic, versión, tipo y tamaño del payload */
    bool parseMessageHeader(const std::vector<uint8_t>& headerBuf, Message& outHeader, uint64_t& payloadLen);

    /** Calcula el CRC32 de un buffer */
    uint32_t crc32_buf(const void* data, size_t len);

    /** Parsea un mensaje COMPLETO (cabecera + payload + checksum) */
    bool parseFullMessage(const std::vector<uint8_t>& buf, Message& outMsg);

    /** Convierte un MessageType en string (útil para logs) */
    std::string messageTypeToString(MessageType t);

    // ============================================================
    //  FUNCIONES DE HANDSHAKE SEGURO
    // ============================================================

    /** Crea datos de handshake con autenticación */
    HandshakeData createHandshakeData(const std::vector<uint8_t>& node_id, 
                                     const std::vector<uint8_t>& private_key);

    /** Verifica datos de handshake recibidos */
    bool verifyHandshakeData(const HandshakeData& handshake, 
                            const HandshakeAuth& auth);

    /** Serializa datos de handshake para envío */
    std::vector<uint8_t> serializeHandshakeData(const HandshakeData& data);

    /** Deserializa datos de handshake recibidos */
    bool deserializeHandshakeData(const std::vector<uint8_t>& data, HandshakeData& out);

    /** Serializa autenticación de handshake */
    std::vector<uint8_t> serializeHandshakeAuth(const HandshakeAuth& auth);

    /** Deserializa autenticación de handshake */
    bool deserializeHandshakeAuth(const std::vector<uint8_t>& data, HandshakeAuth& out);

    // ============================================================
    //  VALIDACIONES DE SEGURIDAD
    // ============================================================

    /** Valida un mensaje completo con todas las comprobaciones de seguridad */
    bool validateMessageSecurity(const Message& msg, const std::vector<uint8_t>& peer_id);

    /** Verifica que el nonce no haya sido reutilizado (prevención de replay) */
    bool isNonceValid(const std::vector<uint8_t>& nonce, uint64_t timestamp);

    /** Limpia nonces expirados de la cache */
    void cleanupExpiredNonces();

} // namespace p2p

#endif // MESSAGE_HPP