#pragma once
#include <cstdint>
#include <vector>
#include <string>

using namespace std;

namespace p2p {

    // ============================================================
    //  CONFIGURACIÓN DEL PROTOCOLO
    // ============================================================
    inline constexpr uint32_t NETWORK_MAGIC = 0xDAB5BFFA; // Único para tu red
    inline constexpr uint8_t  PROTOCOL_VERSION = 1;
    inline constexpr size_t   MAX_PAYLOAD_SIZE = 4 * 1024 * 1024; // 4 MB máx
    inline constexpr size_t   MESSAGE_HEADER_SIZE = 4 + 1 + 1 + 8; // magic + version + type + payload_len
    inline constexpr size_t   CHECKSUM_SIZE = 4; // CRC32

    // ============================================================
    //  TIPOS DE MENSAJE
    // ============================================================
    enum class MessageType : uint8_t {
        HANDSHAKE    = 1,
        HANDSHAKE_ACK= 2,
        PING         = 3,
        PONG         = 4,
        PEER_LIST    = 5,
        INV          = 6,
        GETDATA      = 7,
        TX           = 8,
        BLOCK        = 9,
        DISCONNECT   = 255
    };

    // ============================================================
    //  ESTRUCTURA DEL MENSAJE
    // ============================================================
    struct Message {
        uint32_t magic   = NETWORK_MAGIC;
        uint8_t  version = PROTOCOL_VERSION;
        MessageType type = MessageType::PING;
        vector<uint8_t> payload; // datos binarios
    };

    // ============================================================
    //  FUNCIONES
    // ============================================================

    /** Serializa un Message a bytes en formato de red:
     * [magic(4) big-endian] [version(1)] [type(1)] [payload_len(8) big-endian]
     * [payload] [crc32(4)]
     */
    vector<uint8_t> serializeMessage(const Message& msg);

    /** Parsea SOLO la cabecera para obtener magic, versión, tipo y tamaño del payload.
     * Devuelve false si no hay bytes suficientes o si algún campo no es válido.
     */
    bool parseMessageHeader(const vector<uint8_t>& headerBuf, Message& outHeader, uint64_t& payloadLen);

    /** Calcula el CRC32 de un buffer */
    uint32_t crc32_buf(const void* data, size_t len);

    /** Parsea un mensaje COMPLETO (cabecera + payload + checksum).
     *  - Valida magic, versión, tamaño máximo y CRC32.
     *  - Llena un Message listo para usar.
     * Devuelve false si faltan datos o si el mensaje es inválido.
     */
    bool parseFullMessage(const vector<uint8_t>& buf, Message& outMsg);

    /** Convierte un MessageType en string (útil para logs) */
    string messageTypeToString(MessageType t);

} // namespace p2p
