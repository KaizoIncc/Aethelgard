#include "PeerConnection.hpp"
#include <iostream>

namespace p2p {

    PeerConnection::PeerConnection(boost::asio::io_context& ctx) 
        : io(ctx), 
          sock(ctx), 
          headerBuf(MESSAGE_HEADER_SIZE),
          connected(false) {}

    PeerConnection::~PeerConnection() {
        boost::system::error_code ec;
        sock.close(ec);
        connected.store(false);
    }

    tcp::socket& PeerConnection::socket() { 
        return sock; 
    }

    const PeerInfo& PeerConnection::peerInfo() const { 
        return info; 
    }

    void PeerConnection::setMessageHandler(MessageCallback cb) { 
        onMessage = std::move(cb); 
    }

    void PeerConnection::setErrorHandler(ErrorCallback cb) {
        onError = std::move(cb);
    }

    bool PeerConnection::isConnected() const {
        return connected.load() && sock.is_open();
    }

    void PeerConnection::start() {
        connected.store(true);
        asyncReadHeader();
    }

    void PeerConnection::connectTo(const PeerInfo& peer) {
        info = peer;
        auto self = shared_from_this();
        tcp::resolver resolver(io);
        
        resolver.async_resolve(peer.host, std::to_string(peer.port),
            [this, self, peer](const boost::system::error_code& ec, tcp::resolver::results_type results) {
                if (ec) {
                    handleError("Resolve failed: " + ec.message());
                    return;
                }
                
                boost::asio::async_connect(sock, results,
                    [this, self, peer](const boost::system::error_code& ec2, const tcp::endpoint& endpoint) {
                        if (!ec2) {
                            info = peer;
                            // Actualizar con el endpoint real conectado
                            info.host = endpoint.address().to_string();
                            info.port = static_cast<uint16_t>(endpoint.port());
                            start();
                        } else {
                            handleError("Connect failed: " + ec2.message());
                        }
                    });
            });
    }

    void PeerConnection::asyncReadHeader() {
        if (!isConnected()) {
            return;
        }

        auto self = shared_from_this();
        boost::asio::async_read(sock, boost::asio::buffer(headerBuf),
            [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                if (ec) {
                    handleDisconnect("Header read error: " + ec.message());
                    return;
                }

                if (bytes_transferred != MESSAGE_HEADER_SIZE) {
                    handleDisconnect("Incomplete header received");
                    return;
                }

                Message header;
                uint64_t payloadLen = 0;
                if (!parseMessageHeader(headerBuf, header, payloadLen)) {
                    handleDisconnect("Malformed message header");
                    return;
                }

                // Validar tamaño del payload
                if (payloadLen > MAX_PAYLOAD_SIZE) {
                    handleDisconnect("Payload too large: " + std::to_string(payloadLen));
                    return;
                }

                asyncReadPayload(payloadLen);
            });
    }

    void PeerConnection::asyncReadPayload(uint64_t payloadLen) {
        if (!isConnected()) {
            return;
        }

        // payload + checksum(4)
        const uint64_t total = payloadLen + CHECKSUM_SIZE;
        
        // Validar tamaño total
        if (total > MAX_PAYLOAD_SIZE + CHECKSUM_SIZE) {
            handleDisconnect("Total message size too large");
            return;
        }

        payloadBuf.resize(static_cast<std::size_t>(total));
        
        auto self = shared_from_this();
        boost::asio::async_read(sock, boost::asio::buffer(payloadBuf),
            [this, self, payloadLen](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                if (ec) {
                    handleDisconnect("Payload read error: " + ec.message());
                    return;
                }

                if (bytes_transferred != payloadLen + CHECKSUM_SIZE) {
                    handleDisconnect("Incomplete payload received");
                    return;
                }

                // Reconstruir header + payload para validar CRC
                std::vector<uint8_t> full;
                full.reserve(headerBuf.size() + payloadBuf.size());
                full.insert(full.end(), headerBuf.begin(), headerBuf.end());
                full.insert(full.end(), payloadBuf.begin(), payloadBuf.end());

                // Checksum son los últimos 4 bytes
                if (full.size() < CHECKSUM_SIZE) { 
                    handleDisconnect("Message too short for checksum");
                    return; 
                }

                uint32_t receivedCrc;
                std::memcpy(&receivedCrc, &full[full.size() - CHECKSUM_SIZE], CHECKSUM_SIZE);
                
                // Convertir de big-endian si es necesario
                receivedCrc = ntoh32(receivedCrc);
                
                uint32_t computed = crc32_buf(full.data(), full.size() - CHECKSUM_SIZE);
                if (receivedCrc != computed) {
                    handleDisconnect("Message checksum verification failed");
                    return;
                }

                // Parsear header para obtener información del mensaje
                Message headerMsg;
                uint64_t parsedPayloadLen = 0;
                if (!parseMessageHeader(headerBuf, headerMsg, parsedPayloadLen)) { 
                    handleDisconnect("Failed to parse message header");
                    return; 
                }

                // Verificar consistencia del payload length
                if (parsedPayloadLen != payloadLen) {
                    handleDisconnect("Payload length mismatch");
                    return;
                }

                // Copiar payload (excluyendo checksum)
                std::vector<uint8_t> payload;
                if (payloadLen > 0) {
                    payload.assign(payloadBuf.begin(), 
                                 payloadBuf.begin() + static_cast<std::size_t>(payloadLen));
                }

                headerMsg.payload = std::move(payload);

                // Llamar callback
                if (onMessage) {
                    try { 
                        onMessage(info, headerMsg); 
                    } catch (const std::exception& e) {
                        std::cerr << "Error in message handler: " << e.what() << std::endl;
                    } catch (...) {
                        std::cerr << "Unknown error in message handler" << std::endl;
                    }
                }

                // Continuar leyendo
                if (isConnected()) {
                    asyncReadHeader();
                }
            });
    }

    void PeerConnection::sendRaw(const std::vector<uint8_t>& buf) {
        if (!isConnected()) {
            handleError("Cannot send - not connected");
            return;
        }

        auto self = shared_from_this();
        
        // Proteger escrituras concurrentes en el mismo socket
        std::lock_guard<std::mutex> lock(writeMtx);
        
        boost::asio::async_write(sock, boost::asio::buffer(buf),
            [this, self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                if (ec) {
                    handleDisconnect("Send error: " + ec.message());
                } else if (bytes_transferred == 0) {
                    handleDisconnect("No bytes sent");
                }
                // Éxito - no hacer nada
            });
    }

    void PeerConnection::sendMessage(const Message& msg) {
        try {
            auto buf = serializeMessage(msg);
            sendRaw(buf);
        } catch (const std::exception& e) {
            handleError("Message serialization failed: " + std::string(e.what()));
        } catch (...) {
            handleError("Unknown error during message serialization");
        }
    }

    void PeerConnection::handleDisconnect(const std::string& reason) {
        if (!connected.exchange(false)) {
            return; // Ya desconectado
        }

        boost::system::error_code ec;
        
        if (sock.is_open()) {
            sock.shutdown(tcp::socket::shutdown_both, ec);
            if (ec) {
                // Ignorar errores de shutdown
            }
            
            sock.close(ec);
            if (ec) {
                // Ignorar errores de close
            }
        }

        if (!reason.empty() && onError) {
            onError(reason);
        }
    }

    void PeerConnection::handleError(const std::string& error_msg) {
        std::cerr << "PeerConnection error: " << error_msg << std::endl;
        
        if (onError) {
            onError(error_msg);
        }
        
        handleDisconnect(error_msg);
    }

} // namespace p2p