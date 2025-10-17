#include "P2PNode.hpp"
#include <algorithm>
#include <fstream>

namespace p2p {

    P2PNode::P2PNode(uint16_t listenPort, uint32_t networkMagic) 
        : io(), 
        acceptor(io, tcp::endpoint(tcp::v4(), listenPort)), 
        magic(networkMagic), 
        port(listenPort), 
        workGuard(boost::asio::make_work_guard(io)),
        maintenance_timer(io) {}

    P2PNode::~P2PNode() {
        stop();
    }

    void P2PNode::start() {
        if (running.load()) return;
        
        running.store(true);
        
        // Iniciar temporizador de mantenimiento
        startMaintenanceTimer();
        
        doAccept();
        
        // Ejecutar io_context en hilo en segundo plano
        ioThread = std::thread([this] { 
            try {
                io.run(); 
            } catch (const std::exception& e) {
                std::cerr << "P2PNode IO context error: " << e.what() << std::endl;
            }
        });
        
        // Conectar a peers conocidos (con límites)
        auto knownPeers = peerManager.selectPeersToConnect(std::min(max_peers / 4, size_t(8)));
        for (auto& peer : knownPeers) {
            std::lock_guard<std::mutex> lock(connMtx);
            if (connections.size() < max_peers && !isPeerBlacklisted(peer.key())) {
                connectToPeer(peer);
            }
        }
    }

    void P2PNode::stop() {
        if (!running.load()) return;
        
        running.store(false);
        workGuard.reset();
        
        boost::system::error_code errorCode;
        acceptor.close(errorCode);
        maintenance_timer.cancel();

        // Cerrar conexiones
        {
            std::lock_guard<std::mutex> connectionLock(connMtx);
            for (auto& [key, connection] : connections) {
                boost::system::error_code closeError;
                connection->socket().close(closeError);
            }
            connections.clear();
        }

        io.stop();
        if (ioThread.joinable()) {
            ioThread.join();
        }
    }

    void P2PNode::addBootstrapPeer(const PeerInfo& peer) {
        peerManager.addKnownPeer(peer);
    }

    void P2PNode::broadcastMessage(const Message& message) {
        std::lock_guard<std::mutex> connectionLock(connMtx);
        
        size_t sent_count = 0;
        for (auto& [key, connection] : connections) {
            try {
                // Verificar rate limit antes de enviar
                if (checkRateLimit(key)) {
                    connection->sendMessage(message);
                    sent_count++;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error broadcasting to peer " << key << ": " << e.what() << std::endl;
                // No remover inmediatamente, dejar que el manejo de errores de conexión lo haga
            }
        }
        
        if (sent_count == 0) {
            std::cerr << "Warning: Broadcast message not sent to any peers" << std::endl;
        }
    }

    void P2PNode::connectToPeer(const PeerInfo& peer) {
        std::string peer_key = peer.key();
        
        // Verificar si el peer está en la lista negra
        if (isPeerBlacklisted(peer_key)) {
            std::cerr << "Skipping blacklisted peer: " << peer_key << std::endl;
            return;
        }
        
        // Verificar límite de conexiones
        {
            std::lock_guard<std::mutex> connectionLock(connMtx);
            if (connections.size() >= max_peers) {
                std::cerr << "Max peers reached, skipping connection to: " << peer_key << std::endl;
                return;
            }
        }
        
        // Trackear intento de conexión
        {
            std::lock_guard<std::mutex> behaviorLock(behaviorMtx);
            auto& behavior = peer_behavior[peer_key];
            behavior.connection_attempts++;
            behavior.last_seen = std::chrono::steady_clock::now();
            
            if (behavior.connection_attempts > max_connection_attempts) {
                std::cerr << "Too many connection attempts to peer: " << peer_key << ", blacklisting" << std::endl;
                blacklistPeer(peer_key, 3600); // 1 hora
                return;
            }
        }
        
        auto connection = std::make_shared<PeerConnection>(io);
        
        connection->setMessageHandler([this](const PeerInfo& peerInfo, const Message& message) {
            std::string peer_key = peerInfo.key();
            
            // Validar handshake para nuevas conexiones
            if (message.type == MessageType::HANDSHAKE || message.type == MessageType::HANDSHAKE_AUTH) {
                if (!validatePeerHandshake(peerInfo, message)) {
                    std::cerr << "Invalid handshake from peer: " << peer_key << std::endl;
                    trackPeerBehavior(peer_key, false);
                    
                    // Cerrar conexión si el handshake es inválido
                    std::lock_guard<std::mutex> connectionLock(connMtx);
                    auto it = connections.find(peer_key);
                    if (it != connections.end()) {
                        it->second->socket().close();
                        connections.erase(it);
                    }
                    return;
                }
                trackPeerBehavior(peer_key, true);
            }
            
            // Verificar rate limit para mensajes normales
            if (!checkRateLimit(peer_key)) {
                std::cerr << "Rate limit exceeded for peer: " << peer_key << std::endl;
                trackPeerBehavior(peer_key, false);
                return;
            }
            
            // Validar seguridad del mensaje
            if (!validateMessageSecurity(peerInfo, message)) {
                std::cerr << "Security validation failed for message from peer: " << peer_key << std::endl;
                trackPeerBehavior(peer_key, false);
                return;
            }
            
            trackPeerBehavior(peer_key, true);
            
            if (onMessage) {
                onMessage(peerInfo, message);
            }
        });
        
        connection->setErrorHandler([this, peer_key](const std::string& error) {
            std::cerr << "Connection error with peer " << peer_key << ": " << error << std::endl;
            removeConnection(peer_key);
            
            // Incrementar contador de errores
            std::lock_guard<std::mutex> behaviorLock(behaviorMtx);
            auto it = peer_behavior.find(peer_key);
            if (it != peer_behavior.end()) {
                it->second.invalid_messages++;
            }
        });
        
        try {
            connection->connectTo(peer);

            std::lock_guard<std::mutex> connectionLock(connMtx);
            connections[peer_key] = connection;
            peerManager.markSeen(peer);
            
        } catch (const std::exception& e) {
            std::cerr << "Failed to connect to peer " << peer_key << ": " << e.what() << std::endl;
            trackPeerBehavior(peer_key, false);
        }
    }

    void P2PNode::setMessageHandler(EventCallback callback) { 
        onMessage = std::move(callback); 
    }

    void P2PNode::doAccept() {
        auto connection = std::make_shared<PeerConnection>(io);
        
        acceptor.async_accept(connection->socket(), 
            [this, connection](const boost::system::error_code& errorCode) {
                if (!errorCode) {
                    try {
                        auto endpoint = connection->socket().remote_endpoint();
                        
                        // Verificar si debemos aceptar esta conexión
                        if (!shouldAcceptConnection(endpoint)) {
                            std::cerr << "Rejecting connection from: " << endpoint.address().to_string() << std::endl;
                            boost::system::error_code ec;
                            connection->socket().close(ec);
                            
                            if (running.load()) {
                                doAccept();
                            }
                            return;
                        }
                        
                        PeerInfo peerInfo;
                        peerInfo.host = endpoint.address().to_string();
                        peerInfo.port = static_cast<uint16_t>(endpoint.port());
                        
                        std::string peer_key = peerInfo.key();
                        
                        // Verificar límites antes de aceptar
                        {
                            std::lock_guard<std::mutex> connectionLock(connMtx);
                            if (connections.size() >= max_peers) {
                                std::cerr << "Max peers reached, rejecting incoming connection from: " << peer_key << std::endl;
                                boost::system::error_code ec;
                                connection->socket().close(ec);
                                
                                if (running.load()) {
                                    doAccept();
                                }
                                return;
                            }
                        }
                        
                        connection->setMessageHandler([this](const PeerInfo& peer, const Message& message) {
                            if (onMessage) {
                                onMessage(peer, message);
                            }
                        });
                        
                        connection->setErrorHandler([this, peer_key](const std::string& error) {
                            std::cerr << "Incoming connection error from " << peer_key << ": " << error << std::endl;
                            removeConnection(peer_key);
                        });
                        
                        connection->start();
                        
                        {
                            std::lock_guard<std::mutex> connectionLock(connMtx);
                            connections[peer_key] = connection;
                        }
                        peerManager.markSeen(peerInfo);
                        
                    } catch (const std::exception& e) {
                        std::cerr << "Error accepting connection: " << e.what() << std::endl;
                    }
                } else {
                    if (errorCode != boost::asio::error::operation_aborted) {
                        std::cerr << "Accept error: " << errorCode.message() << std::endl;
                    }
                }
                
                if (running.load()) {
                    doAccept();
                }
            });
    }

    // ============================================================
    // FUNCIONES DE SEGURIDAD
    // ============================================================

    bool P2PNode::shouldAcceptConnection(const tcp::endpoint& endpoint) {
        std::string address = endpoint.address().to_string();
        
        // Rechazar conexiones locales (para pruebas podrías querer permitirlas)
        if (endpoint.address().is_loopback()) {
            return true; // Permitir localhost para desarrollo
        }
        
        // Verificar si la IP está en lista negra
        std::lock_guard<std::mutex> behaviorLock(behaviorMtx);
        for (const auto& [key, behavior] : peer_behavior) {
            if (behavior.is_blacklisted) {
                // Extraer IP de la clave (formato "ip:port")
                size_t colon_pos = key.find(':');
                if (colon_pos != std::string::npos) {
                    std::string blacklisted_ip = key.substr(0, colon_pos);
                    if (blacklisted_ip == address) {
                        return false;
                    }
                }
            }
        }
        
        return true;
    }

    bool P2PNode::checkRateLimit(const std::string& peer_key) {
        std::lock_guard<std::mutex> behaviorLock(behaviorMtx);
        auto it = peer_behavior.find(peer_key);
        if (it == peer_behavior.end()) {
            // Primer mensaje de este peer, inicializar
            peer_behavior[peer_key] = PeerBehavior();
            peer_behavior[peer_key].last_seen = std::chrono::steady_clock::now();
            peer_behavior[peer_key].message_count = 1;
            return true;
        }
        
        auto& behavior = it->second;
        auto now = std::chrono::steady_clock::now();
        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(now - behavior.last_seen);
        
        // Reset counter si ha pasado más de 60 segundos
        if (time_diff.count() >= 60) {
            behavior.message_count = 0;
            behavior.last_seen = now;
        }
        
        // Verificar límite
        if (behavior.message_count >= rate_limit_messages_per_minute) {
            return false;
        }
        
        behavior.message_count++;
        behavior.last_seen = now;
        return true;
    }

    bool P2PNode::validatePeerHandshake(const PeerInfo& peer, const Message& handshake_msg) {
        // Validaciones básicas del handshake
        if (handshake_msg.type != MessageType::HANDSHAKE && 
            handshake_msg.type != MessageType::HANDSHAKE_AUTH) {
            return false;
        }
        
        if (handshake_msg.payload.empty()) {
            return false;
        }
        
        // Verificar magic number
        if (handshake_msg.magic != magic) {
            return false;
        }
        
        // Aquí podrías añadir validaciones específicas del protocolo
        // como verificación de nonce, timestamp, firma, etc.
        
        return true;
    }

    bool P2PNode::validateMessageSecurity(const PeerInfo& peer, const Message& message) {
        // Validaciones de seguridad para diferentes tipos de mensaje
        switch (message.type) {
            case MessageType::BLOCK:
                // Verificar que los bloques no sean demasiado grandes
                return message.payload.size() <= 2 * 1024 * 1024; // 2MB max
                
            case MessageType::TX:
                // Verificar tamaño razonable para transacciones
                return message.payload.size() <= 64 * 1024; // 64KB max
                
            case MessageType::PEER_LIST:
                // Limitar tamaño de lista de peers
                return message.payload.size() <= 16 * 1024; // 16KB max
                
            default:
                return true;
        }
    }

    void P2PNode::trackPeerBehavior(const std::string& peer_key, bool valid_message) {
        std::lock_guard<std::mutex> behaviorLock(behaviorMtx);
        auto it = peer_behavior.find(peer_key);
        if (it == peer_behavior.end()) {
            peer_behavior[peer_key] = PeerBehavior();
            it = peer_behavior.find(peer_key);
        }
        
        auto& behavior = it->second;
        behavior.last_seen = std::chrono::steady_clock::now();
        
        if (!valid_message) {
            behavior.invalid_messages++;
            
            // Blacklist automático si demasiados mensajes inválidos
            if (behavior.invalid_messages >= max_invalid_messages) {
                std::cerr << "Auto-blacklisting peer " << peer_key << " for too many invalid messages" << std::endl;
                blacklistPeer(peer_key, 7200); // 2 horas
            }
        } else {
            // Reset contador de mensajes inválidos en comportamiento bueno
            if (behavior.invalid_messages > 0) {
                behavior.invalid_messages--;
            }
        }
    }

    void P2PNode::blacklistPeer(const std::string& peer_key, uint32_t duration_seconds) {
        std::lock_guard<std::mutex> behaviorLock(behaviorMtx);
        auto it = peer_behavior.find(peer_key);
        if (it == peer_behavior.end()) {
            peer_behavior[peer_key] = PeerBehavior();
            it = peer_behavior.find(peer_key);
        }
        
        auto& behavior = it->second;
        behavior.is_blacklisted = true;
        behavior.blacklist_until = std::chrono::steady_clock::now() + 
                                  std::chrono::seconds(duration_seconds);
        
        // Cerrar conexión si está activa
        std::lock_guard<std::mutex> connectionLock(connMtx);
        auto conn_it = connections.find(peer_key);
        if (conn_it != connections.end()) {
            boost::system::error_code ec;
            conn_it->second->socket().close(ec);
            connections.erase(conn_it);
        }
    }

    void P2PNode::whitelistPeer(const std::string& peer_key) {
        std::lock_guard<std::mutex> behaviorLock(behaviorMtx);
        auto it = peer_behavior.find(peer_key);
        if (it != peer_behavior.end()) {
            it->second.is_blacklisted = false;
            it->second.invalid_messages = 0;
            it->second.connection_attempts = 0;
        }
    }

    bool P2PNode::isPeerBlacklisted(const std::string& peer_key) const {
        std::lock_guard<std::mutex> behaviorLock(behaviorMtx);
        auto it = peer_behavior.find(peer_key);
        if (it != peer_behavior.end() && it->second.is_blacklisted) {
            // Verificar si el blacklist ha expirado
            if (std::chrono::steady_clock::now() >= it->second.blacklist_until) {
                const_cast<PeerBehavior&>(it->second).is_blacklisted = false;
                return false;
            }
            return true;
        }
        return false;
    }

    void P2PNode::cleanupExpiredBlacklists() {
        std::lock_guard<std::mutex> behaviorLock(behaviorMtx);
        auto now = std::chrono::steady_clock::now();
        
        std::vector<std::string> to_remove;
        for (auto& [key, behavior] : peer_behavior) {
            if (behavior.is_blacklisted && now >= behavior.blacklist_until) {
                behavior.is_blacklisted = false;
                behavior.invalid_messages = 0;
                std::cout << "Auto-whitelisting expired blacklist for peer: " << key << std::endl;
            }
            
            // Limpiar peers muy antiguos que no están blacklisted
            auto time_diff = std::chrono::duration_cast<std::chrono::hours>(now - behavior.last_seen);
            if (!behavior.is_blacklisted && time_diff.count() > 24) {
                to_remove.push_back(key);
            }
        }
        
        // Remover peers antiguos
        for (const auto& key : to_remove) {
            peer_behavior.erase(key);
        }
    }

    void P2PNode::startMaintenanceTimer() {
        maintenance_timer.expires_after(std::chrono::minutes(5));
        maintenance_timer.async_wait([this](const boost::system::error_code& ec) {
            if (!ec && running.load()) {
                cleanupExpiredBlacklists();
                startMaintenanceTimer();
            }
        });
    }

    void P2PNode::setMaxPeers(size_t max_peers_limit) {
        max_peers = max_peers_limit;
    }

    void P2PNode::setRateLimit(uint32_t messages_per_minute) {
        rate_limit_messages_per_minute = messages_per_minute;
    }

    void P2PNode::setMaxConnectionAttempts(uint32_t max_attempts) {
        max_connection_attempts = max_attempts;
    }

    size_t P2PNode::getActiveConnections() const {
        std::lock_guard<std::mutex> connectionLock(connMtx);
        return connections.size();
    }

    size_t P2PNode::getBlacklistedPeers() const {
        std::lock_guard<std::mutex> behaviorLock(behaviorMtx);
        size_t count = 0;
        for (const auto& [key, behavior] : peer_behavior) {
            if (behavior.is_blacklisted) {
                count++;
            }
        }
        return count;
    }

    void P2PNode::loadPeersFile(const std::string& filename) {
        peerManager.loadFromDisk(filename);
    }

    void P2PNode::savePeersFile(const std::string& filename) {
        peerManager.persist(filename);
    }

    void P2PNode::onNewConnection(const PeerConnection::Ptr& connection) {
        // Placeholder para lógica adicional de nuevas conexiones
    }

    void P2PNode::removeConnection(const std::string& key) {
        std::lock_guard<std::mutex> connectionLock(connMtx);
        connections.erase(key);
    }

} // namespace p2p