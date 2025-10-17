#ifndef P2P_NODE_HPP
#define P2P_NODE_HPP

#include "PeerManager.hpp"
#include "PeerConnection.hpp"
#include "Message.hpp"
#include <boost/asio.hpp>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <memory>
#include <functional>
#include <iostream>
#include <chrono>
#include <atomic>
#include <thread>

namespace p2p {
    
    using tcp = boost::asio::ip::tcp;

    // Estructura para tracking de comportamiento de peers
    struct PeerBehavior {
        std::chrono::steady_clock::time_point last_seen;
        uint32_t message_count = 0;
        uint32_t invalid_messages = 0;
        uint32_t connection_attempts = 0;
        bool is_blacklisted = false;
        std::chrono::steady_clock::time_point blacklist_until;
    };

    class P2PNode {
        public:
            using EventCallback = std::function<void(const PeerInfo&, const Message&)>;

            P2PNode(uint16_t listenPort, uint32_t networkMagic);
            ~P2PNode();

            void start();
            void stop();

            void addBootstrapPeer(const PeerInfo& p);
            void broadcastMessage(const Message& msg);
            void connectToPeer(const PeerInfo& p);

            void setMessageHandler(EventCallback cb);

            // Gestión de seguridad
            void blacklistPeer(const std::string& peer_key, uint32_t duration_seconds = 3600);
            void whitelistPeer(const std::string& peer_key);
            bool isPeerBlacklisted(const std::string& peer_key) const;
            
            // Configuración de límites
            void setMaxPeers(size_t max_peers);
            void setRateLimit(uint32_t messages_per_minute);
            void setMaxConnectionAttempts(uint32_t max_attempts);

            // persistent peers file
            void loadPeersFile(const std::string& filename);
            void savePeersFile(const std::string& filename);

            // Estadísticas
            size_t getActiveConnections() const;
            size_t getBlacklistedPeers() const;

        private:
            void doAccept();
            void onNewConnection(const PeerConnection::Ptr& conn);
            void removeConnection(const std::string& key);
            
            // Funciones de seguridad
            bool shouldAcceptConnection(const tcp::endpoint& endpoint);
            bool checkRateLimit(const std::string& peer_key);
            bool validatePeerHandshake(const PeerInfo& peer, const Message& handshake_msg);
            bool validateMessageSecurity(const PeerInfo& peer, const Message& message);
            void trackPeerBehavior(const std::string& peer_key, bool valid_message);
            void cleanupExpiredBlacklists();
            
            // Temporizadores para mantenimiento
            void startMaintenanceTimer();
            void onMaintenanceTimer(const boost::system::error_code& ec);

            boost::asio::io_context io;
            boost::asio::executor_work_guard<boost::asio::io_context::executor_type> workGuard;
            tcp::acceptor acceptor;
            boost::asio::steady_timer maintenance_timer;

            PeerManager peerManager;
            std::unordered_map<std::string, PeerConnection::Ptr> connections;
            std::unordered_map<std::string, PeerBehavior> peer_behavior;
            mutable std::mutex connMtx;
            mutable std::mutex behaviorMtx;

            uint32_t magic;
            EventCallback onMessage;
            uint16_t port;

            // Límites de seguridad
            size_t max_peers = 100;
            uint32_t rate_limit_messages_per_minute = 1000;
            uint32_t max_connection_attempts = 3;
            uint32_t max_invalid_messages = 10;

            // thread for io
            std::thread ioThread;
            std::atomic<bool> running{false};
    };

} // namespace p2p

#endif // P2P_NODE_HPP