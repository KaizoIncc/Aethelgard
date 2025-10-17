#ifndef P2P_PEER_MANAGER_HPP
#define P2P_PEER_MANAGER_HPP

#include <unordered_map>
#include <mutex>
#include <vector>
#include <string>
#include <fstream>
#include <algorithm>
#include <iostream>
#include <chrono>
#include <cstdint>

namespace p2p {

    struct PeerInfo {
        std::string host;   // ip o hostname
        uint16_t port = 0;
        std::string nodeId; // opcional
        std::chrono::system_clock::time_point lastSeen = std::chrono::system_clock::now();
        int score = 0;
        uint32_t failedAttempts = 0;
        bool isBootstrap = false;

        std::string key() const {
            return host + ":" + std::to_string(port);
        }

        bool isValid() const {
            return !host.empty() && port > 0 && port <= 65535;
        }
    };

    class PeerManager {
        public:
            PeerManager() = default;
            ~PeerManager() = default;

            /**
             * Adds a known peer to the manager in a thread-safe manner.
             */
            void addKnownPeer(const PeerInfo& p);
            
            /**
             * Removes a peer from the manager by key.
             */
            bool removePeer(const std::string& peerKey);
            
            /**
             * Returns a vector of PeerInfo objects containing information about known peers.
             */
            std::vector<PeerInfo> getKnownPeers() const;

            /**
             * Updates the lastSeen timestamp and score of a peer, or adds a new peer if it doesn't exist.
             */
            void markSeen(const PeerInfo& p);
            
            /**
             * Marks a peer connection attempt as failed and updates its score.
             */
            void markFailed(const std::string& peerKey);
            
            /**
             * Selects a specified number of peers to connect based on their score and last seen timestamp.
             */
            std::vector<PeerInfo> selectPeersToConnect(size_t maxCount) const;

            /**
             * Gets a peer by its key, returns nullptr if not found.
             */
            const PeerInfo* getPeer(const std::string& peerKey) const;

            /**
             * Cleans up old peers that haven't been seen for a specified duration.
             */
            size_t cleanupOldPeers(const std::chrono::hours& maxAge);

            /**
             * Persists peer information to a file.
             */
            bool persist(const std::string& filename) const;

            /**
             * Loads peer information from a file.
             */
            bool loadFromDisk(const std::string& filename);

            /**
             * Returns the number of known peers.
             */
            size_t size() const;

            /**
             * Clears all peers from the manager.
             */
            void clear();

        private:
            mutable std::mutex mtx;
            std::unordered_map<std::string, PeerInfo> peers; // key = host:port
            
            // Constants for peer scoring
            static const int SCORE_INCREMENT = 1;
            static const int SCORE_DECREMENT = 5;
            static const int MAX_FAILED_ATTEMPTS = 3;
    };

} // namespace p2p

#endif // P2P_PEER_MANAGER_HPP