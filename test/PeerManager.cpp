#include "PeerManager.hpp"

namespace p2p {

    // Definición de constantes
    const int PeerManager::SCORE_INCREMENT;
    const int PeerManager::SCORE_DECREMENT;
    const int PeerManager::MAX_FAILED_ATTEMPTS;

    void PeerManager::addKnownPeer(const PeerInfo& peer) {
        if (!peer.isValid()) {
            return;
        }
        
        std::lock_guard<std::mutex> lock(mtx);
        peers[peer.key()] = peer;
    }

    bool PeerManager::removePeer(const std::string& peerKey) {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = peers.find(peerKey);
        if (it != peers.end()) {
            peers.erase(it);
            return true;
        }
        return false;
    }

    std::vector<PeerInfo> PeerManager::getKnownPeers() const {
        std::lock_guard<std::mutex> lock(mtx);
        
        std::vector<PeerInfo> result;
        result.reserve(peers.size());
        
        std::transform(peers.begin(), peers.end(), std::back_inserter(result),
                      [](const auto& pair) { return pair.second; });
        
        return result;
    }

    void PeerManager::markSeen(const PeerInfo& peer) {
        if (!peer.isValid()) {
            return;
        }
        
        std::lock_guard<std::mutex> lock(mtx);
        auto it = peers.find(peer.key());
        const auto currentTime = std::chrono::system_clock::now();
        
        if (it != peers.end()) {
            it->second.lastSeen = currentTime;
            it->second.score += SCORE_INCREMENT;
            it->second.failedAttempts = 0; // Reset failed attempts on successful connection
        } else {
            PeerInfo newPeer = peer;
            newPeer.lastSeen = currentTime;
            newPeer.score = SCORE_INCREMENT;
            peers[newPeer.key()] = newPeer;
        }
    }

    void PeerManager::markFailed(const std::string& peerKey) {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = peers.find(peerKey);
        if (it != peers.end()) {
            it->second.failedAttempts++;
            it->second.score -= SCORE_DECREMENT;
            
            // Remove peer if too many failed attempts
            if (it->second.failedAttempts >= MAX_FAILED_ATTEMPTS) {
                peers.erase(it);
            }
        }
    }

    std::vector<PeerInfo> PeerManager::selectPeersToConnect(size_t maxCount) const {
        std::lock_guard<std::mutex> lock(mtx);
        
        if (peers.empty() || maxCount == 0) {
            return {};
        }
        
        std::vector<PeerInfo> peerList;
        peerList.reserve(peers.size());
        
        const auto currentTime = std::chrono::system_clock::now();
        const auto maxAge = std::chrono::hours(24); // 24 hours maximum age
        
        // Filter and copy peers
        for (const auto& [key, peer] : peers) {
            // Skip peers that are too old or have too many failed attempts
            auto age = currentTime - peer.lastSeen;
            if (age < maxAge && peer.failedAttempts < MAX_FAILED_ATTEMPTS) {
                peerList.push_back(peer);
            }
        }
        
        // Sort by score (descending) and then by last seen (descending)
        auto comparePeers = [](const PeerInfo& first, const PeerInfo& second) {
            if (first.score != second.score) {
                return first.score > second.score;
            }
            return first.lastSeen > second.lastSeen;
        };
        
        std::sort(peerList.begin(), peerList.end(), comparePeers);
        
        // Limit to maxCount
        if (peerList.size() > maxCount) {
            peerList.resize(maxCount);
        }
        
        return peerList;
    }

    const PeerInfo* PeerManager::getPeer(const std::string& peerKey) const {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = peers.find(peerKey);
        if (it != peers.end()) {
            return &it->second;
        }
        return nullptr;
    }

    size_t PeerManager::cleanupOldPeers(const std::chrono::hours& maxAge) {
        std::lock_guard<std::mutex> lock(mtx);
        
        const auto currentTime = std::chrono::system_clock::now();
        size_t initialSize = peers.size();
        
        // Remove peers that are older than maxAge
        auto it = peers.begin();
        while (it != peers.end()) {
            auto age = currentTime - it->second.lastSeen;
            if (age > maxAge && !it->second.isBootstrap) {
                it = peers.erase(it);
            } else {
                ++it;
            }
        }
        
        return initialSize - peers.size();
    }

    bool PeerManager::persist(const std::string& filePath) const {
        std::lock_guard<std::mutex> lock(mtx);
        
        std::ofstream outputFile(filePath, std::ios::trunc);
        if (!outputFile.is_open()) {
            return false;
        }
        
        for (const auto& [key, peer] : peers) {
            outputFile << peer.host << ":" << peer.port;
            if (!peer.nodeId.empty()) {
                outputFile << ":" << peer.nodeId;
            }
            // Add additional fields for persistence
            outputFile << "|" << peer.score;
            outputFile << "|" << peer.failedAttempts;
            outputFile << "|" << peer.isBootstrap;
            outputFile << "\n";
        }
        
        return outputFile.good();
    }

    bool PeerManager::loadFromDisk(const std::string& filePath) {
        std::lock_guard<std::mutex> lock(mtx);
        
        std::ifstream inputFile(filePath);
        if (!inputFile.is_open()) {
            return false;
        }

        std::string line;
        while (std::getline(inputFile, line)) {
            if (line.empty()) {
                continue;
            }
            
            // Split by | to get additional fields
            size_t pipePos = line.find('|');
            std::string peerPart = line;
            std::string additionalFields;
            
            if (pipePos != std::string::npos) {
                peerPart = line.substr(0, pipePos);
                additionalFields = line.substr(pipePos + 1);
            }
            
            // Parse host:port[:nodeId]
            const size_t firstColon = peerPart.find(':');
            if (firstColon == std::string::npos) {
                continue;
            }
            
            size_t secondColon = peerPart.find(':', firstColon + 1);
            
            const std::string host = peerPart.substr(0, firstColon);
            uint16_t port = 0;
            
            try {
                const std::string portStr = peerPart.substr(
                    firstColon + 1, 
                    secondColon == std::string::npos ? std::string::npos : secondColon - (firstColon + 1)
                );
                port = static_cast<uint16_t>(std::stoul(portStr));
            } catch (...) { 
                continue; 
            }

            PeerInfo peerInfo;
            peerInfo.host = host;
            peerInfo.port = port;
            
            if (secondColon != std::string::npos) {
                peerInfo.nodeId = peerPart.substr(secondColon + 1);
            }
            
            // Parse additional fields if present
            if (!additionalFields.empty()) {
                try {
                    size_t pos = 0;
                    size_t nextPos = additionalFields.find('|', pos);
                    
                    // Score
                    if (nextPos != std::string::npos) {
                        peerInfo.score = std::stoi(additionalFields.substr(pos, nextPos - pos));
                        pos = nextPos + 1;
                        
                        nextPos = additionalFields.find('|', pos);
                        // Failed attempts
                        if (nextPos != std::string::npos) {
                            peerInfo.failedAttempts = std::stoi(additionalFields.substr(pos, nextPos - pos));
                            pos = nextPos + 1;
                            
                            // Bootstrap flag
                            peerInfo.isBootstrap = (additionalFields.substr(pos) == "1");
                        }
                    }
                } catch (...) {
                    // If parsing additional fields fails, use defaults
                }
            }
            
            if (peerInfo.isValid()) {
                peers[peerInfo.key()] = peerInfo;
            }
        }

        return true;
    }

    size_t PeerManager::size() const {
        std::lock_guard<std::mutex> lock(mtx);
        return peers.size();
    }

    void PeerManager::clear() {
        std::lock_guard<std::mutex> lock(mtx);
        peers.clear();
    }

} // namespace p2p