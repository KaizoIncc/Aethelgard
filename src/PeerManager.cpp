#include "PeerManager.hpp"

namespace p2p {

    void PeerManager::addKnownPeer(const PeerInfo& peer) {
        lock_guard<mutex> lock(mtx);
        peers[peer.key()] = peer;
    }

    vector<PeerInfo> PeerManager::getKnownPeers() const {
        lock_guard<mutex> lock(mtx);
        
        vector<PeerInfo> result;
        result.reserve(peers.size());
        
        transform(peers.begin(), peers.end(), back_inserter(result),
                [](const auto& pair) { return pair.second; });
        
        return result;
    }

    void PeerManager::markSeen(const PeerInfo& peer) {
        lock_guard<mutex> lock(mtx);
        auto iterator = peers.find(peer.key());
        const auto currentTime = chrono::system_clock::now();
        
        if (iterator != peers.end()) {
            iterator->second.lastSeen = currentTime;
            iterator->second.score += 1;
        } else {
            PeerInfo newPeer = peer;
            newPeer.lastSeen = currentTime;
            peers[newPeer.key()] = newPeer;
        }
    }

    vector<PeerInfo> PeerManager::selectPeersToConnect(size_t maxCount) const {
        lock_guard<mutex> lock(mtx);
        
        vector<PeerInfo> peerList;
        peerList.reserve(peers.size());
        
        for (const auto& [key, peer] : peers) {
            peerList.push_back(peer);
        }
        
        auto comparePeers = [](const PeerInfo& first, const PeerInfo& second) {
            if (first.score != second.score) return first.score > second.score;
            return first.lastSeen > second.lastSeen;
        };
        
        sort(peerList.begin(), peerList.end(), comparePeers);
        
        if (peerList.size() > maxCount) {
            peerList.resize(maxCount);
        }
        
        return peerList;
    }

    bool PeerManager::persist(const string& filePath) const {
        lock_guard<mutex> lock(mtx);
        ofstream outputFile(filePath, ios::trunc);
        
        if (!outputFile) return false;
        
        for (const auto& [key, peer] : peers) {
            outputFile << peer.host << ":" << peer.port;
            if (!peer.nodeId.empty()) outputFile << ":" << peer.nodeId;
            outputFile << "\n";
        }
        
        return true;
    }

    bool PeerManager::loadFromDisk(const string& filePath) {
        lock_guard<mutex> lock(mtx);
        ifstream inputFile(filePath);
        
        if (!inputFile) return false;

        string line;
        while (getline(inputFile, line)) {
            if (line.empty()) continue;
            
            const size_t firstColon = line.find(':');
            if (firstColon == string::npos) continue;
            
            size_t secondColon = line.find(':', firstColon + 1);
            
            const string host = line.substr(0, firstColon);
            uint16_t port = 0;
            
            try {
                const string portStr = line.substr(
                    firstColon + 1, 
                    secondColon == string::npos ? string::npos : secondColon - (firstColon + 1)
                );
                port = static_cast<uint16_t>(stoul(portStr));
            } catch (...) { 
                continue; 
            }

            PeerInfo peerInfo;
            peerInfo.host = host;
            peerInfo.port = port;
            
            if (secondColon != string::npos) {
                peerInfo.nodeId = line.substr(secondColon + 1);
            }
            
            peers[peerInfo.key()] = peerInfo;
        }

        return true;
    }

} // namespace p2p