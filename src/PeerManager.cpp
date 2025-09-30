#include "PeerManager.hpp"

namespace p2p {

    void PeerManager::addKnownPeer(const PeerInfo& p) {
        lock_guard<mutex> lk(mtx);
        peers[p.key()] = p;
    }

    vector<PeerInfo> PeerManager::getKnownPeers() const {
        lock_guard<mutex> lk(mtx);
        vector<PeerInfo> out;

        out.reserve(peers.size());
        
        for (auto const& kv : peers) out.push_back(kv.second);
        
        return out;
    }

    void PeerManager::markSeen(const PeerInfo& p) {
        lock_guard<mutex> lk(mtx);
        auto it = peers.find(p.key());
        
        if (it != peers.end()) {
            it->second.lastSeen = chrono::system_clock::now();
            it->second.score += 1;
        } else {
            PeerInfo np = p;
            np.lastSeen = chrono::system_clock::now();
            peers[np.key()] = np;
        }
    }

    vector<PeerInfo> PeerManager::selectPeersToConnect(size_t maxCount) const {
        lock_guard<mutex> lk(mtx);
        vector<PeerInfo> list;

        list.reserve(peers.size());
        
        for (auto const& kv : peers) list.push_back(kv.second);
        // simple selection: order by lastSeen desc, score desc
        sort(list.begin(), list.end(), [](const PeerInfo& a, const PeerInfo& b) {
            if (a.score != b.score) return a.score > b.score;
            return a.lastSeen > b.lastSeen;
        });

        if (list.size() > maxCount) list.resize(maxCount);

        return list;
    }

    bool PeerManager::persist(const string& filename) const {
        lock_guard<mutex> lk(mtx);
        ofstream out(filename, ios::trunc);

        if (!out) return false;
        
        for (auto const& kv : peers) {
            out << kv.second.host << ":" << kv.second.port;
            if (!kv.second.nodeId.empty()) out << ":" << kv.second.nodeId;
            out << "\n";
        }
        
        return true;
    }

    bool PeerManager::loadFromDisk(const string& filename) {
        lock_guard<mutex> lk(mtx);
        ifstream in(filename);

        if (!in) return false;

        string line;
        while (getline(in, line)) {
            if (line.empty()) continue;
            // format host:port[:nodeId]
            size_t p1 = line.find(':');
            size_t p2 = string::npos;

            if (p1 != string::npos) p2 = line.find(':', p1 + 1);
            if (p1 == string::npos) continue;

            string host = line.substr(0, p1);
            uint16_t port = 0;

            try {
                port = static_cast<uint16_t>(stoul(line.substr(p1 + 1, (p2==string::npos?string::npos:p2 - (p1+1)))));
            } catch (...) { continue; }

            PeerInfo pi;
            pi.host = host;
            pi.port = port;

            if (p2 != string::npos) pi.nodeId = line.substr(p2 + 1);
            peers[pi.key()] = pi;
        }

        return true;
    }

} // namespace p2p
