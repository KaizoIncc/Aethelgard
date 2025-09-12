#pragma once
#ifndef P2P_PEER_HPP
#define P2P_PEER_HPP

#include <string>
#include <chrono>

using namespace std;

namespace p2p {

    struct PeerInfo {
        string host;   // ip o hostname
        uint16_t port = 0;
        string nodeId; // opcional
        chrono::system_clock::time_point lastSeen = chrono::system_clock::now();
        int score = 0;

        string key() const {
            return host + ":" + to_string(port);
        }
    };

} // namespace p2p

#endif // P2P_PEER_HPP
