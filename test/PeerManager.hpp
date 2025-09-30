#pragma once
#ifndef P2P_PEER_MANAGER_HPP
#define P2P_PEER_MANAGER_HPP

#include <unordered_map>
#include <mutex>
#include <vector>
#include <string>
#include <fstream>
#include <algorithm>
#include <iostream>

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

    class PeerManager {
        public:
            
            PeerManager() = default;

            ~PeerManager() = default;

            /**
             * The `addKnownPeer` function adds a `PeerInfo` object to a map of known peers in a thread-safe
             * manner.
             * 
             * @param p The parameter `p` in the `addKnownPeer` function is of type `const PeerInfo&`, which
             * means it is a constant reference to an object of type `PeerInfo`.
             */
            void addKnownPeer(const PeerInfo& p);
            
            /**
             * The function `getKnownPeers` returns a vector of `PeerInfo` objects containing information about
             * known peers, while ensuring thread safety using a mutex.
             * 
             * @return The `getKnownPeers` function returns a vector of `PeerInfo` objects containing
             * information about known peers.
             */
            vector<PeerInfo> getKnownPeers() const;

            /**
             * The markSeen function updates the lastSeen timestamp and score of a peer in a PeerManager
             * object, or adds a new peer if it does not already exist.
             * 
             * @param p The parameter `p` is of type `const PeerInfo&`, which means it is a constant reference
             * to an object of the `PeerInfo` class.
             */
            void markSeen(const PeerInfo& p);
            
            /**
             * The function `selectPeersToConnect` in the `PeerManager` class selects a specified number of
             * peers to connect based on their score and last seen timestamp.
             * 
             * @param maxCount The `maxCount` parameter in the `selectPeersToConnect` function represents the
             * maximum number of peers that should be selected for connection. This function selects a list of
             * peers based on certain criteria and returns a vector of `PeerInfo` objects containing
             * information about these selected peers, with the number
             * 
             * @return A vector of PeerInfo objects containing a selection of peers to connect to, based on the
             * specified maximum count and sorting criteria.
             */
            vector<PeerInfo> selectPeersToConnect(size_t maxCount) const;

            /**
             * The `persist` function in the `PeerManager` class writes peer information to a file specified by
             * the `filename` parameter.
             * 
             * @param filename The `filename` parameter is a constant reference to a `string` which represents
             * the name of the file where the peer information will be persisted.
             * 
             * @return The `persist` method returns a boolean value. It returns `true` if the operation of
             * writing the peer information to the specified file is successful, and `false` if there was an
             * issue opening the file for writing.
             */
            bool persist(const string& filename) const;

            /**
             * The `loadFromDisk` function reads peer information from a file and stores it in a map.
             * 
             * @param filename The `filename` parameter is a `const string&` type, which represents the name of
             * the file from which the `PeerManager` class is supposed to load data.
             * 
             * @return The `loadFromDisk` function returns a boolean value. It returns `true` if the file
             * specified by the `filename` parameter was successfully loaded and processed, and it returns
             * `false` if there was an issue opening the file or reading its contents.
             */
            bool loadFromDisk(const string& filename);

        private:
            mutable mutex mtx;
            unordered_map<string, PeerInfo> peers; // key = host:port
    };

} // namespace p2p

#endif // P2P_PEER_MANAGER_HPP
