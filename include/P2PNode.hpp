#pragma once
#ifndef P2P_NODE_HPP
#define P2P_NODE_HPP

#include "PeerManager.hpp"
#include "PeerConnection.hpp"
#include "Message.hpp"
#include <boost/asio.hpp>
#include <unordered_map>
#include <mutex>
#include <memory>
#include <functional>

namespace p2p {
    
    using tcp = boost::asio::ip::tcp;

    class P2PNode {
        public:
            using EventCallback = function<void(const PeerInfo&, const Message&)>;

            P2PNode(uint16_t listenPort, uint32_t networkMagic);
            ~P2PNode();

            void start();
            void stop();

            void addBootstrapPeer(const PeerInfo& p);
            void broadcastMessage(const Message& msg);
            void connectToPeer(const PeerInfo& p);

            void setMessageHandler(EventCallback cb);

            // persistent peers file
            void loadPeersFile(const string& filename);
            void savePeersFile(const string& filename);

        private:
            void doAccept();
            void onNewConnection(const PeerConnection::Ptr& conn);
            void removeConnection(const string& key);

            boost::asio::io_context io;
            boost::asio::executor_work_guard<boost::asio::io_context::executor_type> workGuard;
            tcp::acceptor acceptor;

            PeerManager peerManager;
            unordered_map<string, PeerConnection::Ptr> connections;
            mutex connMtx;

            uint32_t magic;
            EventCallback onMessage;
            uint16_t port;

            // thread for io
            thread ioThread;
            bool running = false;
    };

} // namespace p2p

#endif // P2P_NODE_HPP
