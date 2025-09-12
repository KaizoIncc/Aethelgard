#include "P2PNode.hpp"
#include <iostream>
#include <chrono>

namespace p2p {

    P2PNode::P2PNode(uint16_t listenPort, uint32_t networkMagic) : io(), acceptor(io, tcp::endpoint(tcp::v4(), listenPort)), magic(networkMagic), port(listenPort), workGuard(boost::asio::make_work_guard(io)) {}

    P2PNode::~P2PNode() {
        stop();
    }

    void P2PNode::start() {
        if (running) return;
        running = true;
        doAccept();
        // run io_context in background thread
        ioThread = thread([this]{ io.run(); });
        // small scheduler: connect to known peers (non-blocking, can be extended)
        auto known = peerManager.selectPeersToConnect(8);
        for (auto &p : known) connectToPeer(p);
    }

    void P2PNode::stop() {
        if (!running) return;
        running = false;
        workGuard.reset();
        boost::system::error_code ec;
        acceptor.close(ec);

        // Close connections
        {
            lock_guard<mutex> lk(connMtx);
            for (auto &kv : connections) {
                boost::system::error_code e2;
                kv.second->socket().close(e2);
            }
            connections.clear();
        }

        io.stop();
        if (ioThread.joinable()) ioThread.join();
    }

    void P2PNode::addBootstrapPeer(const PeerInfo& p) {
        peerManager.addKnownPeer(p);
    }

    void P2PNode::broadcastMessage(const Message& msg) {
        lock_guard<mutex> lk(connMtx);
        for (auto &kv : connections) {
            try {
                kv.second->sendMessage(msg);
            } catch (...) {}
        }
    }

    void P2PNode::connectToPeer(const PeerInfo& p) {
        auto conn = make_shared<PeerConnection>(io);
        conn->setMessageHandler([this](const PeerInfo& peer, const Message& m){
            // forward to application handler
            if (onMessage) onMessage(peer, m);
        });
        conn->connectTo(p);

        lock_guard<mutex> lk(connMtx);
        connections[p.key()] = conn;
        peerManager.markSeen(p);
    }

    void P2PNode::setMessageHandler(EventCallback cb) { onMessage = move(cb); }

    void P2PNode::doAccept() {
        auto conn = make_shared<PeerConnection>(io);
        acceptor.async_accept(conn->socket(), [this, conn](const boost::system::error_code& ec){
            if (!ec) {
                // populate peer info from endpoint
                try {
                    auto ep = conn->socket().remote_endpoint();
                    PeerInfo pi;
                    pi.host = ep.address().to_string();
                    pi.port = static_cast<uint16_t>(ep.port());
                    conn->setMessageHandler([this](const PeerInfo& peer, const Message& m){
                        if (onMessage) onMessage(peer, m);
                    });
                    conn->start();
                    lock_guard<mutex> lk(connMtx);
                    connections[pi.key()] = conn;
                    peerManager.markSeen(pi);
                } catch (...) {}
            }
            if (running) doAccept();
        });
    }

    void P2PNode::loadPeersFile(const string& filename) {
        peerManager.loadFromDisk(filename);
    }

    void P2PNode::savePeersFile(const string& filename) {
        peerManager.persist(filename);
    }

    void P2PNode::onNewConnection(const PeerConnection::Ptr& conn) {
        // not used currently; placeholder hook
    }

    void P2PNode::removeConnection(const string& key) {
        lock_guard<mutex> lk(connMtx);
        connections.erase(key);
    }

} // namespace p2p
