#include "P2PNode.hpp"

namespace p2p {

    P2PNode::P2PNode(uint16_t listenPort, uint32_t networkMagic) 
        : io(), 
        acceptor(io, tcp::endpoint(tcp::v4(), listenPort)), 
        magic(networkMagic), 
        port(listenPort), 
        workGuard(boost::asio::make_work_guard(io)) {}

    P2PNode::~P2PNode() {
        stop();
    }

    void P2PNode::start() {
        if (running) return;
        
        running = true;
        doAccept();
        
        // Ejecutar io_context en hilo en segundo plano
        ioThread = thread([this] { io.run(); });
        
        // Conectar a peers conocidos (no bloqueante, puede extenderse)
        auto knownPeers = peerManager.selectPeersToConnect(8);
        for (auto& peer : knownPeers) {
            connectToPeer(peer);
        }
    }

    void P2PNode::stop() {
        if (!running) return;
        
        running = false;
        workGuard.reset();
        
        boost::system::error_code errorCode;
        acceptor.close(errorCode);

        // Cerrar conexiones
        {
            lock_guard<mutex> connectionLock(connMtx);
            for (auto& [key, connection] : connections) {
                boost::system::error_code closeError;
                connection->socket().close(closeError);
            }
            connections.clear();
        }

        io.stop();
        if (ioThread.joinable()) ioThread.join();
    }

    void P2PNode::addBootstrapPeer(const PeerInfo& peer) {
        peerManager.addKnownPeer(peer);
    }

    void P2PNode::broadcastMessage(const Message& message) {
        lock_guard<mutex> connectionLock(connMtx);
        for (auto& [key, connection] : connections) {
            try {
                connection->sendMessage(message);
            } catch (...) {
                // Ignorar errores de envío
            }
        }
    }

    void P2PNode::connectToPeer(const PeerInfo& peer) {
        auto connection = make_shared<PeerConnection>(io);
        
        connection->setMessageHandler([this](const PeerInfo& peerInfo, const Message& message) {
            if (onMessage) onMessage(peerInfo, message);
        });
        
        connection->connectTo(peer);

        lock_guard<mutex> connectionLock(connMtx);
        connections[peer.key()] = connection;
        peerManager.markSeen(peer);
    }

    void P2PNode::setMessageHandler(EventCallback callback) { 
        onMessage = move(callback); 
    }

    void P2PNode::doAccept() {
        auto connection = make_shared<PeerConnection>(io);
        
        acceptor.async_accept(connection->socket(), 
            [this, connection](const boost::system::error_code& errorCode) {
                if (!errorCode) {
                    try {
                        auto endpoint = connection->socket().remote_endpoint();
                        PeerInfo peerInfo;
                        peerInfo.host = endpoint.address().to_string();
                        peerInfo.port = static_cast<uint16_t>(endpoint.port());
                        
                        connection->setMessageHandler([this](const PeerInfo& peer, const Message& message) {
                            if (onMessage) onMessage(peer, message);
                        });
                        
                        connection->start();
                        
                        lock_guard<mutex> connectionLock(connMtx);
                        connections[peerInfo.key()] = connection;
                        peerManager.markSeen(peerInfo);
                        
                    } catch (...) {
                        // Ignorar excepciones durante la aceptación
                    }
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

    void P2PNode::onNewConnection(const PeerConnection::Ptr& connection) {
        // No utilizado actualmente; placeholder para futura extensión
    }

    void P2PNode::removeConnection(const string& key) {
        lock_guard<mutex> connectionLock(connMtx);
        connections.erase(key);
    }

} // namespace p2p