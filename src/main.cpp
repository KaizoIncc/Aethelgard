#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

#include "Utils.hpp"
#include "BlockchainStorage.hpp"
#include "P2PNode.hpp"
#include "Consensus.hpp"
#include "ProofOfAuction.hpp"

using namespace std;

static atomic<bool> g_running(true);

void signal_handler(int signum){
    (void)signum;
    g_running = false;
}

int main(int argc, char** argv) {
    ios::sync_with_stdio(false);
    string datadir = "./data";
    uint16_t port = 30303;
    uint32_t magic = 0xA1B2C3D4;

    if (argc > 1) datadir = argv[1];
    if (argc > 2) port = static_cast<uint16_t>(atoi(argv[2]));

    cout << "Aethelgard node starting. datadir=" << datadir << " port=" << port << endl;

    // Initialize libsodium via CryptoUtils
    if (!CryptoUtils::initialize()) {
        cerr << "Failed to initialize crypto (sodium)." << endl;
        return 1;
    }

    // Initialize storage
    BlockchainStorage storage(datadir);
    if (!storage.initialize()) {
        cerr << "Failed to initialize storage at " << datadir << endl;
        return 1;
    }

    // Initialize P2P node
    p2p::P2PNode node(port, magic);
    node.start();

    // Initialize consensus (Proof of Auction stub)
    ProofOfAuction consensus;
    // In future: wire consensus with p2p and storage

    // Handle signals
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    cout << "Node running. Press Ctrl+C to exit." << endl;
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    cout << "Shutting down..." << endl;
    node.stop();
    // flush storage if needed (destructor will handle)
    return 0;
}
