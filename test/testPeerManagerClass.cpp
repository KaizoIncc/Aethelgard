#include <gtest/gtest.h>
#include "PeerManager.hpp"
#include <fstream>
#include <chrono>
#include <thread>

using namespace p2p;

// -----------------------
// HELPER FUNCTIONS
// -----------------------
PeerInfo makePeer(const string& host, uint16_t port, int score = 0, const string& nodeId = "") {
    PeerInfo p;
    p.host = host;
    p.port = port;
    p.score = score;
    p.nodeId = nodeId;
    return p;
}

// -----------------------
// BASIC TESTS
// -----------------------
TEST(PeerManagerTest, AddAndGetPeers) {
    PeerManager pm;
    PeerInfo p1 = makePeer("127.0.0.1", 8000);
    pm.addKnownPeer(p1);

    auto peers = pm.getKnownPeers();
    ASSERT_EQ(peers.size(), 1);
    EXPECT_EQ(peers[0].host, "127.0.0.1");
    EXPECT_EQ(peers[0].port, 8000);
}

TEST(PeerManagerTest, MarkSeenUpdatesExistingPeer) {
    PeerManager pm;
    PeerInfo p = makePeer("127.0.0.1", 8000, 5);
    pm.addKnownPeer(p);

    this_thread::sleep_for(chrono::milliseconds(10));
    pm.markSeen(p); // should increment score and update lastSeen

    auto peers = pm.getKnownPeers();
    ASSERT_EQ(peers.size(), 1);
    EXPECT_EQ(peers[0].score, 6);
    EXPECT_GT(peers[0].lastSeen.time_since_epoch().count(), p.lastSeen.time_since_epoch().count());
}

TEST(PeerManagerTest, MarkSeenAddsNewPeer) {
    PeerManager pm;
    PeerInfo p = makePeer("192.168.1.1", 9000);
    pm.markSeen(p);

    auto peers = pm.getKnownPeers();
    ASSERT_EQ(peers.size(), 1);
    EXPECT_EQ(peers[0].host, "192.168.1.1");
    EXPECT_EQ(peers[0].port, 9000);
    EXPECT_EQ(peers[0].score, 0);
}

TEST(PeerManagerTest, SelectPeersToConnectOrdersByScoreAndLastSeen) {
    PeerManager pm;
    auto now = chrono::system_clock::now();

    PeerInfo p1 = makePeer("1", 1, 5); pm.addKnownPeer(p1);
    PeerInfo p2 = makePeer("2", 2, 10); pm.addKnownPeer(p2);
    PeerInfo p3 = makePeer("3", 3, 5); pm.addKnownPeer(p3);

    auto selected = pm.selectPeersToConnect(2);
    ASSERT_EQ(selected.size(), 2);
    EXPECT_EQ(selected[0].host, "2"); // highest score first
}

TEST(PeerManagerTest, PersistAndLoadFromDisk) {
    PeerManager pm;
    PeerInfo p1 = makePeer("host1", 1000, 0, "node1");
    PeerInfo p2 = makePeer("host2", 2000);
    pm.addKnownPeer(p1);
    pm.addKnownPeer(p2);

    string filename = "test_peers.txt";
    ASSERT_TRUE(pm.persist(filename));

    PeerManager pm2;
    ASSERT_TRUE(pm2.loadFromDisk(filename));

    auto peers = pm2.getKnownPeers();
    ASSERT_EQ(peers.size(), 2);
    EXPECT_TRUE((peers[0].host == "host1" || peers[1].host == "host1"));
    EXPECT_TRUE((peers[0].host == "host2" || peers[1].host == "host2"));

    remove(filename.c_str());
}

// -----------------------
// STRESS TESTS
// -----------------------
TEST(PeerManagerTest, StressAddManyPeers) {
    PeerManager pm;
    const int N = 10000;

    for (int i = 0; i < N; ++i) {
        pm.addKnownPeer(makePeer("10.0.0." + to_string(i), 8000 + i, i % 50));
    }

    auto peers = pm.selectPeersToConnect(50);
    ASSERT_EQ(peers.size(), 50);
    EXPECT_TRUE(all_of(peers.begin(), peers.end(), [](const PeerInfo& p){ return p.score >= 0; }));
}

TEST(PeerManagerTest, StressPersistLoadLargeNumber) {
    PeerManager pm;
    const int N = 1000;
    for (int i = 0; i < N; ++i)
        pm.addKnownPeer(makePeer("172.16.0." + to_string(i), 1000 + i));

    string filename = "large_peers.txt";
    ASSERT_TRUE(pm.persist(filename));

    PeerManager pm2;
    ASSERT_TRUE(pm2.loadFromDisk(filename));
    EXPECT_EQ(pm2.getKnownPeers().size(), N);

    remove(filename.c_str());
}
