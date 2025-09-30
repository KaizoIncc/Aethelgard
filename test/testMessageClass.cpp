#include <gtest/gtest.h>
#include "Message.hpp"
#include <vector>
#include <algorithm>

using namespace p2p;

// -----------------------
// ENDINNESS TESTS
// -----------------------
TEST(EndiannessTest, UInt32RoundTrip) {
    uint32_t val = 0x12345678;
    EXPECT_EQ(ntoh32(hton32(val)), val);
}

TEST(EndiannessTest, UInt64RoundTrip) {
    uint64_t val = 0x1122334455667788ULL;
    EXPECT_EQ(ntoh64(hton64(val)), val);
}

// -----------------------
// CRC32 TEST
// -----------------------
TEST(CRC32Test, KnownValue) {
    const char* data = "hello";
    uint32_t crc = crc32_buf(data, 5);
    EXPECT_NE(crc, 0u); // solo verificamos que calcule algo
}

// -----------------------
// SERIALIZATION TESTS
// -----------------------
TEST(SerializationTest, SerializeDeserializeHeader) {
    Message msg;
    msg.magic = NETWORK_MAGIC;
    msg.version = PROTOCOL_VERSION;
    msg.type = MessageType::PING;
    msg.payload = {'a', 'b', 'c'};

    auto serialized = serializeMessage(msg);

    Message parsed;
    uint64_t payloadLen;
    ASSERT_TRUE(parseMessageHeader(serialized, parsed, payloadLen));

    EXPECT_EQ(parsed.magic, msg.magic);
    EXPECT_EQ(parsed.version, msg.version);
    EXPECT_EQ(parsed.type, msg.type);
    EXPECT_EQ(payloadLen, msg.payload.size());
}

TEST(SerializationTest, SerializeDeserializeFullMessage) {
    Message msg;
    msg.magic = NETWORK_MAGIC;
    msg.version = PROTOCOL_VERSION;
    msg.type = MessageType::TX;
    msg.payload = {'x', 'y', 'z', 0, 1, 2};

    auto serialized = serializeMessage(msg);

    Message parsed;
    ASSERT_TRUE(parseFullMessage(serialized, parsed));

    EXPECT_EQ(parsed.magic, msg.magic);
    EXPECT_EQ(parsed.version, msg.version);
    EXPECT_EQ(parsed.type, msg.type);
    EXPECT_EQ(parsed.payload, msg.payload);
}

TEST(SerializationTest, DetectCorruption) {
    Message msg;
    msg.magic = NETWORK_MAGIC;
    msg.version = PROTOCOL_VERSION;
    msg.type = MessageType::BLOCK;
    msg.payload = {'1','2','3'};

    auto serialized = serializeMessage(msg);

    // Corrupt a byte
    serialized[10] ^= 0xFF;

    Message parsed;
    EXPECT_FALSE(parseFullMessage(serialized, parsed));
}

// -----------------------
// MessageType to string
// -----------------------
TEST(MessageTypeToStringTest, KnownTypes) {
    EXPECT_EQ(messageTypeToString(MessageType::PING), "PING");
    EXPECT_EQ(messageTypeToString(MessageType::BLOCK), "BLOCK");
    EXPECT_EQ(messageTypeToString(static_cast<MessageType>(254)), "UNKNOWN");
}

// -----------------------
// STRESS TESTS
// -----------------------
TEST(StressTest, LargePayload) {
    Message msg;
    msg.magic = NETWORK_MAGIC;
    msg.version = PROTOCOL_VERSION;
    msg.type = MessageType::TX;
    msg.payload.resize(MAX_PAYLOAD_SIZE, 0xAB);

    auto serialized = serializeMessage(msg);

    Message parsed;
    ASSERT_TRUE(parseFullMessage(serialized, parsed));

    EXPECT_EQ(parsed.payload.size(), MAX_PAYLOAD_SIZE);
    EXPECT_TRUE(std::all_of(parsed.payload.begin(), parsed.payload.end(), [](uint8_t b){ return b == 0xAB; }));
}
