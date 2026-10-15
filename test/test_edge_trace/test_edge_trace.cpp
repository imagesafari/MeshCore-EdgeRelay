#include <gtest/gtest.h>
#include "../../examples/personal_relay/EdgeTrace.h"

using namespace mesh;

// This node's public key prefix (8 bytes, as the relay hands it to the classifier).
static const uint8_t SELF[8] = {0x3a, 0x9c, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

// A direct TRACE as stock Mesh::createTrace() + sendDirect() build it: tag, auth, flags, then the hop list;
// `done` hops already passed (each appended one SNR to path).
static Packet makeTrace(const uint8_t* hops, uint8_t hops_len, uint8_t size_bits, uint8_t done,
                        uint8_t route = ROUTE_TYPE_DIRECT, uint8_t type = PAYLOAD_TYPE_TRACE) {
  Packet p;
  p.header = route | (type << PH_TYPE_SHIFT);
  memset(p.payload, 0, 8);  // tag, auth
  p.payload[8] = size_bits;
  memcpy(&p.payload[9], hops, hops_len);
  p.payload_len = 9 + hops_len;
  p.path_len = done;
  for (uint8_t i = 0; i < done; i++) p.path[i] = 40;  // SNR readings, not hashes
  return p;
}

TEST(EdgeTrace, RelaysWhenItIsTheFirstHop) {
  const uint8_t hops[] = {0x3a, 0x76, 0x3a};  // car, repeater, car (1-byte hashes)
  auto p = makeTrace(hops, sizeof(hops), 0, 0);
  EXPECT_TRUE(edgeTraceNextHopIsSelf(&p, SELF, sizeof(SELF)));
}

TEST(EdgeTrace, RelaysOnTheWayBackAndNotWhenAnotherHopIsNext) {
  const uint8_t hops[] = {0x3a, 0x76, 0x3a};
  auto back = makeTrace(hops, sizeof(hops), 0, 2);  // car and repeater done: the car is next again
  EXPECT_TRUE(edgeTraceNextHopIsSelf(&back, SELF, sizeof(SELF)));
  auto mid = makeTrace(hops, sizeof(hops), 0, 1);  // the repeater is next
  EXPECT_FALSE(edgeTraceNextHopIsSelf(&mid, SELF, sizeof(SELF)));
}

TEST(EdgeTrace, UsesTheTracesOwnHashSizeNotThePathField) {
  const uint8_t hops[] = {0x76, 0xd9, 0x3a, 0x9c};  // 2-byte hashes: repeater, then the car
  auto p = makeTrace(hops, sizeof(hops), 1, 1);
  EXPECT_TRUE(edgeTraceNextHopIsSelf(&p, SELF, sizeof(SELF)));
  const uint8_t near[] = {0x76, 0xd9, 0x3a, 0x9d};  // same first byte, different second: not us
  auto q = makeTrace(near, sizeof(near), 1, 1);
  EXPECT_FALSE(edgeTraceNextHopIsSelf(&q, SELF, sizeof(SELF)));
}

TEST(EdgeTrace, NeverRelaysPastTheEndOrOtherPacketsOrAFlood) {
  const uint8_t hops[] = {0x3a};
  auto done = makeTrace(hops, sizeof(hops), 0, 1);  // its last hop passed: it is on its way home
  EXPECT_FALSE(edgeTraceNextHopIsSelf(&done, SELF, sizeof(SELF)));
  auto msg = makeTrace(hops, sizeof(hops), 0, 0, ROUTE_TYPE_DIRECT, PAYLOAD_TYPE_TXT_MSG);
  EXPECT_FALSE(edgeTraceNextHopIsSelf(&msg, SELF, sizeof(SELF)));
  auto flood = makeTrace(hops, sizeof(hops), 0, 0, ROUTE_TYPE_FLOOD);
  EXPECT_FALSE(edgeTraceNextHopIsSelf(&flood, SELF, sizeof(SELF)));
  Packet tiny = makeTrace(hops, sizeof(hops), 0, 0);
  tiny.payload_len = 5;  // shorter than its header
  EXPECT_FALSE(edgeTraceNextHopIsSelf(&tiny, SELF, sizeof(SELF)));
}

TEST(EdgeTrace, NeedsEnoughOfOurOwnKeyForTheHashSize) {
  const uint8_t hops[] = {0x3a, 0x9c, 0x11, 0x22};  // one 4-byte hash
  auto p = makeTrace(hops, sizeof(hops), 2, 0);
  EXPECT_TRUE(edgeTraceNextHopIsSelf(&p, SELF, sizeof(SELF)));
  EXPECT_FALSE(edgeTraceNextHopIsSelf(&p, SELF, 2)) << "only 2 bytes of our key held: cannot match 4";
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
