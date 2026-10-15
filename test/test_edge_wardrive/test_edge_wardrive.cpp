#include <gtest/gtest.h>
#include "../../examples/personal_relay/EdgeWardrive.h"

using namespace mesh;

static const uint8_t SELF[8] = {0x3a, 0x9c, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

static Packet echoOf(const uint8_t* path, uint8_t count, uint8_t size) {
  Packet p;
  p.header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_GRP_TXT << PH_TYPE_SHIFT);
  p.payload[0] = 0x11;
  p.payload_len = 1;
  p.setPathHashSizeAndCount(size, count);
  memcpy(p.path, path, (size_t)count * size);
  return p;
}

static void key(uint8_t k[EDGE_WARDRIVE_KEY_LEN], uint8_t b) { memset(k, b, EDGE_WARDRIVE_KEY_LEN); }

TEST(EdgeWardrive, KeepsThePathWhenTheRelayIsAlreadyFirst) {
  const uint8_t path[] = {0x3a, 0x76};  // relay, R1 (1-byte hashes)
  Packet e = echoOf(path, 2, 1);
  uint8_t out[MAX_PATH_SIZE], out_len = 0;
  ASSERT_TRUE(edgeWardriveEchoPath(&e, SELF, sizeof(SELF), out, out_len));
  EXPECT_EQ(out_len, e.path_len);
  EXPECT_EQ(out[0], 0x3a);
  EXPECT_EQ(out[1], 0x76);
}

TEST(EdgeWardrive, PrependsTheRelayWhenAnotherRepeaterIsFirst) {
  const uint8_t path[] = {0x76, 0x01, 0x55, 0x02};  // R2, R3 (2-byte hashes): heard the phone directly
  Packet e = echoOf(path, 2, 2);
  uint8_t out[MAX_PATH_SIZE], out_len = 0;
  ASSERT_TRUE(edgeWardriveEchoPath(&e, SELF, sizeof(SELF), out, out_len));
  EXPECT_EQ(out_len, (uint8_t)((1 << 6) | 3));  // 2-byte hashes, 3 hops
  const uint8_t want[] = {0x3a, 0x9c, 0x76, 0x01, 0x55, 0x02};
  EXPECT_EQ(memcmp(out, want, sizeof(want)), 0);
}

TEST(EdgeWardrive, RefusesNoHopsAFullPathAndAReservedSize) {
  uint8_t out[MAX_PATH_SIZE], out_len = 0;
  Packet none = echoOf(nullptr, 0, 1);
  EXPECT_FALSE(edgeWardriveEchoPath(&none, SELF, sizeof(SELF), out, out_len));
  uint8_t full[MAX_PATH_SIZE];
  memset(full, 0x77, sizeof(full));
  Packet f = echoOf(full, 32, 2);  // 64 bytes: no room for the relay
  EXPECT_FALSE(edgeWardriveEchoPath(&f, SELF, sizeof(SELF), out, out_len));
  Packet r = echoOf(full, 1, 1);
  r.path_len = (3 << 6) | 1;  // hash size 4 is reserved
  EXPECT_FALSE(edgeWardriveEchoPath(&r, SELF, sizeof(SELF), out, out_len));
  Packet wide = echoOf(full, 1, 3);
  EXPECT_FALSE(edgeWardriveEchoPath(&wide, SELF, 2, out, out_len)) << "a hash wider than the relay's prefix";
}

TEST(EdgeWardrive, HandsDownEchoesOnlyOfRememberedPostsInsideTheWindow) {
  EdgeWardriveRing ring;
  uint8_t a[EDGE_WARDRIVE_KEY_LEN], b[EDGE_WARDRIVE_KEY_LEN];
  key(a, 0xaa);
  key(b, 0xbb);
  EXPECT_FALSE(ring.takeEcho(a, 100)) << "not a post the relay sent on";
  ring.remember(a, 1000);
  EXPECT_TRUE(ring.takeEcho(a, 1000 + EDGE_WARDRIVE_WINDOW_MS));
  EXPECT_FALSE(ring.takeEcho(a, 1001 + EDGE_WARDRIVE_WINDOW_MS)) << "after the window";
  EXPECT_FALSE(ring.takeEcho(b, 1000));
}

TEST(EdgeWardrive, CapsEchoesPerPost) {
  EdgeWardriveRing ring;
  uint8_t a[EDGE_WARDRIVE_KEY_LEN];
  key(a, 0xaa);
  ring.remember(a, 0);
  for (int i = 0; i < EDGE_WARDRIVE_MAX_ECHO; i++) EXPECT_TRUE(ring.takeEcho(a, 10));
  EXPECT_FALSE(ring.takeEcho(a, 10));
}

TEST(EdgeWardrive, TheOldestPostIsForgottenWhenTheRingIsFull) {
  EdgeWardriveRing ring;
  uint8_t k[EDGE_WARDRIVE_KEY_LEN];
  for (int i = 0; i <= EDGE_WARDRIVE_SLOTS; i++) {
    key(k, (uint8_t)i);
    ring.remember(k, 0);
  }
  key(k, 0);
  EXPECT_FALSE(ring.takeEcho(k, 1)) << "slot 0 was reused";
  key(k, EDGE_WARDRIVE_SLOTS);
  EXPECT_TRUE(ring.takeEcho(k, 1));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
