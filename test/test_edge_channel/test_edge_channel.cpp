#include <gtest/gtest.h>
#include "../../examples/personal_relay/EdgeChannel.h"

// Runs in env:native_real_crypto, on the firmware's own SHA-256 (rweather/Crypto): test/mocks/SHA256.h would
// give the right derivation and the classic mistake (the key's own first byte) the same answer. Expected
// values worked out apart from the firmware, with Python's hashlib.

TEST(EdgeChannel, RunsOnRealSha256) {
  uint8_t h[4];
  mesh::Utils::sha256(h, sizeof(h), (const uint8_t*)"abc", 3);  // FIPS 180-2 test vector: ba7816bf...
  EXPECT_EQ(h[0], 0xba);
  EXPECT_EQ(h[1], 0x78);
  EXPECT_EQ(h[2], 0x16);
  EXPECT_EQ(h[3], 0xbf);
}

static uint8_t hashOf(const char* arg, const char** name = nullptr) {
  uint8_t h = 0;
  const char *n = "", *err = "";
  EXPECT_TRUE(edgeChannelHash(arg, &h, &n, &err)) << arg << ": " << err;
  if (name) *name = n;
  return h;
}

static const char* errOf(const char* arg) {
  uint8_t h;
  const char *n, *err = "";
  EXPECT_FALSE(edgeChannelHash(arg, &h, &n, &err)) << arg;
  return err;
}

// What a hashtag channel's hash is, step by step: key = sha256(name)[:16], hash = sha256(key)[0].
static uint8_t hashtag(const char* name) {
  uint8_t key[32], h;
  mesh::Utils::sha256(key, sizeof(key), (const uint8_t*)name, (int)strlen(name));
  mesh::Utils::sha256(&h, 1, key, 16);
  return h;
}

TEST(EdgeChannel, TwoHexIsTheHashItself) {
  const char* name;
  EXPECT_EQ(hashOf("11", &name), 0x11);
  EXPECT_STREQ(name, "");
  EXPECT_EQ(hashOf("8B"), 0x8b);
}

TEST(EdgeChannel, PublicIsTheHashOfItsKeyNotTheKeysFirstByte) {
  const char* name;
  uint8_t want;
  mesh::Utils::sha256(&want, 1, EDGE_PUBLIC_KEY, 16);
  EXPECT_EQ(hashOf("Public", &name), want);
  EXPECT_EQ(hashOf("Public"), 0x11);
  EXPECT_STREQ(name, "Public");
  EXPECT_EQ(hashOf("public"), want);
  EXPECT_EQ(EDGE_PUBLIC_KEY[0], 0x8b);  // what an app shows: the wrong byte to give
  EXPECT_EQ(EDGE_PUBLIC_KEY[15], 0x72);  // izOH6cXN6mrJ5e26oRXNcg== is 8b3387e9…a115cd72
}

TEST(EdgeChannel, HashtagChannelsFromTheirNameAsTyped) {
  const char* name;
  EXPECT_EQ(hashOf("#test", &name), 0xd9);  // its key starts 9c: the wrong byte to give
  EXPECT_STREQ(name, "#test");
  EXPECT_EQ(hashOf("#test"), hashtag("#test"));
  EXPECT_EQ(hashOf("#wardriving"), 0x81);
  EXPECT_EQ(hashOf("#a"), 0x25);
  EXPECT_NE(hashOf("#test"), hashtag("test")) << "the # is part of what is hashed";
  EXPECT_EQ(hashOf("#Test"), 0xba) << "no change of case";
}

TEST(EdgeChannel, RefusesWhatItCannotResolve) {
  const char* any = "Err - give 2 hex (the channel hash), Public, or #name";
  EXPECT_STREQ(errOf("Pub"), any);
  EXPECT_STREQ(errOf("1"), any);
  EXPECT_STREQ(errOf("zz"), any);
  EXPECT_STREQ(errOf("#"), any);
  EXPECT_STREQ(errOf("#two words"), "Err - a #name has no spaces");
  EXPECT_STREQ(errOf("#abcdefghijklmnopqrstuvwxyz12345"), any);  // 32 chars: one too long
  EXPECT_EQ(hashOf("#abcdefghijklmnopqrstuvwxyz1234"), 0x12);  // 31: fits
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
