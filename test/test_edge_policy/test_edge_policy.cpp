#include <gtest/gtest.h>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>

// The relay's EdgePolicy.cpp reads and writes the filesystem itself, so it is built here against an in-memory one:
// just what EdgePolicy.cpp asks of the ESP32 FS (open for read, open "w", remove, rename) and of its File.
struct MockFile {
  std::string* buf = nullptr;
  size_t pos = 0;
  bool fail = false;  // writes do not reach the file
  explicit operator bool() const { return buf != nullptr; }
  int read() { return pos < buf->size() ? (unsigned char)(*buf)[pos++] : -1; }
  size_t write(const uint8_t* b, size_t n) {
    if (fail) return 0;
    buf->append((const char*)b, n);
    return n;
  }
  size_t print(const char* s) { return write((const uint8_t*)s, strlen(s)); }
  size_t println(const char* s) { return print(s) + print("\r\n"); }
  void close() {}
};

struct MockFS {
  std::map<std::string, std::string> files;
  bool fail_writes = false;       // a full or failing flash: files open, but nothing is written
  bool rename_overwrites = true;  // LittleFS does; SPIFFS refuses when the target exists
  MockFile open(const char* path, const char* mode = "r", bool /* create */ = false) {
    MockFile f;
    if (mode[0] == 'w') {
      files[path].clear();
      f.buf = &files[path];
      f.fail = fail_writes;
    } else if (files.count(path)) {
      f.buf = &files[path];
    }
    return f;
  }
  bool mkdir(const char*) { return true; }
  bool remove(const char* path) { return files.erase(path) > 0; }
  bool rename(const char* from, const char* to) {
    if (!files.count(from) || (!rename_overwrites && files.count(to))) return false;
    files[to] = files[from];
    files.erase(from);
    return true;
  }
};

#define FILESYSTEM MockFS
using File = MockFile;
#include "../../examples/personal_relay/EdgePolicy.cpp"

using namespace mesh;

// This node's public key prefix, as the relay hands it to the classifier.
static const uint8_t SELF[EDGE_SELF_HASH_MAX] = {0x3a, 0x9c, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
static const uint8_t OWNER = 0xb1;  // first byte (1-byte hash) of the owner's key
static const uint8_t CHAN = 0x7e;   // an opted-in channel hash

static void ownerKey(uint8_t key[PUB_KEY_SIZE], uint8_t first) {
  memset(key, 0x11, PUB_KEY_SIZE);
  key[0] = first;
}

// A policy is valid once saved, as `edge owner add` makes it.
static EdgePolicy validPolicy() {
  EdgePolicy p;
  uint8_t key[PUB_KEY_SIZE];
  ownerKey(key, OWNER);
  p.addOwner(key);
  p.addChannel(CHAN);
  MockFS fs;
  p.save(&fs);
  return p;
}

static EdgeStats sampleStats() {
  EdgeStats s;
  s.clear();
  s.boot[ES_UPLINK] = 12;
  s.boot[ES_COPY] = 3;
  s.boot[ES_DIRECT] = 3;
  s.boot[ES_ACK] = 1;  // dfwd 4: direct and receipts
  s.boot[ES_TRACE] = 2;
  s.boot[ES_DROP_POLICY] = 35;
  s.boot[ES_RL_COPY] = 5;  // drop 40: every reason
  s.boot[ES_WD_ECHO] = 7;
  return s;
}

TEST(EdgePolicyFile, TheOwnerKeyByHashIsTheFirstMatch) {
  auto p = validPolicy();
  ASSERT_NE(p.ownerKeyByHash(OWNER), nullptr);
  EXPECT_EQ(p.ownerKeyByHash(OWNER)[0], OWNER);
  EXPECT_EQ(p.ownerKeyByHash(0x42), nullptr);
}

TEST(EdgePolicyFile, APolicyRoundTripsThroughItsFile) {
  MockFS fs;
  EdgePolicy p = validPolicy();
  p.setFwdAcks(true);
  ASSERT_TRUE(p.save(&fs));
  EdgePolicy q;
  ASSERT_TRUE(q.load(&fs));
  EXPECT_EQ(q.getNumOwners(), 1);
  EXPECT_EQ(q.getChannelHash(0), CHAN);
  EXPECT_TRUE(q.getFwdAcks());
  fs.files[EDGE_POLICY_FILE] += "something_new 1\n";
  EXPECT_FALSE(q.load(&fs)) << "an unknown line fails closed";
  EXPECT_EQ(q.getNumOwners(), 0);
}

#include "test_edge_stats.inc"

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
