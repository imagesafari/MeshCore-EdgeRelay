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
  bool fail_renames = false;      // every rename fails (as if power went before it, or the flash refused it)
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
    if (fail_renames || !files.count(from) || (!rename_overwrites && files.count(to))) return false;
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

static EdgeAction cls(const EdgePolicy& p, const Packet& k) { return p.classify(&k, SELF, sizeof(SELF)); }

// A direct TRACE as heard: 1-byte hop hashes, `done` of them already passed (each appended one SNR), heard at `snr`.
static Packet trace(const uint8_t* hops, uint8_t n, uint8_t done, float snr = 0) {
  Packet p;
  p._snr = (int8_t)(snr * 4);  // Packet() leaves it unset: a test must not read whatever was there
  p.header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_TRACE << PH_TYPE_SHIFT);
  memset(p.payload, 0, 8);
  p.payload[8] = 0;  // 1-byte hop hashes
  memcpy(&p.payload[9], hops, n);
  p.payload_len = 9 + n;
  p.path_len = done;
  return p;
}

TEST(EdgePolicyRules, ATraceNamingThisNodeIsRelayedEvenWithAnEmptyPath) {
  auto p = validPolicy();
  const uint8_t via_us[] = {SELF[0], 0x76};
  // path_len 0 would read as "zero-hop direct" to the rule below it, which drops traces.
  EXPECT_EQ(cls(p, trace(via_us, sizeof(via_us), 0)), EDGE_STOCK);
  const uint8_t via_other[] = {0x76, SELF[0]};
  EXPECT_EQ(cls(p, trace(via_other, sizeof(via_other), 0)), EDGE_DROP);
  EXPECT_EQ(cls(p, trace(via_other, sizeof(via_other), 1)), EDGE_STOCK);
}

// --- transparent trace: a fresh trace not naming us, heard loud, goes out; its result comes back ---

TEST(EdgeTransparentTrace, ItIsOffUntilTurnedOn) {
  auto p = validPolicy();
  EXPECT_EQ(p.getTraceSnr(), EDGE_TRACE_SNR_OFF);
  const uint8_t r1[] = {0x94};
  EXPECT_EQ(cls(p, trace(r1, 1, 0, 20)), EDGE_DROP) << "a loud fresh trace not naming us";
  EXPECT_EQ(cls(p, trace(r1, 1, 1, 20)), EDGE_DROP) << "a completed one is not ours to hand back";
  const uint8_t via_us[] = {SELF[0], 0x94};
  EXPECT_EQ(cls(p, trace(via_us, 2, 0, 12)), EDGE_STOCK) << "a trace naming us is relayed as always";
  EXPECT_EQ(EdgePolicy().getTraceSnr(), EDGE_TRACE_SNR_OFF) << "nothing loaded";
}

TEST(EdgeTransparentTrace, AFreshLoudTraceNotNamingUsGoesThroughAQuietOneDoesNot) {
  auto p = validPolicy();
  ASSERT_TRUE(p.setTraceSnr(EDGE_TRACE_SNR_ON));
  const uint8_t r1[] = {0x94};  // MeshMapper's trace mode: just the repeater it maps
  EXPECT_EQ(cls(p, trace(r1, 1, 0, 11.5)), EDGE_TRACE_THROUGH) << "an owner's, in the car";
  EXPECT_EQ(cls(p, trace(r1, 1, 0, EDGE_TRACE_SNR_ON)), EDGE_TRACE_THROUGH) << "at the threshold";
  EXPECT_EQ(cls(p, trace(r1, 1, 0, 2.0)), EDGE_DROP) << "quiet: not from inside the car";
  const uint8_t two[] = {0x94, 0x73};
  EXPECT_EQ(cls(p, trace(two, 2, 1, 12)), EDGE_DROP) << "already on its way, not to us: not ours to send";
  const uint8_t via_us[] = {SELF[0], 0x94};
  EXPECT_EQ(cls(p, trace(via_us, 2, 0, 12)), EDGE_STOCK) << "naming us: relayed as before";
}

TEST(EdgeTransparentTrace, ACompletedTraceIsACandidateToHandBack) {
  auto p = validPolicy();
  ASSERT_TRUE(p.setTraceSnr(EDGE_TRACE_SNR_ON));
  const uint8_t r1[] = {0x94};
  EXPECT_EQ(cls(p, trace(r1, 1, 1, -3)), EDGE_TRACE_BACK) << "R1 sent it back with its SNR: done";
  const uint8_t three[] = {0x73, 0x94, 0x73};
  EXPECT_EQ(cls(p, trace(three, 3, 3, 9)), EDGE_TRACE_BACK);
  EXPECT_TRUE(edgeTraceComplete(&static_cast<const Packet&>(trace(three, 3, 3))));
  EXPECT_FALSE(edgeTraceComplete(&static_cast<const Packet&>(trace(three, 3, 2))));
}

TEST(EdgeTransparentTrace, OffMeansTracesAreOnlyRelayedWhenNamed) {
  auto p = validPolicy();
  ASSERT_TRUE(p.setTraceSnr(EDGE_TRACE_SNR_ON));
  ASSERT_TRUE(p.setTraceSnr(EDGE_TRACE_SNR_OFF));
  const uint8_t r1[] = {0x94};
  EXPECT_EQ(cls(p, trace(r1, 1, 0, 12)), EDGE_DROP);
  EXPECT_EQ(cls(p, trace(r1, 1, 1, 12)), EDGE_DROP);
  EXPECT_FALSE(p.setTraceSnr(31));
  EXPECT_FALSE(p.setTraceSnr(-21));
}

TEST(EdgeTransparentTrace, AnInvalidPolicySendsNoTraceThrough) {
  EdgePolicy p;  // nothing loaded: fail closed
  const uint8_t r1[] = {0x94};
  EXPECT_EQ(cls(p, trace(r1, 1, 0, 12)), EDGE_DROP);
  EXPECT_EQ(cls(p, trace(r1, 1, 1, 12)), EDGE_DROP);
}

TEST(EdgeTransparentTrace, TheRingHandsBackOnceInsideItsWindow) {
  EdgeTraceRing r;
  r.remember(0xAABBCCDD, 1000);
  EXPECT_FALSE(r.take(0x11111111, 1500)) << "someone else's";
  EXPECT_TRUE(r.take(0xAABBCCDD, 1000 + EDGE_TRACE_BACK_MS));
  EXPECT_FALSE(r.take(0xAABBCCDD, 1001)) << "once";
  r.remember(0x01020304, 1000);
  EXPECT_FALSE(r.take(0x01020304, 1001 + EDGE_TRACE_BACK_MS)) << "too late";
  for (uint32_t i = 0; i < EDGE_TRACE_RING + 1; i++) r.remember(100 + i, 5000);
  EXPECT_FALSE(r.take(100, 5001)) << "the oldest gave way";
  EXPECT_TRUE(r.take(100 + EDGE_TRACE_RING, 5001));
}

static std::string traceSnr(EdgePolicy& p, const char* arg, bool* changed = nullptr) {
  char reply[EDGE_REPLY_MAX];
  memset(reply, 'x', sizeof(reply));
  bool c = edgeTraceSnrCommand(p, arg, reply, sizeof(reply));
  if (changed) *changed = c;
  EXPECT_LT(strlen(reply), (size_t)EDGE_REPLY_MAX) << arg;
  return reply;
}

TEST(EdgeTransparentTrace, TheThresholdIsSetSavedAndRead) {
  auto p = validPolicy();
  EXPECT_EQ(traceSnr(p, ""), "OK - transparent trace off") << "off until turned on";
  bool changed;
  EXPECT_EQ(traceSnr(p, "on", &changed), "OK - transparent trace: traces heard at 6 dB or better");
  EXPECT_TRUE(changed);
  EXPECT_EQ(p.getTraceSnr(), EDGE_TRACE_SNR_ON);
  EXPECT_EQ(traceSnr(p, "9", &changed), "OK - transparent trace: traces heard at 9 dB or better");
  EXPECT_TRUE(changed);
  EXPECT_EQ(traceSnr(p, "99", &changed).rfind("Err - trace_snr", 0), 0u);
  EXPECT_FALSE(changed);
  EXPECT_EQ(traceSnr(p, "9x").rfind("Err - trace_snr", 0), 0u);
  EXPECT_EQ(traceSnr(p, "127").rfind("Err - trace_snr", 0), 0u) << "off is spelled off";
  EXPECT_EQ(traceSnr(p, "loud").rfind("Err - trace_snr", 0), 0u);
  EXPECT_EQ(traceSnr(p, "on6").rfind("Err - trace_snr", 0), 0u);
  EXPECT_EQ(p.getTraceSnr(), 9) << "a bad value changes nothing";
  MockFS fs;
  ASSERT_TRUE(p.save(&fs));
  EXPECT_NE(fs.files[EDGE_POLICY_FILE].find("trace_snr 9\r\n"), std::string::npos);
  EdgePolicy q;
  ASSERT_TRUE(q.load(&fs));
  EXPECT_EQ(q.getTraceSnr(), 9);
  EXPECT_EQ(traceSnr(p, "off"), "OK - transparent trace off");
  ASSERT_TRUE(p.save(&fs));
  ASSERT_TRUE(q.load(&fs));
  EXPECT_EQ(q.getTraceSnr(), EDGE_TRACE_SNR_OFF);
  EXPECT_EQ(traceSnr(p, "-20"), "OK - transparent trace: traces heard at -20 dB or better");
  EdgePolicy d = validPolicy();
  ASSERT_TRUE(d.save(&fs));
  EXPECT_NE(fs.files[EDGE_POLICY_FILE].find("trace_snr off\r\n"), std::string::npos)
      << "off is written too: v0.4.0-beta.1 reads a missing line as on";
  ASSERT_TRUE(d.setTraceSnr(EDGE_TRACE_SNR_ON));
  ASSERT_TRUE(d.save(&fs));
  EXPECT_NE(fs.files[EDGE_POLICY_FILE].find("trace_snr 6\r\n"), std::string::npos) << "and so is on";
  EdgePolicy back;
  ASSERT_TRUE(back.load(&fs));
  EXPECT_EQ(back.getTraceSnr(), EDGE_TRACE_SNR_ON) << "on survives a save and reload";
}

TEST(EdgeTransparentTrace, AnOlderFileWithNoLineReadsAsOff) {
  // v0.4.0-beta.1 left the line out at its default (on, 6 dB): such a file now reads as off.
  MockFS fs;
  auto p = validPolicy();
  ASSERT_TRUE(p.save(&fs));
  std::string& s = fs.files[EDGE_POLICY_FILE];
  size_t at = s.find("trace_snr ");
  if (at != std::string::npos) s.erase(at, s.find('\n', at) + 1 - at);
  ASSERT_EQ(s.find("trace_snr"), std::string::npos);
  ASSERT_NE(s.find("owner "), std::string::npos) << "the rest of the file is kept";
  EdgePolicy q;
  ASSERT_TRUE(q.load(&fs));
  EXPECT_EQ(q.getTraceSnr(), EDGE_TRACE_SNR_OFF);
}

TEST(EdgeTransparentTrace, ABadThresholdInTheFileFailsClosed) {
  MockFS fs;
  auto p = validPolicy();
  ASSERT_TRUE(p.setTraceSnr(9));  // read before the bad line: must not survive it
  ASSERT_TRUE(p.save(&fs));
  std::string good = fs.files[EDGE_POLICY_FILE];
  for (const char* bad : {"trace_snr 31\n", "trace_snr\n", "trace_snr x\n", "trace_snr 5 6\n"}) {
    fs.files[EDGE_POLICY_FILE] = good + bad;
    EdgePolicy q;
    EXPECT_FALSE(q.load(&fs)) << bad;
    EXPECT_FALSE(q.isValid()) << bad;
    EXPECT_EQ(q.getTraceSnr(), EDGE_TRACE_SNR_OFF) << bad << ": nothing half-read, and off";
  }
}

static Packet sent(uint8_t route, uint8_t type, uint8_t hops) {
  Packet p;
  p.header = route | (type << PH_TYPE_SHIFT);
  p.setPathHashSizeAndCount(1, hops);
  p.payload[0] = CHAN;
  p.payload[1] = OWNER;
  p.payload_len = 2;
  return p;
}

TEST(EdgeSentStat, EachPacketSentOnIsCountedByItsKind) {
  Packet up = sent(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_TXT_MSG, 0);
  EXPECT_EQ(edgeSentStat(&up, false), ES_UPLINK);
  Packet post = sent(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_GRP_TXT, 0);
  EXPECT_EQ(edgeSentStat(&post, false), ES_UPLINK) << "a post on an opted-in channel";
  EXPECT_EQ(edgeSentStat(&post, true), ES_WD_POST);
  Packet login = sent(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_ANON_REQ, 0);
  EXPECT_EQ(edgeSentStat(&login, false), ES_LOGIN);
  Packet dlogin = sent(ROUTE_TYPE_DIRECT, PAYLOAD_TYPE_ANON_REQ, 1);
  EXPECT_EQ(edgeSentStat(&dlogin, false), ES_LOGIN) << "a login routed through the car is a login, not dfwd";
  Packet direct = sent(ROUTE_TYPE_DIRECT, PAYLOAD_TYPE_TXT_MSG, 1);
  EXPECT_EQ(edgeSentStat(&direct, false), ES_DIRECT);
}

TEST(EdgeSentStat, AFloodReceiptSentOnWithFwdAcksIsAReceiptNotAnUplink) {
  for (uint8_t hops : {0, 3}) {
    Packet ack = sent(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_ACK, hops);
    EXPECT_EQ(edgeSentStat(&ack, false), ES_ACK) << (int)hops << " hops";
    Packet tack = sent(ROUTE_TYPE_TRANSPORT_FLOOD, PAYLOAD_TYPE_ACK, hops);
    EXPECT_EQ(edgeSentStat(&tack, false), ES_ACK) << (int)hops << " hops, scoped";
  }
}

// A mirrored advert goes as a Share, which stock repeaters keep out of their neighbour tables; nothing else does
TEST(EdgeCopy, OnlyAnAdvertGoesAsAShare) {
  EXPECT_TRUE(edgeCopyAsShare(PAYLOAD_TYPE_ADVERT));
  for (uint8_t t : {PAYLOAD_TYPE_GRP_TXT, PAYLOAD_TYPE_TXT_MSG, PAYLOAD_TYPE_ACK, PAYLOAD_TYPE_REQ, PAYLOAD_TYPE_RESPONSE,
                    PAYLOAD_TYPE_PATH, PAYLOAD_TYPE_TRACE, PAYLOAD_TYPE_ANON_REQ}) {
    EXPECT_FALSE(edgeCopyAsShare(t)) << "payload type " << (int)t;
  }
}

#include "test_edge_stats.inc"

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
