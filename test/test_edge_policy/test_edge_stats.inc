// The edge counts (EdgeStats.h): kept across reboots by their file, read as pages within a mesh reply, and sent
// to a console as the 0xC0 answer. Included by test_edge_policy.cpp (one test binary per folder). Ported from the
// edge companion's test/test_edge_policy/test_edge_stats.inc; the relay's own status line and stats file at the end.

static void fill(EdgeStats& s, uint32_t v) {
  s.clear();
  for (int i = 0; i < ES_COUNT; i++) {
    s.boot[i] = v;
    s.life[i] = v;
  }
}

TEST(EdgeStats, CountsBothSets) {
  EdgeStats s;
  s.clear();
  s.add(ES_UPLINK);
  s.add(ES_UPLINK);
  s.add(ES_RL_COPY);
  EXPECT_EQ(s.boot[ES_UPLINK], 2u);
  EXPECT_EQ(s.life[ES_UPLINK], 2u);
  EXPECT_TRUE(s.dirty);
  s.add(ES_DROP_POLICY);
  EXPECT_EQ(s.drops(false), 2u) << "drops: every reason";
  EXPECT_EQ(s.boot[ES_UPLINK], 2u);
}

TEST(EdgeStats, LifetimeRoundTripsThroughItsFile) {
  EdgeStats a;
  a.clear();
  for (int i = 0; i < ES_COUNT; i++) a.life[i] = 1000u * (i + 1);
  a.life[ES_WD_ECHO] = 4294967295u;
  char text[EDGE_STATS_TEXT_MAX];
  int n = a.serialize(text, sizeof(text));
  ASSERT_GT(n, 0);
  EXPECT_EQ(strncmp(text, "ES1 ", 4), 0);
  EdgeStats b;
  b.clear();
  b.boot[ES_UPLINK] = 7;
  ASSERT_TRUE(b.parse(text));
  EXPECT_EQ(memcmp(a.life, b.life, sizeof(a.life)), 0);
  EXPECT_EQ(b.boot[ES_UPLINK], 7u) << "loading lifetime leaves since-boot alone";
}

TEST(EdgeStats, AHalfWrittenOrForeignFileIsNotUsed) {
  EdgeStats a;
  fill(a, 5);
  char text[EDGE_STATS_TEXT_MAX];
  int n = a.serialize(text, sizeof(text));
  EdgeStats b;
  b.clear();
  std::string cut(text, n - 4);  // the write stopped short
  EXPECT_FALSE(b.parse(cut.c_str()));
  EXPECT_FALSE(b.parse("ES1 3 1 2 3\n")) << "another firmware's count of counters";
  EXPECT_FALSE(b.parse("XX1 19 0\n"));
  EXPECT_FALSE(b.parse(""));
  for (int i = 0; i < ES_COUNT; i++) EXPECT_EQ(b.life[i], 0u) << "nothing half-loaded";
}

TEST(EdgeStats, EveryPageFitsAMeshReplyAtItsLargest) {
  EdgeStats s;
  fill(s, 4294967295u);
  for (auto& o : s.owners) {
    o.prefix[0] = 0xff;
    o.prefix[1] = 0xee;
    o.packets = 4294967295u;
    o.heard_ms = 1;
    o.snr4 = -128;
  }
  s.save_failed = true;  // the longest life page says so
  for (const char* page : {"", "boot", "life", "late", "drops", "drops life", "owners", "nope"}) {
    char reply[EDGE_REPLY_MAX + 40];
    memset(reply, 'x', sizeof(reply));
    edgeStatsReply(s, page, reply, EDGE_REPLY_MAX, 4000000000u);
    size_t len = strlen(reply);
    EXPECT_LT(len, (size_t)EDGE_REPLY_MAX) << page;
    // the last field is whole: snprintf did not have to cut it
    char full[400];
    if (strcmp(page, "owners") != 0) {
      edgeStatsReply(s, page, full, sizeof(full), 4000000000u);
      EXPECT_STREQ(reply, full) << page << " was cut short";
    }
  }
}

TEST(EdgeStats, PagesSayWhatTheyCount) {
  EdgeStats s;
  s.clear();
  s.boot[ES_UPLINK] = 12;
  s.life[ES_UPLINK] = 340;
  s.boot[ES_TRACE_THROUGH] = 2;
  s.boot[ES_HELD] = 5;
  s.life[ES_HELD] = 50;
  s.boot[ES_RL_ECHO] = 3;
  char r[EDGE_REPLY_MAX];
  edgeStatsReply(s, "", r, sizeof(r), 0);
  EXPECT_STREQ(r, "OK - boot up:12 copy:0 dfwd:0 ack:0 tr:0 trt:2 wdp:0 wde:0 login:0");
  edgeStatsReply(s, "life", r, sizeof(r), 0);
  EXPECT_EQ(std::string(r).rfind("OK - life up:340 ", 0), 0u);
  edgeStatsReply(s, "late", r, sizeof(r), 0);
  EXPECT_STREQ(r, "OK - late held:5/50 sent:0/0 sup:0/0");
  edgeStatsReply(s, "drops", r, sizeof(r), 0);
  EXPECT_STREQ(r, "OK - drops boot pol:0 nobuf:0 rl copy:0 ack:0 tr:0 echo:3 notours:0");
  edgeStatsReply(s, "x", r, sizeof(r), 0);
  EXPECT_EQ(std::string(r).rfind("Err - stats ", 0), 0u);
}

TEST(EdgeStats, OwnersAreKeptByKeyPrefix) {
  EdgeStats s;
  s.clear();
  const uint8_t a[4] = {0xb1, 0xa5, 0x01, 0x02}, b[4] = {0x22, 0xab, 0x33, 0x44};
  s.owner(a)->packets += 3;
  EdgeOwnerStat* ob = s.owner(b);
  ob->packets = 1;
  ob->heard_ms = 1000;
  ob->snr4 = -18;
  EXPECT_EQ(s.owner(a)->packets, 3u) << "the same slot again";
  char r[EDGE_REPLY_MAX];
  edgeStatsReply(s, "owners", r, sizeof(r), 1000 + 5 * 60000);
  EXPECT_STREQ(r, "OK - owners: b1a5 n3 - 22ab n1 5m -4.5dB");
}

TEST(EdgeStats, TheConsoleFrameHasOneSetWithItsLayout) {
  EdgeStats s;
  s.clear();
  s.boot[ES_UPLINK] = 0x01020304;
  s.life[ES_UPLINK] = 7;
  s.life[ES_ECHO_NOT_OURS] = 9;
  uint8_t f[200];
  int n = edgeStatsFrame(f, sizeof(f), s, 0, 0x05, 2, 1, 1);
  ASSERT_EQ(n, 7 + 4 * ES_COUNT);
  EXPECT_EQ(f[0], EDGE_STATS_FRAME_VER);
  EXPECT_EQ(f[1], 0);
  EXPECT_EQ(f[2], 0x05);
  EXPECT_EQ(f[3], 2);
  EXPECT_EQ(f[6], ES_COUNT);
  EXPECT_EQ(f[7], 0x04);
  EXPECT_EQ(f[10], 0x01) << "little-endian";
  n = edgeStatsFrame(f, sizeof(f), s, 1, 0, 0, 0, 0);
  EXPECT_EQ(f[1], 1);
  EXPECT_EQ(f[7], 7);
  EXPECT_EQ(f[7 + 4 * ES_ECHO_NOT_OURS], 9);
  EXPECT_EQ(edgeStatsFrame(f, 10, s, 0, 0, 0, 0, 0), 0) << "too small: nothing";
  // it fits a flood's path return with room for a path (Mesh::createPathReturn: about 100 bytes of extra)
  EXPECT_LE(4 + n, 100);
}

TEST(EdgeStats, StatusUpKeepsItsOldMeaningAndAFailedSaveIsSaid) {
  auto p = validPolicy();
  EdgeStats s = sampleStats();
  s.boot[ES_WD_POST] = 5;
  s.boot[ES_LOGIN] = 2;
  s.boot[ES_TRACE_THROUGH] = 1;
  char reply[EDGE_REPLY_MAX];
  edgeStatusReply(p, s, reply, sizeof(reply));
  EXPECT_NE(strstr(reply, " up:19 "), nullptr) << reply << ": owner floods, wardriving posts and logins";
  EXPECT_NE(strstr(reply, " dfwd:4 "), nullptr) << reply << ": direct and receipts";
  EXPECT_NE(strstr(reply, " trace:3 "), nullptr) << reply << ": both kinds";
  EXPECT_NE(strstr(reply, " drop:40 "), nullptr) << reply << ": every reason";
  EXPECT_NE(strstr(reply, " wde:7"), nullptr) << reply;
  s.save_failed = true;
  edgeStatsReply(s, "life", reply, sizeof(reply), 0);
  EXPECT_EQ(std::string(reply).rfind("OK - life save FAILED up:", 0), 0u) << reply;
  uint8_t f[200];
  edgeStatsFrame(f, sizeof(f), s, 1, 0x20, 0, 0, 0);
  EXPECT_EQ(f[2] & 0x20, 0x20);
}

TEST(EdgeStats, StatusFitsAMeshReplyAtItsLargest) {
  auto p = validPolicy();
  EdgeStats s;
  fill(s, 4294967295u);
  char reply[EDGE_REPLY_MAX + 40], full[400];
  edgeStatusReply(p, s, reply, EDGE_REPLY_MAX);
  edgeStatusReply(p, s, full, sizeof(full));
  EXPECT_LT(strlen(reply), (size_t)EDGE_REPLY_MAX);
  EXPECT_STREQ(reply, full) << "cut short";
}

// --- the lifetime counts on the filesystem (edgeLoadStats / edgeSaveStats, EdgePolicy.cpp) ---

TEST(EdgeStatsFile, LifetimeCountsSurviveAReboot) {
  MockFS fs;
  EdgeStats a;
  a.clear();
  a.add(ES_UPLINK);
  a.add(ES_TRACE_THROUGH);
  ASSERT_TRUE(edgeSaveStats(&fs, a, 5000));
  EXPECT_FALSE(a.dirty);
  EXPECT_FALSE(a.save_failed);
  EXPECT_EQ(a.saved_ms, 5000u);
  EXPECT_EQ(fs.files.count(EDGE_STATS_FILE_NEW), 0u) << "written beside it, then renamed over it";
  EdgeStats b;  // the next boot
  b.clear();
  ASSERT_TRUE(edgeLoadStats(&fs, b));
  EXPECT_EQ(b.life[ES_UPLINK], 1u);
  EXPECT_EQ(b.life[ES_TRACE_THROUGH], 1u);
  EXPECT_EQ(b.boot[ES_UPLINK], 0u) << "since boot starts again";
  b.add(ES_UPLINK);
  ASSERT_TRUE(edgeSaveStats(&fs, b, 6000));
  EdgeStats c;
  c.clear();
  ASSERT_TRUE(edgeLoadStats(&fs, c));
  EXPECT_EQ(c.life[ES_UPLINK], 2u) << "a second save replaces the first, not appended to it";
}

TEST(EdgeStatsFile, AFailedSaveIsSaidAndKeepsTheSavedCounts) {
  MockFS fs;
  EdgeStats a;
  a.clear();
  a.add(ES_COPY);
  ASSERT_TRUE(edgeSaveStats(&fs, a, 1000));
  a.add(ES_COPY);
  fs.fail_writes = true;
  EXPECT_FALSE(edgeSaveStats(&fs, a, 2000));
  EXPECT_TRUE(a.save_failed);
  EXPECT_TRUE(a.dirty) << "still to be saved";
  EXPECT_EQ(a.saved_ms, 2000u) << "tried again at the next interval, not at once";
  EXPECT_EQ(fs.files.count(EDGE_STATS_FILE_NEW), 0u) << "the partial file is removed";
  char r[EDGE_REPLY_MAX];
  edgeStatsReply(a, "life", r, sizeof(r), 0);
  EXPECT_EQ(std::string(r).rfind("OK - life save FAILED ", 0), 0u) << r;
  EdgeStats b;
  b.clear();
  ASSERT_TRUE(edgeLoadStats(&fs, b));
  EXPECT_EQ(b.life[ES_COPY], 1u) << "the last good save is still there";
  fs.fail_writes = false;
  EXPECT_TRUE(edgeSaveStats(&fs, a, 3000));
  EXPECT_FALSE(a.save_failed) << "a good save clears it";
}

TEST(EdgeStatsFile, ReplacesTheFileWhereRenameWillNotOverwrite) {
  MockFS fs;
  fs.rename_overwrites = false;  // SPIFFS
  EdgeStats a;
  a.clear();
  a.add(ES_ACK);
  ASSERT_TRUE(edgeSaveStats(&fs, a, 1));
  a.add(ES_ACK);
  ASSERT_TRUE(edgeSaveStats(&fs, a, 2));
  EdgeStats b;
  b.clear();
  ASSERT_TRUE(edgeLoadStats(&fs, b));
  EXPECT_EQ(b.life[ES_ACK], 2u);
}

TEST(EdgeStatsFile, AMissingHalfWrittenOrOversizedFileIsNotUsed) {
  MockFS fs;
  EdgeStats b;
  b.clear();
  EXPECT_FALSE(edgeLoadStats(&fs, b)) << "no file";
  EdgeStats a;
  fill(a, 9);
  char text[EDGE_STATS_TEXT_MAX];
  int n = a.serialize(text, sizeof(text));
  fs.files[EDGE_STATS_FILE] = std::string(text, n - 3);
  EXPECT_FALSE(edgeLoadStats(&fs, b)) << "cut short";
  fs.files[EDGE_STATS_FILE] = std::string(EDGE_STATS_TEXT_MAX + 10, '1');
  EXPECT_FALSE(edgeLoadStats(&fs, b)) << "larger than any this firmware writes";
  for (int i = 0; i < ES_COUNT; i++) EXPECT_EQ(b.life[i], 0u) << "nothing half-loaded";
}
