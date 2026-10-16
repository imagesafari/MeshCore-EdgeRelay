#pragma once

// What the edge did, counted, kept across reboots. Two sets of the same counters: since boot (RAM), and lifetime
// (saved to EDGE_STATS_FILE every EDGE_STATS_SAVE_MS, on `edge stats save`, and before a reboot or power-off that
// is asked for; a crash loses at most the time since the last save). Plus, per owner, how many of its packets
// went out and when it was last heard directly (RAM only).
//
// Pure: no I/O. MyMesh.cpp counts, and answers `edge stats …` and the 0xC0 request (EDGE_REQ_GET_EDGE_STATS);
// EdgePolicy.cpp reads and writes the file (edgeLoadStats, edgeSaveStats).

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

enum EdgeStat : uint8_t {
  // sent on
  ES_UPLINK = 0,      // an owner's flood sent on (its posts, adverts, requests)
  ES_COPY,            // a packet for an owner re-sent as a zero-hop copy
  ES_DIRECT,          // a direct packet to or from an owner sent on
  ES_ACK,             // a delivery receipt sent on (a direct one naming this node, or a flood one with fwd_acks)
  ES_TRACE,           // a trace naming this node sent on
  ES_TRACE_THROUGH,   // an owner's trace that does not name this node, sent on (transparent trace)
  ES_WD_POST,         // a wardriving post sent on
  ES_WD_ECHO,         // an echo of one handed back down
  ES_LOGIN,           // an owner's login to a repeater or room sent on
  // late relay
  ES_HELD,            // an owner's flood held for late relay
  ES_SENT_LATE,       // ...and sent when the hold ran out
  ES_SUPPRESSED,      // ...or not sent, a trusted repeater having sent it first
  // not sent on
  ES_DROP_POLICY,     // not an owner's, not a chosen channel
  ES_DROP_NOBUF,      // the packet pool was empty
  ES_RL_COPY,         // over the local-copy rate limit
  ES_RL_ACK,          // over the receipt rate limit
  ES_RL_TRACE,        // over the trace rate limit
  ES_RL_ECHO,         // over the wardriving echo rate limit
  ES_ECHO_NOT_OURS,   // a wardriving echo of a post this node did not send on
  ES_COUNT
};

#define EDGE_STATS_FILE      "/edge_stats"
#define EDGE_STATS_FILE_NEW  "/edge_stats.new"
#define EDGE_STATS_MAGIC     "ES1"
#define EDGE_STATS_SAVE_MS   (6UL * 3600UL * 1000UL)
#define EDGE_STATS_TEXT_MAX  (8 + ES_COUNT * 11 + 2)
#define EDGE_STATS_OWNERS    8

struct EdgeOwnerStat {
  uint8_t prefix[4];   // the owner's key, first 4 bytes (0: unused slot)
  uint32_t packets;    // its packets this node sent on (DMs, requests, logins: a channel post names no sender)
  uint32_t heard_ms;   // when it was last heard directly (zero hops), by millis(); 0: not since boot
  int8_t snr4;         // ...at this SNR, in quarter dB
};

struct EdgeStats {
  uint32_t boot[ES_COUNT];
  uint32_t life[ES_COUNT];
  bool dirty;              // lifetime counts changed since the last save
  bool save_failed;        // the last save of the lifetime counts did not reach the file (said on `stats life`)
  uint32_t saved_ms;       // millis() of the last save (or of the load at boot)
  EdgeOwnerStat owners[EDGE_STATS_OWNERS];

  void clear() { memset(this, 0, sizeof(*this)); }
  void add(EdgeStat s) {
    boot[s]++;
    life[s]++;
    dirty = true;
  }
  uint32_t drops(bool lifetime) const {
    const uint32_t* c = lifetime ? life : boot;
    uint32_t n = 0;
    for (int s = ES_DROP_POLICY; s < ES_COUNT; s++) n += c[s];
    return n;
  }

  // An owner's slot by its key's first 4 bytes, taking a free one (or the longest unheard) if new.
  EdgeOwnerStat* owner(const uint8_t key[4]) {
    EdgeOwnerStat* spare = nullptr;
    for (auto& o : owners) {
      if (memcmp(o.prefix, key, 4) == 0) return &o;
      bool unused = !(o.prefix[0] | o.prefix[1] | o.prefix[2] | o.prefix[3]);
      if (unused && !spare) spare = &o;
    }
    if (!spare) {
      spare = &owners[0];
      for (auto& o : owners) if (o.heard_ms < spare->heard_ms) spare = &o;
    }
    memset(spare, 0, sizeof(*spare));
    memcpy(spare->prefix, key, 4);
    return spare;
  }

  // Lifetime counts as text for EDGE_STATS_FILE: "ES1 <count> <v0> <v1> …\n". -1 if it does not fit.
  int serialize(char* out, size_t cap) const {
    int n = snprintf(out, cap, "%s %d", EDGE_STATS_MAGIC, (int)ES_COUNT);
    for (int s = 0; s < ES_COUNT && n > 0 && (size_t)n < cap; s++) n += snprintf(out + n, cap - n, " %lu", (unsigned long)life[s]);
    if (n < 0 || (size_t)n + 2 > cap) return -1;
    n += snprintf(out + n, cap - n, "\n");
    return n;
  }
  // Reads them back. A file with another magic, a different count (another firmware's), or cut short (a write
  // that did not finish) is not used: false, and the lifetime counts start from zero.
  bool parse(const char* text) {
    if (strncmp(text, EDGE_STATS_MAGIC " ", 4) != 0) return false;
    char* p;
    long count = strtol(text + 4, &p, 10);
    if (count != ES_COUNT) return false;
    uint32_t v[ES_COUNT];
    for (int s = 0; s < ES_COUNT; s++) {
      char* end;
      while (*p == ' ') p++;
      unsigned long x = strtoul(p, &end, 10);
      if (end == p) return false;
      v[s] = (uint32_t)x;
      p = end;
    }
    if (*p != '\n') return false;
    memcpy(life, v, sizeof(life));
    return true;
  }
};

// `edge stats [boot|life|late|drops [life]|owners]`: one page at a time, each within an over-the-mesh reply
// (reply_max, 160) even with every counter at its largest (test_edge_stats checks that). now_ms: millis(), for
// the owners' "heard … ago".
inline void edgeStatsReply(const EdgeStats& st, const char* page, char* reply, size_t reply_max, uint32_t now_ms) {
  bool life = strcmp(page, "life") == 0;
  if (page[0] == 0 || strcmp(page, "boot") == 0 || life) {  // what it sent on
    const uint32_t* c = life ? st.life : st.boot;
    snprintf(reply, reply_max, "OK - %s up:%lu copy:%lu dfwd:%lu ack:%lu tr:%lu trt:%lu wdp:%lu wde:%lu login:%lu",
             life ? (st.save_failed ? "life save FAILED" : "life") : "boot", (unsigned long)c[ES_UPLINK],
             (unsigned long)c[ES_COPY],
             (unsigned long)c[ES_DIRECT], (unsigned long)c[ES_ACK], (unsigned long)c[ES_TRACE],
             (unsigned long)c[ES_TRACE_THROUGH], (unsigned long)c[ES_WD_POST], (unsigned long)c[ES_WD_ECHO],
             (unsigned long)c[ES_LOGIN]);
    return;
  }
  if (strcmp(page, "late") == 0) {  // late relay, since boot / lifetime
    snprintf(reply, reply_max, "OK - late held:%lu/%lu sent:%lu/%lu sup:%lu/%lu", (unsigned long)st.boot[ES_HELD],
             (unsigned long)st.life[ES_HELD], (unsigned long)st.boot[ES_SENT_LATE], (unsigned long)st.life[ES_SENT_LATE],
             (unsigned long)st.boot[ES_SUPPRESSED], (unsigned long)st.life[ES_SUPPRESSED]);
    return;
  }
  bool drops_life = strcmp(page, "drops life") == 0;
  if (strcmp(page, "drops") == 0 || drops_life) {  // not sent on, by reason
    const uint32_t* c = drops_life ? st.life : st.boot;
    snprintf(reply, reply_max, "OK - drops %s pol:%lu nobuf:%lu rl copy:%lu ack:%lu tr:%lu echo:%lu notours:%lu",
             drops_life ? "life" : "boot", (unsigned long)c[ES_DROP_POLICY], (unsigned long)c[ES_DROP_NOBUF],
             (unsigned long)c[ES_RL_COPY], (unsigned long)c[ES_RL_ACK], (unsigned long)c[ES_RL_TRACE],
             (unsigned long)c[ES_RL_ECHO], (unsigned long)c[ES_ECHO_NOT_OURS]);
    return;
  }
  if (strcmp(page, "owners") == 0) {  // each: key prefix, packets sent on, heard directly how long ago and at what SNR
    int n = snprintf(reply, reply_max, "OK - owners:");
    for (const auto& o : st.owners) {
      if (!(o.prefix[0] | o.prefix[1] | o.prefix[2] | o.prefix[3])) continue;
      char item[48];
      if (o.heard_ms) {
        snprintf(item, sizeof(item), " %02x%02x n%lu %lum %.1fdB", o.prefix[0], o.prefix[1], (unsigned long)o.packets,
                 (unsigned long)((now_ms - o.heard_ms) / 60000UL), o.snr4 / 4.0f);
      } else {
        snprintf(item, sizeof(item), " %02x%02x n%lu -", o.prefix[0], o.prefix[1], (unsigned long)o.packets);
      }
      if ((size_t)n + strlen(item) + 1 > reply_max) break;  // a full reply stops at the last owner that fits
      n += snprintf(reply + n, reply_max - n, "%s", item);
    }
    return;
  }
  snprintf(reply, reply_max, "Err - stats boot|life|late|drops [life]|owners|save|reset");
}

// The 0xC0 request's answer (EDGE_REQ_GET_EDGE_STATS), after its 4-byte tag:
// [ver 1][set 0 boot|1 life][flags][owners][channels][wardrive][count N][N x uint32 LE]. flags: bit0 on, bit1 a valid
// policy, bit2 late relay on, bit3 receipts forwarded, bit4 remote adverts mirrored. Returns its length, or 0 if
// cap is too small. One set per request keeps it inside a flood's path return (about 100 bytes). flags bit5: the
// last save of the lifetime counts failed.
#define EDGE_STATS_FRAME_VER 1
inline int edgeStatsFrame(uint8_t* out, size_t cap, const EdgeStats& st, uint8_t set, uint8_t flags, uint8_t owners,
                          uint8_t channels, uint8_t wardrive) {
  size_t need = 7 + 4 * (size_t)ES_COUNT;
  if (cap < need) return 0;
  const uint32_t* c = set ? st.life : st.boot;
  out[0] = EDGE_STATS_FRAME_VER;
  out[1] = set ? 1 : 0;
  out[2] = flags;
  out[3] = owners;
  out[4] = channels;
  out[5] = wardrive;
  out[6] = ES_COUNT;
  for (int s = 0; s < ES_COUNT; s++) {
    uint32_t v = c[s];
    out[7 + 4 * s] = v & 0xff;
    out[8 + 4 * s] = (v >> 8) & 0xff;
    out[9 + 4 * s] = (v >> 16) & 0xff;
    out[10 + 4 * s] = (v >> 24) & 0xff;
  }
  return (int)need;
}
