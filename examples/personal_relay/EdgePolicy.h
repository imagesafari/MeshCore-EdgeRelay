#pragma once

#include <Arduino.h>
#include <Mesh.h>
#include <helpers/IdentityStore.h>   // FILESYSTEM
#include "EdgeTrace.h"
#include "EdgeStats.h"

// Maximum number of owner identities (companion devices) this relay serves.
#ifndef EDGE_MAX_OWNERS
#define EDGE_MAX_OWNERS  8
#endif
// Maximum number of group channel hashes mirrored to owners.
#ifndef EDGE_MAX_CHANNELS
#define EDGE_MAX_CHANNELS  8
#endif

// Maximum number of wardriving channels (see EdgeWardrive.h).
#ifndef EDGE_MAX_WARDRIVE
#define EDGE_MAX_WARDRIVE  2
#endif

// Filesystem path of the persisted policy.
#define EDGE_POLICY_FILE  "/edge_policy"

// Local-copy rate limit: at most this many zero-hop copies per window.
#define EDGE_LOCAL_COPY_MAX    30
#define EDGE_LOCAL_COPY_WINDOW_MS  60000UL

// Wardrive echo rate limit (EdgeWardrive.h): its own budget, so wardriving never starves owner local copies.
#define EDGE_WARDRIVE_ECHO_RATE_MAX  24
#define EDGE_WARDRIVE_ECHO_WINDOW_MS 60000UL

// Direct receipts forwarded (D1): an ACK names no sender, so they are capped like traces, and bounded in size.
#define EDGE_ACK_MAX_LEN       8
#define EDGE_ACK_FWD_MAX       30
#define EDGE_ACK_FWD_WINDOW_MS 60000UL

// Trace rate limit: at most this many traces relayed per window (a trace names no sender, so anyone who
// knows this node's hash could route one through it; this caps that).
#define EDGE_TRACE_MAX         10
#define EDGE_TRACE_WINDOW_MS   60000UL

// Bytes of this node's public key prefix the callers hand to classify(): enough for any hop hash size.
#define EDGE_SELF_HASH_MAX     8

// A CLI reply, as the mesh carries one back to an admin: 159 characters and the terminator.
#define EDGE_REPLY_MAX         160

/**
 * Edge-relay packet policy.
 *
 * This is the "directional firewall" for the personal edge relay: it decides,
 * for every received packet, whether stock MeshCore handling may proceed
 * (EDGE_STOCK), whether the packet's payload should be re-emitted once as a
 * local zero-hop copy for nearby owners (EDGE_LOCAL_COPY), or whether the
 * packet must be dropped outright (EDGE_DROP).
 *
 * The classifier is intentionally pure (no side effects): rate-limit tokens
 * are consumed separately via tryLocalCopy() only when a copy is actually made.
 */
enum EdgeAction {
  EDGE_STOCK,       // hand to stock Mesh::onRecvPacket()
  EDGE_LOCAL_COPY,  // re-emit payload once as zero-hop direct; drop the original
  EDGE_DROP,        // drop the packet entirely
  EDGE_WARDRIVE_ECHO // an echo on a wardriving channel: hand down with its path if it is of a post we sent on
};

class EdgePolicy {
  uint8_t _owner_keys[EDGE_MAX_OWNERS][PUB_KEY_SIZE];
  uint8_t _num_owners;
  uint8_t _channel_hashes[EDGE_MAX_CHANNELS];
  uint8_t _num_channels;
  uint8_t _wardrive_hashes[EDGE_MAX_WARDRIVE];
  uint8_t _num_wardrive;
  bool _mirror_adverts;   // re-emit selected remote adverts locally (default: false)
  bool _fwd_acks;         // forward ACKs naming this node (default: false)
  bool _valid;            // false -> fail closed (receive-only)

  // sliding-window rate limiter for local copies
  uint32_t _rl_start_ms;
  uint16_t _rl_count;
  // and for relayed traces
  uint32_t _tr_start_ms;
  uint16_t _tr_count;
  uint32_t _ack_start_ms;  // and for direct receipts forwarded
  uint16_t _ack_count;
  // and for wardrive echoes handed down
  uint32_t _wd_start_ms;
  uint16_t _wd_count;

  bool parsePolicy(FILESYSTEM* fs);

public:
  EdgePolicy();

  // --- persistence ---
  bool load(FILESYSTEM* fs);   // false -> policy invalid, fail closed
  bool save(FILESYSTEM* fs);

  bool isValid() const { return _valid; }

  // --- owner / channel management ---
  int addOwner(const uint8_t pubkey[PUB_KEY_SIZE]);  // returns idx, or -1 if full/duplicate
  bool removeOwner(const uint8_t pubkey[PUB_KEY_SIZE]);
  int addChannel(uint8_t hash1);                     // returns idx, or -1 if full/duplicate
  bool removeChannel(uint8_t hash1);
  int addWardrive(uint8_t hash1);                    // returns idx, or -1 if full/duplicate
  bool removeWardrive(uint8_t hash1);
  uint8_t getNumWardrive() const { return _num_wardrive; }
  uint8_t getWardriveHash(int i) const { return _wardrive_hashes[i]; }
  bool isWardrive(uint8_t h) const;
  void setMirrorAdverts(bool v) { _mirror_adverts = v; }
  void setFwdAcks(bool v) { _fwd_acks = v; }
  bool getMirrorAdverts() const { return _mirror_adverts; }
  bool getFwdAcks() const { return _fwd_acks; }
  uint8_t getNumOwners() const { return _num_owners; }
  uint8_t getNumChannels() const { return _num_channels; }
  const uint8_t* getOwnerKey(int i) const { return _owner_keys[i]; }
  uint8_t getChannelHash(int i) const { return _channel_hashes[i]; }

  bool isOwnerHash(uint8_t h) const;
  // The first owner whose key starts with this 1-byte hash, or nullptr (two owners can share a byte: the stats
  // that use this name the first).
  const uint8_t* ownerKeyByHash(uint8_t h) const;
  bool isOwnerPubkey(const uint8_t pubkey[PUB_KEY_SIZE]) const;
  bool isChannel(uint8_t h) const;

  // --- classification ---
  // self_hash/self_hash_len: this node's path hash, for direct next-hop checks.
  EdgeAction classify(const mesh::Packet* pkt, const uint8_t* self_hash, uint8_t self_hash_len) const;

  // Final deny guard for allowPacketForward(): true only if stock handling is permitted.
  bool checkForward(const mesh::Packet* pkt, const uint8_t* self_hash, uint8_t self_hash_len) const {
    return _valid && classify(pkt, self_hash, self_hash_len) == EDGE_STOCK;
  }

  // Rate limiter: call when actually making a local copy.
  bool tryLocalCopy(uint32_t now_ms);
  // Rate limiter: call once per new trace about to be relayed.
  bool tryTrace(uint32_t now_ms);
  // Rate limiter: call once per direct receipt (ACK or multi-ACK) about to be forwarded.
  bool tryAckForward(uint32_t now_ms);
  // Rate limiter: call once per wardrive echo about to be handed down.
  bool tryWardriveEcho(uint32_t now_ms);
};

// --- edge stats (EdgeStats.h) on the filesystem ---
// Reads the lifetime counts from EDGE_STATS_FILE. No file, a half-written one or another firmware's: false, and
// the lifetime counts are left as they were (zero at boot).
bool edgeLoadStats(FILESYSTEM* fs, EdgeStats& stats);
// Writes them beside the file and renames that over it, so a failed write never costs the saved counts. Sets
// saved_ms, save_failed (said on `edge stats life` and in the 0xC0 flags) and, on success, clears dirty.
bool edgeSaveStats(FILESYSTEM* fs, EdgeStats& stats, uint32_t now_ms);

// `edge status`: the settings, then the totals since boot. The totals mean what they always did: up is owner
// floods, wardriving posts and logins sent on; dfwd direct packets and receipts; trace both kinds; drop every
// reason (`edge stats` has them apart). One reply over the mesh (EDGE_REPLY_MAX) at every count's largest.
void edgeStatusReply(const EdgePolicy& policy, const EdgeStats& stats, char* reply, size_t cap);
