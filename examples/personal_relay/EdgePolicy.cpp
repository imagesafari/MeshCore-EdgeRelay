#include "EdgePolicy.h"

EdgePolicy::EdgePolicy() {
  _num_owners = 0;
  _num_channels = 0;
  _num_wardrive = 0;
  _mirror_adverts = false;
  _fwd_acks = false;
  _valid = false;   // no policy loaded yet -> fail closed until load() succeeds
  _rl_start_ms = 0;
  _rl_count = 0;
  _tr_start_ms = 0;
  _tr_count = 0;
  _ack_start_ms = 0;
  _ack_count = 0;
  _wd_start_ms = 0;
  _wd_count = 0;
  memset(_owner_keys, 0, sizeof(_owner_keys));
  memset(_channel_hashes, 0, sizeof(_channel_hashes));
  memset(_wardrive_hashes, 0, sizeof(_wardrive_hashes));
}

bool EdgePolicy::isOwnerHash(uint8_t h) const {
  // The 1-byte wire hash is the first byte of the Ed25519 public key.
  for (int i = 0; i < _num_owners; i++) {
    if (_owner_keys[i][0] == h) return true;
  }
  return false;
}

const uint8_t* EdgePolicy::ownerKeyByHash(uint8_t h) const {
  for (int i = 0; i < _num_owners; i++) {
    if (_owner_keys[i][0] == h) return _owner_keys[i];
  }
  return nullptr;
}

bool EdgePolicy::isOwnerPubkey(const uint8_t pubkey[PUB_KEY_SIZE]) const {
  for (int i = 0; i < _num_owners; i++) {
    if (memcmp(_owner_keys[i], pubkey, PUB_KEY_SIZE) == 0) return true;
  }
  return false;
}

bool EdgePolicy::isChannel(uint8_t h) const {
  for (int i = 0; i < _num_channels; i++) {
    if (_channel_hashes[i] == h) return true;
  }
  return false;
}

int EdgePolicy::addOwner(const uint8_t pubkey[PUB_KEY_SIZE]) {
  if (isOwnerPubkey(pubkey)) return -1;  // duplicate
  if (_num_owners >= EDGE_MAX_OWNERS) return -1;
  memcpy(_owner_keys[_num_owners], pubkey, PUB_KEY_SIZE);
  return _num_owners++;
}

bool EdgePolicy::removeOwner(const uint8_t pubkey[PUB_KEY_SIZE]) {
  for (int i = 0; i < _num_owners; i++) {
    if (memcmp(_owner_keys[i], pubkey, PUB_KEY_SIZE) == 0) {
      // compact the list
      for (int j = i; j < _num_owners - 1; j++) {
        memcpy(_owner_keys[j], _owner_keys[j + 1], PUB_KEY_SIZE);
      }
      _num_owners--;
      return true;
    }
  }
  return false;
}

int EdgePolicy::addChannel(uint8_t hash1) {
  if (isChannel(hash1)) return -1;
  if (_num_channels >= EDGE_MAX_CHANNELS) return -1;
  _channel_hashes[_num_channels] = hash1;
  return _num_channels++;
}

bool EdgePolicy::removeChannel(uint8_t hash1) {
  for (int i = 0; i < _num_channels; i++) {
    if (_channel_hashes[i] == hash1) {
      for (int j = i; j < _num_channels - 1; j++) {
        _channel_hashes[j] = _channel_hashes[j + 1];
      }
      _num_channels--;
      return true;
    }
  }
  return false;
}

bool EdgePolicy::isWardrive(uint8_t h) const {
  for (int i = 0; i < _num_wardrive; i++) {
    if (_wardrive_hashes[i] == h) return true;
  }
  return false;
}

int EdgePolicy::addWardrive(uint8_t hash1) {
  if (isWardrive(hash1)) return -1;
  if (_num_wardrive >= EDGE_MAX_WARDRIVE) return -1;
  _wardrive_hashes[_num_wardrive] = hash1;
  return _num_wardrive++;
}

bool EdgePolicy::removeWardrive(uint8_t hash1) {
  for (int i = 0; i < _num_wardrive; i++) {
    if (_wardrive_hashes[i] == hash1) {
      for (int j = i; j < _num_wardrive - 1; j++) _wardrive_hashes[j] = _wardrive_hashes[j + 1];
      _num_wardrive--;
      return true;
    }
  }
  return false;
}

bool EdgePolicy::tryLocalCopy(uint32_t now_ms) {
  if (now_ms - _rl_start_ms >= EDGE_LOCAL_COPY_WINDOW_MS) {
    _rl_start_ms = now_ms;
    _rl_count = 0;
  }
  if (_rl_count >= EDGE_LOCAL_COPY_MAX) return false;
  _rl_count++;
  return true;
}

bool EdgePolicy::tryWardriveEcho(uint32_t now_ms) {
  if (now_ms - _wd_start_ms >= EDGE_WARDRIVE_ECHO_WINDOW_MS) {
    _wd_start_ms = now_ms;
    _wd_count = 0;
  }
  if (_wd_count >= EDGE_WARDRIVE_ECHO_RATE_MAX) return false;
  _wd_count++;
  return true;
}

bool EdgePolicy::tryAckForward(uint32_t now_ms) {
  if (now_ms - _ack_start_ms >= EDGE_ACK_FWD_WINDOW_MS) {
    _ack_start_ms = now_ms;
    _ack_count = 0;
  }
  if (_ack_count >= EDGE_ACK_FWD_MAX) return false;
  _ack_count++;
  return true;
}

bool EdgePolicy::tryTrace(uint32_t now_ms) {
  if (now_ms - _tr_start_ms >= EDGE_TRACE_WINDOW_MS) {
    _tr_start_ms = now_ms;
    _tr_count = 0;
  }
  if (_tr_count >= EDGE_TRACE_MAX) return false;
  _tr_count++;
  return true;
}

static bool isFloodRoute(uint8_t route) {
  return route == ROUTE_TYPE_FLOOD || route == ROUTE_TYPE_TRANSPORT_FLOOD;
}

static bool isDirectRoute(uint8_t route) {
  return route == ROUTE_TYPE_DIRECT || route == ROUTE_TYPE_TRANSPORT_DIRECT;
}

EdgeAction EdgePolicy::classify(const mesh::Packet* pkt, const uint8_t* self_hash, uint8_t self_hash_len) const {
  if (!_valid) return EDGE_DROP;  // fail closed: receive-only

  uint8_t route = pkt->getRouteType();
  uint8_t ptype = pkt->getPayloadType();
  uint8_t path_count = pkt->getPathHashCount();

  if (isFloodRoute(route)) {
    switch (ptype) {
      case PAYLOAD_TYPE_TXT_MSG:
      case PAYLOAD_TYPE_REQ:
      case PAYLOAD_TYPE_RESPONSE:
      case PAYLOAD_TYPE_PATH: {
        if (pkt->payload_len < 2) return EDGE_DROP;
        uint8_t dest_hash = pkt->payload[0];
        uint8_t src_hash = pkt->payload[1];
        if (path_count == 0) {
          // Directly heard (zero-hop). Only an owner's own transmission may enter
          // the stock flood path; anything else is foreign transit.
          // The empty-path requirement keeps a packet already circulating in the
          // mesh from being mistaken for a local owner transmission.
          return isOwnerHash(src_hash) ? EDGE_STOCK : EDGE_DROP;
        }
        // Already circulating: deliver a local copy if it is addressed to an owner.
        return isOwnerHash(dest_hash) ? EDGE_LOCAL_COPY : EDGE_DROP;
      }
      case PAYLOAD_TYPE_GRP_TXT:
      case PAYLOAD_TYPE_GRP_DATA: {
        if (pkt->payload_len < 1) return EDGE_DROP;
        uint8_t ch = pkt->payload[0];
        // A wardriving channel: posts heard zero-hop go out as on an opted-in channel; echoes (path >= 1) are
        // handed down with their path only if they are of a post we sent on (EdgeWardrive.h), else dropped.
        if (isWardrive(ch)) return path_count == 0 ? EDGE_STOCK : EDGE_WARDRIVE_ECHO;
        if (!isChannel(ch)) return EDGE_DROP;
        // Configured channel: owner opted in. Outbound (zero-hop) group traffic
        // goes through the normal flood path; inbound floods get a local copy.
        return path_count == 0 ? EDGE_STOCK : EDGE_LOCAL_COPY;
      }
      case PAYLOAD_TYPE_ADVERT: {
        if (pkt->payload_len < PUB_KEY_SIZE) return EDGE_DROP;
        // Never export an owner's advert outward: that would publish a route
        // through this moving relay.
        if (isOwnerPubkey(pkt->payload)) return EDGE_DROP;
        // Optional one-way discovery: mirror selected remote adverts locally.
        // Disabled by default.
        if (_mirror_adverts && path_count > 0) return EDGE_LOCAL_COPY;
        return EDGE_DROP;
      }
      case PAYLOAD_TYPE_ANON_REQ: {
        // A login (to a repeater or room): [dest hash][sender's 32-byte public key][...]. Unlike other packets it
        // names its sender in full, so an owner's own, heard zero-hop, goes out like their other requests.
        // A login to this node itself is not one to pass on: its own zero-hop login rule decides that.
        if (path_count != 0 || pkt->payload_len < 1 + PUB_KEY_SIZE || pkt->payload[0] == self_hash[0]) return EDGE_DROP;
        return isOwnerPubkey(&pkt->payload[1]) ? EDGE_STOCK : EDGE_DROP;
      }
      case PAYLOAD_TYPE_ACK: {
        // ACKs carry no attributable owner identity; default is to drop.
        return _fwd_acks ? EDGE_STOCK : EDGE_DROP;
      }
      default:
        // TRACE, CONTROL, MULTIPART, RAW_CUSTOM, unknown: drop.
        // (ANON_REQ is answered only when zero-hop direct; see below.)
        return EDGE_DROP;
    }
  }

  if (isDirectRoute(route)) {
    if (ptype == PAYLOAD_TYPE_TRACE) {
      // A trace's path field holds SNRs, not hashes, so the next-hop rules below do not apply to it: its
      // hops are listed in the payload (EdgeTrace.h). Relay it only when this node is the next one named.
      return edgeTraceNextHopIsSelf(pkt, self_hash, self_hash_len) ? EDGE_STOCK : EDGE_DROP;
    }
    if (path_count == 0) {
      // Zero-hop direct: link-local only. Allow control (e.g. discovery),
      // anonymous requests (info queries + password login), and post-login
      // admin session packets from known clients (handled just above in
      // onRecvPacket) through stock handling; a direct exchange cannot
      // propagate or teach the mesh a path through us. Everything else: drop.
      return (ptype == PAYLOAD_TYPE_CONTROL || ptype == PAYLOAD_TYPE_ANON_REQ)
                 ? EDGE_STOCK : EDGE_DROP;
    }
    // This node must be the named next hop, or the packet is not ours to touch.
    uint8_t hash_len = pkt->getPathHashSize();
    if (hash_len > self_hash_len) return EDGE_DROP;
    if (memcmp(pkt->path, self_hash, hash_len) != 0) return EDGE_DROP;

    switch (ptype) {
      case PAYLOAD_TYPE_TXT_MSG:
      case PAYLOAD_TYPE_REQ:
      case PAYLOAD_TYPE_RESPONSE:
      case PAYLOAD_TYPE_PATH: {
        if (pkt->payload_len < 2) return EDGE_DROP;
        // Forward only owner-associated direct traffic; stock consumes our path
        // entry exactly as usual. This keeps a direct path the owner's companion
        // learned while parked working, without making this node general transit.
        uint8_t dest_hash = pkt->payload[0];
        uint8_t src_hash = pkt->payload[1];
        return (isOwnerHash(dest_hash) || isOwnerHash(src_hash)) ? EDGE_STOCK : EDGE_DROP;
      }
      case PAYLOAD_TYPE_GRP_TXT:
      case PAYLOAD_TYPE_GRP_DATA: {
        if (pkt->payload_len < 1) return EDGE_DROP;
        return isChannel(pkt->payload[0]) ? EDGE_STOCK : EDGE_DROP;
      }
      case PAYLOAD_TYPE_ACK: {
        // A delivery receipt routed through us: nodes learn a route through this node only from traffic it carried,
        // which is owners' traffic, so a direct receipt naming it is an owner's (flood receipts name nobody: those
        // stay behind fwd_acks).
        // A receipt is 4-6 bytes (BaseChatMesh::sendAckTo): anything longer is not one, and would make this
        // node carry a stranger's payload. Forwards are also rate-limited (tryAckForward).
        return pkt->payload_len >= 4 && pkt->payload_len <= EDGE_ACK_MAX_LEN ? EDGE_STOCK : EDGE_DROP;
      }
      case PAYLOAD_TYPE_MULTIPART: {
        // the multi-ACK form of the same receipt (Mesh::createMultiAck): [remaining << 4 | ACK][ack...]
        if (pkt->payload_len < 5 || pkt->payload_len > 1 + EDGE_ACK_MAX_LEN) return EDGE_DROP;
        return (pkt->payload[0] & 0x0F) == PAYLOAD_TYPE_ACK ? EDGE_STOCK : EDGE_DROP;
      }
      case PAYLOAD_TYPE_ANON_REQ: {
        // an owner's login on its way to a repeater or room, by a route through us (it names its sender in full)
        if (pkt->payload_len < 1 + PUB_KEY_SIZE) return EDGE_DROP;
        return isOwnerPubkey(&pkt->payload[1]) ? EDGE_STOCK : EDGE_DROP;
      }
      default:
        // everything else (CONTROL, other MULTIPART, RAW_CUSTOM): drop. (TRACE is handled above.)
        return EDGE_DROP;
    }
  }

  return EDGE_DROP;
}

// --- persistence: simple line-based text format ---
//   ER1
//   owner <64 hex chars of pubkey>
//   chan <2 hex chars of channel hash>
//   wardrive <2 hex chars of channel hash>
//   mirror_adverts 0|1
//   fwd_acks 0|1
// Any parse error invalidates the whole policy (fail closed).

// The policy file and the stats file (EdgeStats.h) open the same way on every platform.
static File openEdgeRead(FILESYSTEM* fs, const char* path) {
#if defined(RP2040_PLATFORM)
  return fs->open(path, "r");
#else
  return fs->open(path);   // ESP32 default is read; NRF52 Adafruit default is FILE_O_READ
#endif
}

static File openEdgeWrite(FILESYSTEM* fs, const char* path) {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  // FILE_O_WRITE does not truncate: it opens read/write and seeks to the end,
  // so without the remove every save appended another copy of the policy and
  // load() stopped at the second "ER1" (same pattern as IdentityStore::save).
  fs->remove(path);
  return fs->open(path, FILE_O_WRITE);
#elif defined(RP2040_PLATFORM)
  return fs->open(path, "w");
#else
  return fs->open(path, "w", true);
#endif
}

bool EdgePolicy::load(FILESYSTEM* fs) {
  if (parsePolicy(fs)) return true;
  // Any parse error invalidates the whole policy: drop whatever was parsed
  // before the error too, so a later save() can't persist a half-read file.
  _valid = false;
  _num_owners = 0;
  _num_channels = 0;
  _num_wardrive = 0;
  _mirror_adverts = false;
  _fwd_acks = false;
  return false;
}

bool EdgePolicy::parsePolicy(FILESYSTEM* fs) {
  _valid = false;
  _num_owners = 0;
  _num_channels = 0;
  _num_wardrive = 0;
  _mirror_adverts = false;
  _fwd_acks = false;

  File f = openEdgeRead(fs, EDGE_POLICY_FILE);
  if (!f) return false;

  char line[80];
  int n = 0;
  bool got_magic = false;
  // parse one line at a time, char by char (f.read() is the portable primitive here)
  while (true) {
    int c = f.read();
    if (c < 0 || c == '\n') {
      line[n] = 0;
      // trim trailing CR/whitespace
      while (n > 0 && (line[n - 1] == '\r' || line[n - 1] == ' ' || line[n - 1] == '\t')) line[--n] = 0;
      if (n > 0 && line[0] != '#') {
        if (!got_magic) {
          if (strcmp(line, "ER1") != 0) { f.close(); return false; }
          got_magic = true;
        } else if (memcmp(line, "owner ", 6) == 0) {
          uint8_t key[PUB_KEY_SIZE];
          if (strlen(line + 6) != PUB_KEY_SIZE * 2 || !mesh::Utils::fromHex(key, PUB_KEY_SIZE, line + 6)) {
            f.close(); return false;
          }
          if (addOwner(key) < 0) { f.close(); return false; }  // duplicate or full
        } else if (memcmp(line, "chan ", 5) == 0) {
          uint8_t h;
          if (strlen(line + 5) != 2 || !mesh::Utils::fromHex(&h, 1, line + 5)) {
            f.close(); return false;
          }
          if (addChannel(h) < 0) { f.close(); return false; }
        } else if (memcmp(line, "wardrive ", 9) == 0) {
          uint8_t h;
          if (strlen(line + 9) != 2 || !mesh::Utils::fromHex(&h, 1, line + 9)) {
            f.close(); return false;
          }
          if (addWardrive(h) < 0) { f.close(); return false; }
        } else if (memcmp(line, "mirror_adverts ", 15) == 0) {
          _mirror_adverts = (line[15] == '1');
        } else if (memcmp(line, "fwd_acks ", 9) == 0) {
          _fwd_acks = (line[9] == '1');
        } else {
          f.close(); return false;  // unknown directive -> fail closed
        }
      }
      n = 0;
      if (c < 0) break;  // EOF
    } else if (n < (int) sizeof(line) - 1) {
      line[n++] = (char) c;
    }
    // lines longer than the buffer are truncated rather than aborting; the
    // truncated directive will simply fail to match and invalidate the file
  }
  f.close();
  if (!got_magic) return false;
  _valid = true;
  return true;
}

bool EdgePolicy::save(FILESYSTEM* fs) {
  File f = openEdgeWrite(fs, EDGE_POLICY_FILE);
  if (!f) return false;
  f.println("ER1");
  char hex[PUB_KEY_SIZE * 2 + 1];
  for (int i = 0; i < _num_owners; i++) {
    for (int k = 0; k < PUB_KEY_SIZE; k++) {
      sprintf(&hex[k * 2], "%02x", _owner_keys[i][k]);
    }
    f.print("owner ");
    f.println(hex);
  }
  for (int i = 0; i < _num_channels; i++) {
    sprintf(hex, "%02x", _channel_hashes[i]);
    f.print("chan ");
    f.println(hex);
  }
  for (int i = 0; i < _num_wardrive; i++) {
    sprintf(hex, "%02x", _wardrive_hashes[i]);
    f.print("wardrive ");
    f.println(hex);
  }
  f.print("mirror_adverts ");
  f.println(_mirror_adverts ? "1" : "0");
  f.print("fwd_acks ");
  f.println(_fwd_acks ? "1" : "0");
  f.close();
  _valid = true;
  return true;
}

bool edgeLoadStats(FILESYSTEM* fs, EdgeStats& stats) {
  File f = openEdgeRead(fs, EDGE_STATS_FILE);
  if (!f) return false;
  char text[EDGE_STATS_TEXT_MAX];
  size_t n = 0;
  int c;
  while ((c = f.read()) >= 0) {
    if (n + 1 >= sizeof(text)) {  // longer than any this firmware writes: not ours
      f.close();
      return false;
    }
    text[n++] = (char)c;
  }
  f.close();
  text[n] = 0;
  return stats.parse(text);
}

bool edgeSaveStats(FILESYSTEM* fs, EdgeStats& stats, uint32_t now_ms) {
  char text[EDGE_STATS_TEXT_MAX];
  int n = stats.serialize(text, sizeof(text));
  bool ok = n > 0;
  if (ok) {
    File f = openEdgeWrite(fs, EDGE_STATS_FILE_NEW);
    ok = f && f.write((const uint8_t*)text, (size_t)n) == (size_t)n;
    if (f) f.close();
  }
  if (ok && !fs->rename(EDGE_STATS_FILE_NEW, EDGE_STATS_FILE)) {
    // LittleFS renames over a file; SPIFFS will not, so make room
    fs->remove(EDGE_STATS_FILE);
    ok = fs->rename(EDGE_STATS_FILE_NEW, EDGE_STATS_FILE);
  }
  if (!ok) fs->remove(EDGE_STATS_FILE_NEW);
  stats.saved_ms = now_ms;    // a failed save is tried again at the next interval, not at once
  stats.save_failed = !ok;    // said on `edge stats life` and in the 0xC0 flags, not kept quiet
  if (ok) stats.dirty = false;
  return ok;
}

void edgeStatusReply(const EdgePolicy& policy, const EdgeStats& stats, char* reply, size_t cap) {
  const uint32_t* c = stats.boot;
  snprintf(reply, cap, "OK - valid:%d owners:%d ch:%d up:%lu copy:%lu dfwd:%lu trace:%lu drop:%lu wd:%d wde:%lu",
           policy.isValid() ? 1 : 0, policy.getNumOwners(), policy.getNumChannels(),
           (unsigned long)(c[ES_UPLINK] + c[ES_WD_POST] + c[ES_LOGIN]), (unsigned long)c[ES_COPY],
           (unsigned long)(c[ES_DIRECT] + c[ES_ACK]), (unsigned long)(c[ES_TRACE] + c[ES_TRACE_THROUGH]),
           (unsigned long)stats.drops(false), policy.getNumWardrive(), (unsigned long)c[ES_WD_ECHO]);
}
