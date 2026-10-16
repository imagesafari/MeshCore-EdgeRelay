#pragma once

#include <stdint.h>
#include <string.h>
#include <Packet.h>

// Bytes before a TRACE's hop list: a 4-byte tag, a 4-byte auth code and a flags byte.
#define EDGE_TRACE_HDR  9

/**
 * Whether this node is the next hop of a direct TRACE, the only case in which the edge relay relays one.
 *
 * A trace names the hops it should visit in its payload, after the header; the low 2 bits of the flags
 * byte give each hop hash's size (1 << bits bytes). Its path field holds no hashes: each relay appends the
 * SNR it heard the trace at, so path_len counts the hops done. This mirrors stock src/Mesh.cpp
 * (onRecvPacket, PAYLOAD_TYPE_TRACE). A trace carries no message and teaches no route, so relaying one when
 * named does not make this node transit for anything else.
 *
 * self: this node's public key prefix, self_len bytes of it (at least the trace's hash size).
 */
inline bool edgeTraceNextHopIsSelf(const mesh::Packet* pkt, const uint8_t* self, uint8_t self_len) {
  if (!pkt->isRouteDirect() || pkt->getPayloadType() != PAYLOAD_TYPE_TRACE) return false;
  if (pkt->payload_len < EDGE_TRACE_HDR || pkt->path_len >= MAX_PATH_SIZE) return false;
  uint8_t bits = pkt->payload[8] & 0x03;
  uint8_t size = (uint8_t)(1u << bits);
  uint32_t off = EDGE_TRACE_HDR + ((uint32_t)pkt->path_len << bits);
  if (size > self_len || off + size > pkt->payload_len) return false;  // past its last hop, or too wide
  return memcmp(&pkt->payload[off], self, size) == 0;
}

// Whether a direct TRACE has been everywhere it names: stock then hands it to onTraceRecv on any node that hears it
// (the sender knows it by its tag). Mirrors stock src/Mesh.cpp: offset (path_len << bits) >= the hop list's length.
inline bool edgeTraceComplete(const mesh::Packet* pkt) {
  if (!pkt->isRouteDirect() || pkt->getPayloadType() != PAYLOAD_TYPE_TRACE) return false;
  if (pkt->payload_len < EDGE_TRACE_HDR || pkt->path_len >= MAX_PATH_SIZE) return false;
  uint8_t bits = pkt->payload[8] & 0x03;
  return ((uint32_t)pkt->path_len << bits) >= (uint32_t)(pkt->payload_len - EDGE_TRACE_HDR);
}

inline uint32_t edgeTraceTag(const mesh::Packet* pkt) {
  uint32_t tag = 0;
  if (pkt->payload_len >= 4) memcpy(&tag, pkt->payload, 4);
  return tag;
}

// Transparent trace: the tags of owners' traces this node sent on, so the completed trace with the
// same tag is handed back down to the owner, who may not hear the repeater it went to. A few seconds each.
#define EDGE_TRACE_RING      8
#define EDGE_TRACE_BACK_MS   8000UL

class EdgeTraceRing {
  uint32_t _tag[EDGE_TRACE_RING];
  uint32_t _ms[EDGE_TRACE_RING];
  bool _used[EDGE_TRACE_RING];
  uint8_t _next;
public:
  EdgeTraceRing() : _next(0) { memset(_used, 0, sizeof(_used)); }
  void remember(uint32_t tag, uint32_t now_ms) {
    _tag[_next] = tag;
    _ms[_next] = now_ms;
    _used[_next] = true;
    _next = (uint8_t)((_next + 1) % EDGE_TRACE_RING);
  }
  // True once for a tag remembered within the window: its result is ours to hand back, once.
  bool take(uint32_t tag, uint32_t now_ms) {
    for (int i = 0; i < EDGE_TRACE_RING; i++) {
      if (_used[i] && _tag[i] == tag && now_ms - _ms[i] <= EDGE_TRACE_BACK_MS) {
        _used[i] = false;
        return true;
      }
    }
    return false;
  }
};
