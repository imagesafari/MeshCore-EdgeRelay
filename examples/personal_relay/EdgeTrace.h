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
