#pragma once

// Wardrive echo-down, for a channel the owner marks as their wardriving channel (MeshMapper posts to
// #wardriving and credits a repeater when it hears its own post repeated, with that repeater in the path).
//
// A stock repeater in the car sends the owner's post on, but ignores the echoes that come back: it has already
// sent that packet. So the owner's phone only credits repeaters it can hear itself. Here, for a few seconds
// after the relay sends an owner's post on, an echo of it is handed back down as a DIRECT packet with its path
// kept and this relay as the first hop ([relay, R1, ...]). MeshMapper's CARpeater pass-through then strips the
// relay and credits R1. A direct packet is retransmitted only by the node named first in its path, and only if
// that node has not already seen the packet (src/Mesh.cpp), so the copy goes no further than the owner.
//
// Pure (no radio, no clock): unit-tested in test/test_edge_wardrive.

#include <stdint.h>
#include <string.h>
#include <Packet.h>

#define EDGE_WARDRIVE_SLOTS      8      // posts remembered at once
#define EDGE_WARDRIVE_WINDOW_MS  6000UL // MeshMapper listens 5 s for echoes
#define EDGE_WARDRIVE_MAX_ECHO   6      // echoes handed down per post
#define EDGE_WARDRIVE_KEY_LEN    8      // bytes of the packet hash kept (MAX_HASH_SIZE)

class EdgeWardriveRing {
  struct Slot {
    uint8_t key[EDGE_WARDRIVE_KEY_LEN];
    uint32_t at_ms;
    uint8_t echoes;
    bool used;
  };
  Slot _slots[EDGE_WARDRIVE_SLOTS];
  uint8_t _next;

public:
  EdgeWardriveRing() : _next(0) { memset(_slots, 0, sizeof(_slots)); }

  // A post this relay just sent on: its echoes may be handed down for the next window.
  void remember(const uint8_t key[EDGE_WARDRIVE_KEY_LEN], uint32_t now_ms) {
    Slot& s = _slots[_next];
    memcpy(s.key, key, EDGE_WARDRIVE_KEY_LEN);
    s.at_ms = now_ms;
    s.echoes = 0;
    s.used = true;
    _next = (uint8_t)((_next + 1) % EDGE_WARDRIVE_SLOTS);
  }

  // An echo heard: true (and counted) if it is of a remembered post, inside the window, under the cap.
  bool takeEcho(const uint8_t key[EDGE_WARDRIVE_KEY_LEN], uint32_t now_ms) {
    for (int i = 0; i < EDGE_WARDRIVE_SLOTS; i++) {
      Slot& s = _slots[i];
      if (!s.used || memcmp(s.key, key, EDGE_WARDRIVE_KEY_LEN) != 0) continue;
      if (now_ms - s.at_ms > EDGE_WARDRIVE_WINDOW_MS || s.echoes >= EDGE_WARDRIVE_MAX_ECHO) return false;
      s.echoes++;
      return true;
    }
    return false;
  }
};

// The path for the copy handed down: the echo's own path, with this relay as the first hop (kept if it already
// is, prepended if not). out_path_len is in the packet's encoding (hash size in the top 2 bits, count below).
// False if the echo has no hops, uses a hash wider than self_len, or there is no room to prepend.
inline bool edgeWardriveEchoPath(const mesh::Packet* echo, const uint8_t* self_hash, uint8_t self_len,
                                 uint8_t out_path[MAX_PATH_SIZE], uint8_t& out_path_len) {
  uint8_t count = echo->getPathHashCount();
  uint8_t size = echo->getPathHashSize();
  if (count == 0 || size > self_len || !mesh::Packet::isValidPathLen(echo->path_len)) return false;
  if (memcmp(echo->path, self_hash, size) == 0) {
    memcpy(out_path, echo->path, (size_t)count * size);
    out_path_len = echo->path_len;
    return true;
  }
  if ((size_t)(count + 1) * size > MAX_PATH_SIZE || count + 1 > 63) return false;
  memcpy(out_path, self_hash, size);
  memcpy(out_path + size, echo->path, (size_t)count * size);
  out_path_len = (uint8_t)(((size - 1) << 6) | (count + 1));
  return true;
}
