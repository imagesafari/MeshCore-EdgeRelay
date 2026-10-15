#pragma once

// A channel as `edge chan` and `edge wardrive` take it: its 1-byte hash (2 hex chars, as on the air), or
// its name, worked out here so nobody has to.
//
// The byte a channel post carries (Mesh::createGroupDatagram) is the first byte of SHA-256 of the
// channel's secret key (BaseChatMesh::addChannel) — not the key's own first byte, which is what an app
// shows and the easy thing to copy by mistake (Public's key starts 8b; its hash is 11).
//
//   Public  - the key every companion is built with (PUBLIC_GROUP_PSK, izOH6cXN6mrJ5e26oRXNcg==)
//   #name   - a hashtag channel: its key is the first 16 bytes of SHA-256 of the name as typed, '#'
//             included (docs/companion_protocol.md, "Hashtag Channels"; the meshcore Python library does
//             the same, with no change of case). So #Test and #test are different channels.
//
// A private channel's hash needs its secret, which this does not take: give its 2 hex chars.

#include <Utils.h>
#include <ctype.h>
#include <string.h>

#define EDGE_CHANNEL_NAME_MAX 31  // a channel name fills at most 32 bytes, its terminator included

static const uint8_t EDGE_PUBLIC_KEY[16] = {0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a,
                                            0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15, 0xcd, 0x72};

static inline uint8_t edgeChannelHashOfKey(const uint8_t* key, int key_len) {
  uint8_t h;
  mesh::Utils::sha256(&h, 1, key, key_len);
  return h;
}

// arg: "11", "Public" (any case), or "#name". On success the hash, and in `name` what it was taken as
// ("" for 2 hex). On failure false, and `err` says what it takes.
static inline bool edgeChannelHash(const char* arg, uint8_t* out, const char** name, const char** err) {
  size_t n = strlen(arg);
  *name = "";
  if (n == 2 && isxdigit((unsigned char)arg[0]) && isxdigit((unsigned char)arg[1])) {
    return mesh::Utils::fromHex(out, 1, arg);
  }
  if (n == 6 && strncasecmp(arg, "public", 6) == 0) {
    *out = edgeChannelHashOfKey(EDGE_PUBLIC_KEY, sizeof(EDGE_PUBLIC_KEY));
    *name = "Public";
    return true;
  }
  if (arg[0] == '#' && n >= 2 && n <= EDGE_CHANNEL_NAME_MAX) {
    for (size_t i = 1; i < n; i++) {
      if (arg[i] == ' ') {
        *err = "Err - a #name has no spaces";
        return false;
      }
    }
    uint8_t key[32];
    mesh::Utils::sha256(key, sizeof(key), (const uint8_t*)arg, (int)n);
    *out = edgeChannelHashOfKey(key, 16);
    *name = arg;
    return true;
  }
  *err = "Err - give 2 hex (the channel hash), Public, or #name";
  return false;
}
