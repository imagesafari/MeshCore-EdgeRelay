# MeshCore EdgeRelay

A personal, car-based MeshCore edge relay. This is a **fork** of the official
[MeshCore](https://github.com/meshcore-dev/MeshCore) repository, modified so a
repeater installed in a parked car can serve its owner's companion devices
without burdening the wider mesh.

**Upstream:** https://github.com/meshcore-dev/MeshCore — all core protocol,
radio, and platform code is theirs, under the MIT license (see `LICENSE`).

## Why this fork exists

A companion node inside an office building can't always reach the fixed
repeater infrastructure directly. A relay on a car in the parking lot bridges
that gap — but a moving relay that behaves like a normal repeater is a bad
mesh citizen: it would learn and advertise paths that go stale, forward other
people's traffic, and add airtime load. So this fork adds a new
`examples/personal_relay` firmware — a **directional edge relay** built on the
stock `simple_repeater` example, which is left untouched:

- **Uplink:** forwards flood traffic that originates directly from a
  whitelisted companion the owner configured. No other flood goes out.
- **Downlink:** re-emits selected inbound traffic as a single local
  zero-hop copy for nearby owners. Neighbors ignore it (direct route, empty
  path) and no return path is learned through the car.
- **Traces:** relayed when the car is the next hop the trace names (anyone's, since a trace names no
  sender; at most 10 a minute). They let you measure the links through the car and teach no routes.
  A fresh trace heard loud from inside the car that does not name it is sent on unchanged, and its
  result handed back (transparent trace, below).
- **Everything else:** dropped.

## What changed vs upstream

Based on MeshCore **1.18.0** (`repeater-v1.18.0`). All changes are confined to `examples/personal_relay/`
(plus this README, `build.sh`, one new build environment, and one new workflow). Core protocol code in
`src/` and the stock `simple_repeater` example are untouched.

| Area | Change |
|---|---|
| `EdgePolicy.h` / `EdgePolicy.cpp` (new) | Packet classifier, persisted configuration, per-class rate limiting, the stats file. |
| `EdgeStats.h` (new) | What the relay did, counted since boot and lifetime (`edge stats`, request `0xC0`). |
| `EdgeTrace.h` (new) | Trace hop checks and the transparent trace ring. |
| `MyMesh::onRecvPacket()` | Every received packet is classified **before** stock handling: `EDGE_STOCK` (proceed), `EDGE_LOCAL_COPY` (re-emit once as zero-hop direct, drop original), or `EDGE_DROP`. |
| `MyMesh::allowPacketForward()` | Final deny guard — stock forwarding is permitted only for packets the policy approved. |
| `sendSelfAdvertisement()` | No-op. The car **never** advertises, so the mesh never learns routes through a moving node. |
| `updateAdvertTimer()` / `updateFloodAdvertTimer()` / `loop()` | Advert timers permanently stopped; timer blocks removed from `loop()`. Boot adverts are also suppressed via the no-op. |
| `handleCommand()` | New `edge` CLI for configuration over USB serial (see below). |

### Packet policy (default)

| Traffic | Flood | Direct (car is next hop) |
|---|---|---|
| `TXT_MSG`, `REQ`, `RESPONSE`, `PATH` from a whitelisted owner (heard directly) | Forward normally | — |
| Same, addressed to an owner (already circulating) | Re-emit locally as one zero-hop copy | — |
| Same, unrelated to owners | Drop | Drop |
| `GRP_TXT` / `GRP_DATA` on a configured channel | Owner's own transmission: forward; inbound: local copy | Forward if channel configured |
| `GRP_TXT` / `GRP_DATA` on a wardriving channel | Heard zero-hop: forward; echoes of a post the car sent on: handed down with their path (below) | Forward if channel configured |
| `ADVERT` from an owner | Drop (never export owner adverts) | — |
| `ADVERT` from anyone else | Drop (mirroring opt-in only, off by default) | — |
| `ACK` | Drop (forwarding opt-in only, off by default) | Forward when the car is the named next hop (a delivery receipt on an owner's route), and the multi-ACK form (`MULTIPART` wrapping an ACK): receipt-sized only (4-8 bytes), at most 30 a minute, since an ACK names no sender |
| `ANON_REQ` (a login) | Forward an owner's own, heard directly, to another node: it carries the sender's full public key, checked against the owner list (a flood login to the car itself is still dropped) | Forward an owner's when the car is the named next hop. Zero-hop to the car itself: info queries, password login, and the resulting admin session (stock crypto auth still enforced) |
| `TRACE` | — (always sent direct) | Relayed when the car is the next hop on the trace's own list, at most 10 a minute. Not naming the car: a fresh one heard at `trace_snr` or better is sent on unchanged, and its completed result handed back (transparent trace) |
| `MULTIPART`, `RAW_CUSTOM`, unknown | Drop | Drop |
| `CONTROL` | Drop | Drop. Zero-hop control is handled as stock, except that the car **does not answer node discovery**: it never advertises, and from MeshCore 1.18 a node that does not advertise is not discoverable |

Notes:

- **Source authentication is weak by design of the wire format.** Ordinary
  packets expose only a 1-byte public-key prefix, so owner matching is
  prefix-based and spoofable. This firmware does not claim cryptographic
  attribution of uplink traffic — it fails closed and treats the prefix
  check as a routing hint, not authentication. Group traffic is matched on
  the 1-byte channel hash you explicitly configure.
- Local copies preserve payload bytes and payload type exactly; only the
  route is reframed to zero-hop direct. Public/channel messages stay
  public/channel messages — no per-companion DMs are created. The relay
  never re-signs or re-encrypts anything.
- Dedup uses the same seen-table as stock MeshCore (hash over payload type
  + payload), so one inbound message yields at most one local copy.
- Local copies are rate-limited (30/minute, sliding window).
- Traces: a trace lists the hops it should visit in its payload and collects one SNR per hop in its path
  field, so the car relays one only when it is the next hop named in that list (`EdgeTrace.h`, mirroring
  stock `src/Mesh.cpp`). A trace teaches no route and carries only the sender's hop list (plus whatever payload bytes the sender
  chose), so this lets you measure the
  office-to-car and car-to-repeater links without making the car transit for anything else. It names no
  sender, so it cannot be limited to owners; relayed traces are capped at 10 a minute instead. To trace
  through the car you need its hash: `get public.key` on its serial console (it does not answer discovery).
- **Transparent trace.** MeshMapper's trace mode on your pocket companion traces one repeater (`[R1]`), so
  the trace does not name the car, and the car would drop it. With transparent trace the car sends it on
  **unchanged**: it adds no hop and no SNR of its own, so the trace reads as if your pocket companion had
  reached `R1` itself. That is the car's coverage, which is what MeshMapper maps.
  - **Out:** a direct trace with nothing traced yet, not naming the car, heard at `trace_snr` (default
    6 dB) or better. A trace has no sender to check against the owner list. A loud one is from inside the
    car (your phone is a few feet away); a stranger's down the road is not.
  - **Back:** `R1` answers with the trace complete. The car hands that back down, as heard, if it sent the
    trace out in the last 8 s (matched by its tag), so your pocket companion hears its result. Any other
    completed trace is not the car's to send, and is dropped.
  - Counted once per trace, as `trt` in `edge stats`. Going out shares the 10 a minute with traces that
    name the car (`rl tr`); the answer back does not spend it again (there is at most one per trace
    sent). With repeat off (`set repeat off`) nothing goes out.
  - A stranger's trace heard that loud would go out once; the rate limit and `R1`'s own duplicate check
    bound it. `edge trace_snr off` turns transparent trace off.
  - **Downgrading:** a `trace_snr` line is written to `/edge_policy` only when it is not the default.
    Firmware older than this treats it as unknown and boots receive-only (fail closed). Run
    `edge trace_snr 6` before flashing an older build.
- **Wardriving (MeshMapper).** `edge wardrive add 81` (81 is `#wardriving`'s hash) makes the car behave
  like a repeater for your wardriving pings, and pass their echoes back down to you:
  - A post on that channel heard zero-hop is sent on, as on any configured channel.
  - For 6 s after that, echoes of it that come back (path `[car, R1, …]`) are handed down as a **direct**
    packet with the path kept and the car first, at most 6 per post (`EdgeWardrive.h`). A stock repeater
    ignores those echoes, having already sent the packet; handing them down lets the phone credit
    repeaters only the car's antenna reaches.
  - In MeshMapper, set the car as your **CARpeater**: it strips the car from the path and credits the next
    repeater. Without that setting MeshMapper reads the copy as an ordinary multi-hop echo: at −30 dBm or
    stronger (likely, in the car) it drops it as a car repeater; weaker, it shows it credited to the last
    hop with the car link's signal, and does not upload it.
  - The copy goes no further: a direct packet is retransmitted only by the node named first (the car),
    and only if that node has not seen it. A post is remembered only once the car actually sends it on
    (every forwarding check passed, region scope included), so echoes of posts it did not send on are
    dropped.
  - Hand-downs have their own rate limit (24 a minute), separate from the 30 a minute for owners' local
    copies, so wardriving never starves delivery of your messages.
  - **Downgrading:** firmware older than this treats a `wardrive` line in `/edge_policy` as unknown and
    boots receive-only (fail closed). Run `edge wardrive del 81` before flashing an older build.
  - A wardriving channel takes precedence over the same hash in `chan`. Like a configured channel, it
    carries anyone's zero-hop post on it, not only an owner's: a channel post names no sender.
- App login and remote administration are allowed, but only from direct radio
  range (zero-hop): the admin password is still required, and stock's
  cryptographic authentication applies to every session packet (the 1-byte
  prefix the classifier sees is only a routing hint). Flood and multi-hop
  admin traffic is dropped, so the node cannot be administered through the
  wider mesh. USB serial remains available as the primary console.
  Commands are accepted as CLI data or as MeshCore 1.18's explicit CLI type.
- New installs start with **loop detection minimal**, as upstream repeaters do from 1.18 (`set loop.detect`
  changes it; a saved setting is kept).
- With no valid policy file on the filesystem, the node boots **receive-only**
  (fail closed) until you configure owners via the CLI.

### CLI (`edge`)

Over USB serial at 115200 baud (also works on the ethernet console where enabled):

```
edge status                  - show policy + counters (incl. traces relayed, wardrive echoes handed down)
edge owner list              - list owner pubkeys
edge owner show <idx>        - show one owner pubkey in the reply
edge owner add <64 hex>      - add owner, save
edge owner del <64 hex>      - remove owner, save
edge chan list               - list mirrored channel hashes
edge chan add <ch>           - add channel, save (ch: Public, #name, or its 2-hex hash)
edge chan del <ch>           - remove channel, save
edge wardrive list           - list wardriving channel hashes
edge wardrive add <ch>       - wardriving channel (#wardriving): send on, hand echoes back with path, save
edge wardrive del <ch>       - remove wardriving channel, save
edge opt mirror_adverts 0|1  - remote advert mirroring, save (default 0)
edge opt fwd_acks 0|1        - ACK forwarding, save (default 0)
edge trace_snr [<dB>|off]    - transparent trace threshold, -20 to 30, save (default 6); alone: show it
edge stats [<page>]          - counts by kind: boot (default), life, drops, drops life, owners, late
edge stats save              - save the lifetime counts now
edge stats reset             - zero both sets (owners stay listed), save
```

Configuration persists to `/edge_policy` on the device filesystem.

`edge status` replies `OK - valid:1 owners:1 ch:1 up:… copy:… dfwd:… trace:… drop:… wd:0 wde:…`. The
counts are since boot, and each total is the sum of these `edge stats` counters:

- `up`: owner floods, wardriving posts, and owners' logins (flood, or routed through the car) sent on
  (`up` + `wdp` + `login`).
- `copy`: local copies (`copy`).
- `dfwd`: owners' other direct packets routed through the car, and receipts: direct ones naming the car, and
  flood ones with `fwd_acks 1` (`dfwd` + `ack`).
- `trace`: traces naming the car, and transparent traces (`tr` + `trt`).
- `drop`: everything not sent on, for every reason: policy, packet pool empty, each rate limit, and
  wardriving echoes of posts the car did not send on (the whole `stats drops` page).
- `wde`: wardriving echoes handed down (`wde`).

Earlier firmware counted these differently: a login routed through the car in `dfwd`, a flood receipt
heard directly in `up`, an owner flood as it was heard rather than when it was sent on, and wardriving
echo losses not at all.

#### Edge stats

What the car did, counted two ways: **since boot**, and **lifetime**, which survives reboots. Lifetime
counts are saved to `/edge_stats` every 6 hours when they changed, on `edge stats save`, and before a
reboot or power-off you ask for (`reboot`, `clkreboot`, `poweroff`, `shutdown`, `start ota`, or holding
the user button). A crash or a pulled battery loses at most the 6 hours since the last save. A missing or
half-written file starts them from zero.

| Page | What it counts |
|---|---|
| `stats` / `stats boot` / `stats life` | sent on: `up` owner floods, `copy` zero-hop copies, `dfwd` direct, `ack` receipts, `tr` traces naming the car, `trt` owners' traces through it (transparent), `wdp` wardriving posts, `wde` echoes handed down, `login` owners' logins |
| `stats drops` / `stats drops life` | not sent on, by reason: `pol` not an owner's or a chosen channel; `nobuf` packet pool empty; `rl` over a rate limit (`copy`, `ack`, `tr`, `echo`); `notours` a wardriving echo of a post the car did not send on |
| `stats owners` | each owner by key prefix: packets sent on (DMs, requests and logins; a channel post names no sender), and when it was last heard directly, at what SNR (since boot) |
| `stats late` | late relay, which this firmware does not have: always 0 (kept so the counter list, and the `0xC0` frame, has a fixed layout) |

Each page fits one reply over the mesh, even with every count at its largest. If the last save of the
lifetime counts failed, `stats life` reads `life save FAILED`.

**For a console:** a logged-in client can ask for request type `0xC0` (`EDGE_REQ_GET_EDGE_STATS`, one
data byte: 0 since boot, 1 lifetime). The answer, after the 4-byte tag, is
`[version 1][set][flags][owners][channels][wardrive][count N][N × uint32 LE]`, in the order of `EdgeStat`
(`EdgeStats.h`). flags: bit 0 edge on (always, on the relay),
1 valid policy, 2 late relay (never, on the relay), 3 receipts forwarded, 4 adverts mirrored, 5 the last
lifetime save failed. `0xC0` is ours, not an upstream allocation. A stock node does not answer it, which
is how a console tells an edge node from any other. As with any admin traffic to the car, the request
must come from direct radio range.

#### Adding your companions

1. In the MeshCore phone app, open the companion's node details and copy its
   public key (64 hex characters).
2. In the serial console: `edge owner add <paste the key>`.
3. Confirm with `edge owner list` and `edge status`.

Repeat for each companion you own (up to 8). Until at least one valid policy
is saved, the node stays receive-only.

#### Adding channels

Give the channel by name and the relay works out its hash, and says it back:

```
edge chan add Public          -> OK - channel 11 (Public) added
edge chan add #test           -> OK - channel d9 (#test) added
edge wardrive add #wardriving -> OK - wardriving channel 81 (#wardriving) added
```

A channel post carries one byte to say which channel it is on: the first byte of SHA-256 of the channel's
secret key. That byte is what the relay matches, and what `chan list` shows. It is **not** the first byte of
the key itself, which is what an app shows and the easy thing to copy by mistake: Public's key starts `8b`,
its hash is `11`; `#test`'s key starts `9c`, its hash is `d9`. A wrong byte is accepted and simply never
matches anything.

- `Public` is the channel every companion is built with.
- A `#name` channel's key comes from its name, so the relay can work it out. Type the name exactly as the
  apps have it, `#` included: names are hashed as typed, so `#Test` and `#test` are different channels.
- A private channel's hash needs its secret key, which the relay does not take: give its 2-hex hash. It is
  the first byte of SHA-256 of the 16-byte key, or ask whoever set the channel up.

#### Wardriving with MeshMapper

Goal: wardrive with [MeshMapper](https://meshmapper.net) on your pocket companion while the relay in the
car extends it, and have MeshMapper credit the real repeaters, not the car.

**On the relay** (USB serial console):

1. `edge owner add <your pocket companion's key>`, if you have not already; the relay needs a valid policy.
2. `edge wardrive add #wardriving` (or `edge wardrive add 81`: `81` is its channel hash). A `chan add 81`
   you set earlier can stay; the wardriving setting takes precedence.
3. `get public.key`, and copy the 64 hex characters: MeshMapper needs them below.

**In MeshMapper** (Settings → Wardriving → CARpeater):

1. Turn on **CARpeater Filter**.
2. **My CARpeater** → paste the relay's public key. The relay never adverts, so it will not be in
   "Choose from repeater list"; paste it.
   - MeshMapper shares this key with its server, so other wardrivers in your region filter the relay
     too. That is what you want: a moving car is not fixed coverage.
3. Leave **Disable RSSI Filter** off. Echoes through your CARpeater skip that check anyway.
4. Wardrive in **Active** or **Hybrid** mode as usual, with your pocket companion connected.

**What you get:**

- **TX pings:** your `#wardriving` post goes out through the car. Echoes come back to your pocket node
  with the path kept (`[car, R1, …]`). MeshMapper strips the car and credits `R1`, the repeater that heard
  the car. These include repeaters only the car's antenna reaches. A stripped echo carries no SNR/RSSI:
  MeshMapper records the repeater, not the signal.
- **Discovery (DISC):** answered by repeaters your pocket node reaches directly. The relay does not
  answer discovery (it never advertises). Discovery is zero-hop by design, so the car cannot extend it.
- **Traces:** MeshMapper's targeted trace names one repeater. The car sends it on unchanged and hands the
  result back (transparent trace, above), so it maps the repeaters the car reaches. `edge stats` counts
  them as `trt`. (A trace that names the car first, from another tool, is relayed as before.)
- `edge status` shows `wde:` (echoes handed down) climbing while you wardrive.

Without the CARpeater setting, echoes handed down by the car are not uploaded: at the car's usual in-cabin
signal (−30 dBm or stronger) MeshMapper drops them as a likely car repeater; weaker, it shows them in its
log against the last hop but does not upload them.

## Build and flash

Same as upstream. From this directory:

```bash
pio run -e <your_target>        # build
pio run -e <your_target> -t upload   # flash
```

Every board with a stock repeater target also has a personal relay target:
`<board>_personal_relay` (e.g. `RAK_4631_personal_relay`, `Heltec_v3_personal_relay`).
Each one mirrors its board's normal repeater target with only the example
swapped to `examples/personal_relay` and the advert name changed to
`<board> Personal Relay`. Or run the **Build Personal Relay Firmwares**
workflow from the Actions tab and download the artifact (`.uf2` for the
RAK4631).

See the [upstream README](https://github.com/meshcore-dev/MeshCore#readme)
for hardware compatibility, the web flasher, clients, and unit tests.
`pio test -e native` also runs this fork's own tests (`test/test_edge_*`: the edge policy, its files,
stats, traces and wardriving), and `pio test -e native_real_crypto` the channel hashes on the real
SHA-256.

## Goals and non-goals

Goals: give the owner's companions one extra hop into the mesh; never
poison other repeaters' learned paths; add no measurable load to the wider
mesh; stay a single-purpose, reviewable change on top of stock code.

Non-goals: general-purpose repeating, movement/parked detection, GPS,
telemetry, administration beyond direct radio range, or any change to the
MeshCore wire protocol.

## License

MIT — same as upstream. See `LICENSE`.
