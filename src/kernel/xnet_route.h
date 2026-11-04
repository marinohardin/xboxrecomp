/*
 * xnet_route.h - where a peer's datagrams go (BO-134): its local address or
 * the public address the lobby saw, and which peer a datagram came from.
 *
 * The title addresses a peer by the address in its XNADDR, which is that
 * copy's own local address (the "title address"). That reaches a peer on the
 * same network, but not one behind another router. The lobby publishes each
 * player's title address (LA, LADDRn) next to the public address it saw (A,
 * ADDRn); a copy's XUID carries its port offset. So per peer:
 *
 *   - a hello came from it (below): answer where it came from
 *   - same public address as ours: the title address (same network)
 *   - another public address: the public address
 *   - TAKEDAWN_NET_FORCE_PUBLIC=1 (tests): the public address even when it
 *     is ours, through the router's NAT loopback
 *   - no public address known yet: the title address
 *
 * with the port the title used plus the peer's offset. Each copy also sends
 * a few small hellos ("TKDH") from its game socket to every peer it talks to,
 * so a router on the way opens a path back (UDP hole punching) and the other
 * copy learns where it really comes from: a router may change the source
 * port, and NAT loopback shows the router's own address as the source. A
 * hello says which title address and port it is from; it never reaches the
 * title.
 *
 * Pure bookkeeping, no sockets (tests/xnet_route). Addresses are in network
 * order, ports in host order. Not thread-safe: xnet_hle.c holds its lock.
 */
#ifndef XNET_ROUTE_H
#define XNET_ROUTE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t ip;      /* network order */
    uint16_t port;    /* host order */
} xr_ep;

#define XR_HELLO_LEN 24
/* The title's UDP ports below this move by the port offset on the host
 * (1000, 3074, 6000); higher ones (the system's own) stay. */
#define XR_TITLE_PORTS 10000
/* the tables' sizes: peers (a full table gives up the longest unused one
 * outside the current game) and learned paths (one that went quiet or whose
 * peer left the game) */
#define XR_MAX_PEERS   32
#define XR_MAX_LEARNED 64

void xr_reset(void);
/* A new game (another IDENT in a member record) or none any more (the
 * lobby's empty record, glea, gdel): no member, no secret (xr_secret_seq
 * moves on). Known peers and their learned paths stay as non-members' (not
 * used for them), the first to go when a table is full. */
void xr_game_reset(void);
/* A new lobby session (another TKSID, or our own TKADDR changed): the
 * synthetic addresses are handed out again, so every peer, learned path,
 * hello schedule, member and the secret go (BO-343). Our own address,
 * offset and public address stay. Returns how many peers and paths went. */
int  xr_session_reset(void);
/* The identity scheme (.handoff/online-identity-spec.md): the server gives
 * each capable copy a synthetic title address (TKADDR in its addr reply);
 * the others know it by that. A peer's record with TKRADDRn / TKRLA is such
 * a player: its title address is the synthetic one, the real local address
 * is its LAN path (taken only when it shares our public address). Our own
 * record stays our real address; our hellos carry the synthetic one. */
void xr_self_synth(uint32_t synth);
/* this machine's own LAN address, when the title address is another
 * (TAKEDAWN_NET_ID): where our router's NAT loopback shows (BO-345) */
void xr_self_lan(uint32_t lan);
/* BO-349, Local network mode: where this copy reaches the lobby it runs
 * itself. A lobby on loopback (127/8) is reached at the machine's LAN
 * address lan, so the lobby records that copy as every other player does
 * (its own address in addr, its source as the others see it); any other
 * lobby, or no LAN address (0 or loopback), stays as it is. */
uint32_t xr_lan_lobby_at(uint32_t lobby_ip, uint32_t lan);
#define XR_HAS_LAN_LOBBY_AT 1
/* BO-349: this machine's LAN address when no route probe found one (a LAN
 * with no gateway, a LAN party): from the up interfaces' IPv4 addresses a[n],
 * never 0, loopback (127/8), link-local (169.254/16), multicast or broadcast;
 * a private one first (192.168/16, then 10/8, then 172.16/12, each in the
 * order given), else the first other. *why: XR_LAN_PRIVATE, XR_LAN_OTHER, or
 * XR_LAN_NONE with 0 returned. */
enum { XR_LAN_NONE = 0, XR_LAN_PRIVATE = 1, XR_LAN_OTHER = 2 };
uint32_t xr_pick_lan(const uint32_t *a, int n, int *why);
#define XR_HAS_PICK_LAN 1
uint32_t xr_self_synthetic(void);
/* an addr reply's body: TKADDR= sets the synthetic address (none: cleared);
 * 1 when it had one */
int  xr_addr_reply(const char *body, int n);
int  xr_member_count(void);
int  xr_learned_count(void);
/* this copy: its title address, its port offset, the test switch */
void xr_self(uint32_t title_ip, uint16_t offset, int force_public);
/* a lobby record: a title address and the public address the server saw */
void xr_lobby(uint32_t title_ip, uint32_t public_ip);
/* a lobby packet's body (KEY=VALUE lines): every LA/A and LADDRn/ADDRn pair */
void xr_lobby_body(const char *body, int n);
/* a peer's port offset (from its XUID) */
void xr_offset(uint32_t title_ip, uint16_t offset);
/* a member record of our game (+mgm, the gcre/gjoi reply): its LADDRn are
 * the game's players (xr_source lets them in through our own router) */
void xr_members_body(const char *body, int n);
int  xr_is_member(uint32_t title_ip);
/* the current secret's first 2 bytes as 4 hex digits, or "none" (for logs) */
void xr_secret_prefix(char out[5]);
/* this copy's public address as the lobby saw it (0 = not known yet) */
uint32_t xr_self_public(void);
/* the game's secret (TKSECRET= in the lobby's member-only records): hellos
 * carry a SipHash tag under it, and one without the right tag is refused */
int      xr_has_secret(void);
/* how many different secrets the lobby has given (a new game: one more) */
int      xr_secret_seq(void);
uint64_t xr_siphash(const uint8_t key[16], const uint8_t *m, int n);
int      xr_is_private(uint32_t ip);
/* at most 10 log lines in any 10 s (unknown senders, dropped datagrams) */
int      xr_log_ok(uint64_t now_ms);
/* UPnP's internal client: local_ip when on the router's /24, else igd_lan_ip
 * (miniupnpc's lanaddr: this computer's address on the router's network) */
uint32_t xr_upnp_client(uint32_t local_ip, uint32_t igd_lan_ip);

/* Where a datagram the title sends to title_ip:title_port goes. Returns 1
 * when the peer is known (out and why set), 0 for an unknown address (the
 * caller keeps the old behaviour), 2 when it must not be sent (a public
 * address only the player's own XUID claims). *changed is 1 when the choice
 * differs from the last one for this peer (log it). */
int xr_route(uint32_t title_ip, uint16_t title_port, xr_ep *out, const char **why, int *changed);
/* BO-349: sending to the player's LAN address failed (EHOSTUNREACH, EPERM:
 * macOS without Local Network access refuses every LAN address but the
 * router's). From then on its public address, through our router's NAT
 * loopback, like a copy that forces the public path; kept for the lobby
 * session (the next game is often the same player). to_ip: where the send
 * went. 1 = newly given up (log it), 0 = not that player's LAN path or
 * already given up. Nothing changes while sends work. */
int xr_lan_denied(uint32_t title_ip, uint32_t to_ip);
#define XR_HAS_LAN_DENIED 1
/* Where hellos go: the route, and on one public address also the path
 * through the router (two homes behind one address); 0, 1 or 2 of them. */
int xr_candidates(uint32_t title_ip, uint16_t title_port, xr_ep out[2]);
/* whether src is a known peer's (learned path, local or public address) */
int xr_known_source(xr_ep src);
int xr_peer_count(void);

/* The title's view of a datagram from src: 1 with the peer's title address
 * and port, 0 when src is no known peer's. Once a member record has been
 * seen, only the current game's members count; a peer's local address only
 * when it is on our network (xnet_route.c local_ok). */
int xr_source(xr_ep src, uint32_t *title_ip, uint16_t *title_port);
/* The same for a datagram that reached our socket with title port ltport
 * (0 = not known). BO-345: one router source can carry two players' flows to
 * two of our sockets, and several copies can share one public address; a
 * datagram that cannot be tied to one player gives 0 (the title drops its
 * link on a datagram from another player's address). */
#define XR_HAS_SOURCE_ON 1
int xr_source_on(xr_ep src, uint16_t ltport, uint32_t *title_ip, uint16_t *title_port);

/* hellos */
int  xr_hello_make(uint8_t *buf, uint16_t title_port);          /* XR_HELLO_LEN bytes */
int  xr_is_hello(const uint8_t *buf, int n);
/* a hello arrived from src (ms clock): what came of it */
enum { XR_HELLO_OLD = 0, XR_HELLO_NEW = 1, XR_HELLO_BAD = -1, XR_HELLO_UNKNOWN = -2,
       XR_HELLO_BADTAG = -3, XR_HELLO_WRONGSRC = -4 };
int  xr_hello_seen(xr_ep src, const uint8_t *buf, int n, uint32_t *title_ip, uint64_t now_ms);
/* the same, the hello having reached our socket with title port ltport */
int  xr_hello_seen_on(xr_ep src, uint16_t ltport, const uint8_t *buf, int n, uint32_t *title_ip, uint64_t now_ms);
/* whether to send a hello before a datagram to this peer's title port now
 * (ms clock): every 500 ms until that port's own hello came, 15 s after */
int  xr_hello_due(uint32_t title_ip, uint16_t title_port, uint64_t now_ms);

/* the current game's members, by title address, in table order: the send
 * side of the reactions channel walks them (at most max, the count) */
int  xr_member_list(uint32_t *ids, int max);
/* whether a title address is this copy's own (a member record lists us too) */
int  xr_is_self(uint32_t id);

/* ── the reactions side channel (BO-352) ───────────────────────────
 * A 32-byte "TKRX" datagram on the title's game socket, signed with the
 * game's secret like the hellos and dropped before the title (xnet_hle.c
 * recvfrom). It carries one fixed phrase (a reaction, ids 0..4), a
 * countdown (the host, seconds left) or a player's word that it has left the
 * race's group (the results' Quit); the receiver shows the phrase in its
 * own language, because only the id travels. Only members of the current
 * game may send, so there is no free text to moderate. The packet is sent
 * twice, 60 ms apart (the sender does that); the receiver drops the second
 * by its sequence.
 *
 *  0..3   "TKRX"
 *  4      version (1)
 *  5      kind (1 reaction, 2 countdown, 3 left)
 *  6..9   the sender's title address (the synthetic one when set, as hellos)
 *  10..13 sequence (big-endian, one more per packet from that sender)
 *  14     value (a reaction id 0..4, the countdown's seconds left, or why the
 *         player left: XR_LEFT_RESULTS)
 *  15..23 zero
 *  24..31 SipHash of bytes 0..23 under the game's secret (0 without one) */
#define XR_REACT_LEN 32
enum { XR_REACT_REACTION = 1, XR_REACT_COUNTDOWN = 2, XR_REACT_LEFT = 3 };
#define XR_LEFT_RESULTS 1           /* kind 3: it quit on the race's results */
#define XR_REACT_N 5

/* ── the peers' ping (BO-357) ──────────────────────────────────────
 * A 32-byte "TKPG" datagram on the title's sockets, signed like the hellos
 * and dropped before the title (xnet_hle.c recvfrom). A copy pings each
 * member once a second and the member answers at once; a rate limit caps the
 * answers. A copy that can answer says so in its hello (byte 14 bit 0), which
 * older copies ignore, and pings go only to peers that said so: an older copy
 * would hand them to the title.
 *
 *  0..3   "TKPG"
 *  4      version (1)
 *  5      kind (1 ping, 2 answer)
 *  6..9   the sender's title address (the synthetic one when set)
 *  10..13 the ping's sequence, big-endian (an answer repeats it)
 *  14..23 zero
 *  24..31 SipHash of bytes 0..23 under the game's secret (0 without one) */
#define XR_PING_LEN 32
#define XR_PING_EVERY_MS 1000u
#define XR_PING_LOST_MS  3000u      /* unanswered this long: counted as lost */
enum { XR_PING_PING = 1, XR_PING_ANSWER = 2 };
typedef struct {
    int samples;                     /* answers among the last few; 0: no measurement yet */
    unsigned last_ms, min_ms, med_ms;
    int sent, lost;                  /* the last pings that have an outcome */
} xr_rtt;

/* 1 when buf is a TKPG packet of our version */
int  xr_is_ping(const uint8_t *buf, int n);
/* the next ping due at now_ms: 1, with its target and packet (XR_PING_LEN
 * bytes); 0 when none is due. Call until 0. */
int  xr_ping_next(uint64_t now_ms, uint32_t *title_ip, uint8_t *buf);
/* a TKPG packet arrived from src. XR_PING_ANSWER_IT: reply holds the answer,
 * send it back to src. XR_PING_MEASURED: an answer to our ping, *rtt_ms set. */
enum { XR_PING_NOTHING = 0, XR_PING_ANSWER_IT = 1, XR_PING_MEASURED = 2, XR_PING_BAD = -1,
       XR_PING_UNKNOWN = -2, XR_PING_BADTAG = -3, XR_PING_WRONGSRC = -4, XR_PING_LIMIT = -5 };
int  xr_ping_seen(xr_ep src, const uint8_t *buf, int n, uint32_t *title_ip, uint8_t *reply,
                  unsigned *rtt_ms, uint64_t now_ms);
/* what is known of the path to title_ip: 1 with a measurement, else 0 */
int  xr_peer_rtt(uint32_t title_ip, uint64_t now_ms, xr_rtt *out);

/* make a TKRX packet (kind, value). The sequence moves on each call, so the
 * same packet sent twice stays one reaction at the receiver. Returns
 * XR_REACT_LEN. */
int  xr_react_make(uint8_t *buf, int kind, int value);
/* 1 when buf is a TKRX packet of our version */
int  xr_is_react(const uint8_t *buf, int n);
/* a TKRX packet arrived from src (ms clock). Checked: signed with the game's
 * secret, from a member's address, a sequence newer than the sender's last,
 * within the per-sender rate limit; OK, it is queued for xr_react_get. */
enum { XR_REACT_OK = 0, XR_REACT_BAD = -1, XR_REACT_UNKNOWN = -2, XR_REACT_BADTAG = -3,
       XR_REACT_WRONGSRC = -4, XR_REACT_DUP = -5, XR_REACT_LIMIT = -6 };
int  xr_react_seen(xr_ep src, const uint8_t *buf, int n, uint32_t *title_ip,
                   int *kind, int *value, uint64_t now_ms);
/* whether this copy may send a reaction now (ms clock): the send bucket
 * (at most 1 per 1.5 s, a burst of 3, 10 a minute) */
int  xr_react_send_ok(uint64_t now_ms);
/* a received reaction (or countdown) not yet shown: 1 and its sender, kind
 * and value, else 0 (no queued reaction) */
int  xr_react_get(uint32_t *title_ip, int *kind, int *value);

/* ── the track vote's side channel ─────────────────────────────────
 * A 48-byte "TKVT" datagram on the title's game socket, signed and dropped
 * before the title like TKRX. It carries XR_VOTE_DATA opaque bytes for the
 * game's vote logic, which does its own resends and acknowledgements: state
 * from the host, a choice from a guest. Same rules as TKRX (a member of the
 * current game, from that player's own addresses), a much larger allowance
 * (the vote resends several times a second), and it is sent once.
 *
 *  0..3   "TKVT"
 *  4      version (1)
 *  5      zero
 *  6..9   the sender's title address (the synthetic one when set, as hellos)
 *  10..13 sequence (big-endian, one more per packet from that sender)
 *  14..37 the data
 *  38..39 zero
 *  40..47 SipHash of bytes 0..39 under the game's secret (0 without one) */
#define XR_VOTE_LEN  48
#define XR_VOTE_DATA 24
int  xr_vote_make(uint8_t *buf, const uint8_t data[XR_VOTE_DATA]);
int  xr_is_vote(const uint8_t *buf, int n);
/* a TKVT packet arrived from src (ms clock): XR_REACT_OK when queued for
 * xr_vote_get, else why it was refused (the XR_REACT_ values) */
int  xr_vote_seen(xr_ep src, const uint8_t *buf, int n, uint32_t *title_ip, uint64_t now_ms);
/* a received vote packet not yet taken: 1, its sender and data, else 0 */
int  xr_vote_get(uint32_t *title_ip, uint8_t data[XR_VOTE_DATA]);

#ifdef __cplusplus
}
#endif
#endif
