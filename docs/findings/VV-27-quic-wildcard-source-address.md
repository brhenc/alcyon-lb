# VV-27: QUIC on a wildcard bind replies from the wrong source address

| | |
|---|---|
| Found by | V&V, 2026-10-31 (ledger row on `vv/ledger-1101` a1017370), A1 dry run on main 61bb0771 |
| Severity | medium: a difference from HAProxy; no crash, no leak; connections fail |
| Affects | every Alcyon with QUIC since the listener was written; not a regression of tonight's quinn work (2f807eef, before T542, fails the same way) |
| Fix | T552 (`tasks/T552-quic-wildcard-source-address.md`) |

## What goes wrong

With QUIC bound to every address, e.g. `bind quic4@0.0.0.0:443`, Alcyon sends its replies from
whatever source address the kernel picks for the route back to the client, not from the address the
client sent to. On a host with one address the two are the same and nothing shows. On a host with
secondary or floating addresses (a VIP, keepalived, several IPv6 addresses on one interface) they
differ. A client on a connected UDP socket, which is what curl, browsers and most QUIC stacks use,
only accepts datagrams from the address it connected to. It drops our replies, so the handshake never
completes.

Reproduction (V&V): Alcyon with `bind quic4@0.0.0.0:<port>`, then
`curl --http3-only https://127.0.0.2:<port>/` times out (rc=28) on the mux and the relay. The same
config on HAProxy 3.5-dev10 returns 200. The dev10 reg-test `reg-tests/quic/retry_wildcard.vtc` fails
on Alcyon, also with `quic-force-retry` removed.

## Why

The receive side is right: the listener enables `IP_PKTINFO` / `IPV6_RECVPKTINFO`
(`crates/alcyon-mmsg/src/lib.rs` `set_ip_pktinfo` ~319, `set_ipv6_recvpktinfo` ~343) and reads each
datagram's destination address from the cmsg (~95-101). It hands that address to quinn, and quinn puts
it in each outgoing `Transmit.src_ip`.

The send side drops it. `crates/alcyon-rt/src/quic_listener.rs` ~719-735 copies `tx.src_ip` into
`DgramOut.src_addr`, but `alcyon_mmsg::sendmmsg` never reads that field: it always sets
`msg_control = NULL, msg_controllen = 0` (~282-283). With no `IP_PKTINFO` (`ipi_spec_dst`) /
`IPV6_PKTINFO` cmsg, the kernel chooses the source. That breaks AGENTS.md §5, "a field populated and
never read": the source address was computed per datagram and thrown away at the last step.

## What HAProxy does (3.5-dev10, `src/quic_sock.c`)

- `quic_lstnr_may_set_src()` (682-686) sets the source only when the listener is bound to a wildcard
  address and the connection's local address is known.
- `qc_snd_buf()` (772-775) then attaches it with `cmsg_set_saddr()` (568-): `IP_PKTINFO` for IPv4
  (`IP_SENDSRCADDR` on the BSDs), `IPV6_PKTINFO` for IPv6. The datagrams that go out before a
  connection exists, such as Retry and version negotiation (871-873), do the same with the
  datagram's own destination address.
- A listener bound to one address sends no cmsg at all.

## The fix (T552)

Send the `IP_PKTINFO` / `IPV6_PKTINFO` cmsg per message in `sendmmsg` when `src_addr` is set and
the bind is a wildcard, exactly HAProxy's condition. This covers connection traffic and the
connectionless replies (Retry, version negotiation, stateless reset), GSO batches, and IPv4-mapped
addresses on a `quic6@[::]` bind. Tests, red first: a wildcard bind answering a connected client on
127.0.0.2 (mux and relay), and `retry_wildcard.vtc`. A single-address bind must cost nothing
(insreq h3c1, +0.5 % budget); the wildcard case's cmsg cost is reported.

## Notes

- TCP is unaffected: an accepted TCP socket always replies from the address the client reached.
- Until T552 merges: bind QUIC to explicit addresses (`bind quic4@192.0.2.10:443`, one line per
  address). That is unaffected.
