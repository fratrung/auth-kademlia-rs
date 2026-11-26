# 0007. A node asks its neighbours for its records when it starts

Status: Proposed, 2026-11-25.

## Context

Kademlia fills a node by push. "When a new node joins the system, it must
store any key-value pair to which it is one of the k closest", and "any node
learning of a new node therefore issues STORE RPCs to transfer relevant
key-value pairs to the new node" ([KADEMLIA], section 2.5). The joining
node itself only looks up its own id and refreshes its buckets
([KADEMLIA], section 2.3).

This implementation does the same (`welcome`, `replicate_to`): a node met
for the first time is sent the records it should hold, and so is a known
node that comes back at least 2.5 s (`RETURNED_AFTER`) after a neighbour
first failed to reach it (`note_alive`, `record_success`). A node that
restarts faster than that, or while no neighbour sent it anything, stays
in its neighbours' tables as if it had never left, and nobody sends it
anything until a republication. The testbed measured it: "A replica that
restarts empty without a rotation stays empty until a republication"
(`EXPERIMENTS.md`, Summary).

On 2026-11-25 the republication moved from every hour to once a day
(ADR 0006, points 5 and 10, amended), to cut the traffic and the writes on
the SD cards of cheap devices. Kademlia republishes hourly for file
sharing, where pairs "expire 24 hours after publication", and notes that
"for other applications, such as digital certificates or cryptographic hash
to value mappings, longer expiration times may be appropriate"
([KADEMLIA], section 2.3); records here live 14 days. The gap a restart
leaves grows from an hour to a day.

A data directory (ADR 0006, point 5) keeps the records a node held, but not
what changed while it was down: a rotation the owner sent to the `k`
closest nodes alive, or a record first published then, reaches it only at
a republication. A device that keeps its records in memory only, the
direction of the cheapest proxies, and a node whose disk was lost or wiped
restart empty.

A record proves its own key from the DID (ADR 0006), so a node that asks
for records needs nobody's word on their authenticity. What other nodes
can withhold is completeness, a record they do not mention, and freshness,
a lower position than the one that exists.

## Decision

1. **When.** Every node runs one synchronization each time it starts
   listening, once the lookup of its own id is over: at the end of
   `bootstrap` from a seed that answered, or in the maintenance tick once a
   contact answers, the moment `note_joined` marks today. It runs whether
   its storage is empty or not: an empty node takes every record it should
   hold, a node restarted from its data directory takes the positions and
   the records published while it was down, and a node with nothing to
   take spends the lists only. Without a data directory a node cannot tell
   a first start from a restart, and on the first start of a network the
   lists are empty.
2. **Whom.** It asks `max(alpha, ceil(k / 2), 10)` nodes, or all it knows
   if it knows fewer, chosen among the `max(k, that number)` closest to its
   own id of those it knows, the nodes that answered that lookup and the
   contacts of its routing table, spread across the tree of ids: first the
   closest, then each time the one farthest, by XOR, from the nearest of
   those already chosen, passing over a node at an IP address already
   chosen. With `k` = 20 that is 10 of the 20 closest; with `k` below 10,
   the 10 closest. The replicas of the keys it should hold are close to
   those keys, hence close to it: they are the nodes that hold its records.
   Nodes far from each other are close to different keys. In a simulation
   with random ids, honest nodes and complete tables (`k` = 20), the 10
   closest nodes held no copy of 0.85% of the keys a node should hold with
   127 nodes, and of 0.5% with 1000; 10 nodes spread in this way missed
   0.05% and none, and listed each key about 7.8 times instead of 9. With a
   small `k` the other holders of a key are few and all close to the node,
   and a spread choice reaches nodes that hold none of its keys: with `k` =
   3, the 3 closest held no copy of 3.9% to 6.0% of the keys with 10 to 127
   nodes, 10 spread among the 20 closest of 4.9% to 5.5%, and the 10
   closest of none. With `k` = 16, 10 spread among the 16 closest missed
   0.25%, the 10 closest 0.75% to 0.94%. Made-up ids close to the node
   share one branch, from which a spread choice takes few, and one IP
   address gets one place.
3. **What it asks.** A new request asks a neighbour for the records it holds
   of which the requester is one of the `k` closest nodes it knows: the
   test the welcome replication already makes (`new_node_close`), so a node
   is listed only the keys it should hold by XOR. The answer is a list of
   `(key, position, SHA-256)`, ordered by key, as many entries as fit one
   datagram (about 19 of 72 bytes), and whether more follow; the next
   request starts after the last key received. A page is one datagram,
   never fragmented: a lost page is asked again alone, it takes no place
   among the messages in reassembly, which the fetches use, and the
   responder keeps nothing between two pages. With DID records only a
   neighbour lists about 15 keys for the requester, one page. No record
   travels in a list. Both messages go at the end of `RpcMessage`, so a node
   of an earlier release cannot decode them.
4. **How it merges.** For each key it takes the highest position listed.
   It fetches it only if it holds nothing for that key, holds a lower
   position, or holds a marker at that position or below; a position it
   holds, under the same hash or another, and a lower one are not fetched,
   since the rules of a replica would keep what it holds (`AlreadyStored`,
   `Conflict`, `Stale`). It fetches the record (`FindValue`) from a node
   that listed it, the keys listed by more neighbours first. A key the
   requester should hold is listed by most of the neighbours it asks (about
   7.8 of 10 in the simulation of point 2); a key made up by one neighbour
   is listed by that neighbour alone, so its fetches come last and the
   deadline cuts them, not the requester's keys. The record counts only if
   it hashes to the entry, has the form of a record of the key at that
   position, and its signature verifies, as a fetch of the empty-replica
   check (`shows_higher`). It is written by the rules of a replica, as a
   repair writes (`decide_locally`, then `insert_if_absent` or
   `replace_if`), without the network check of an empty replica: the lists
   stand in for it, about 8 holders of each key telling their position,
   and a higher position the owner published reaches every replica, so all
   of them would have to hide it. A node that does not show its entry is
   passed over for the next node that listed the same, then for the next
   lower position listed. A neighbour that answers twice that it holds no
   record of a key it listed (`FindValueNodes`) is asked for no record
   after that: it lists keys it does not hold, and each would cost a fetch.
   A record other than the one listed does not count against it, since it
   may have taken a higher position after its list. An entry nobody shows
   refuses nothing, and the key comes back with the next republication. The Status List is listed
   at position 0, as `FindHash` answers it, and written by its own rule:
   signed by the issuer, first writer wins.
5. **Bounds.** The requester runs one synchronization per start, asks the
   neighbours of point 2 and no other, takes at most 64 pages from each,
   about 1,200 keys, so that a neighbour listing made-up keys page after
   page fills no more of its memory before the deadline (DID records take
   one or two), drops a page longer than one datagram or whose keys do not
   follow the last one received, fetches at most four records at once
   and at most two from one neighbour (each neighbour has at most 8
   messages in reassembly), none from a neighbour after two it said it
   does not hold, verifies on the blocking pool capped at the
   number of cores, and stops at its storage budget and 30 s after it
   sends its first list request: what it wrote stays, and the rest waits
   for a republication. With neighbours that answer, an empty node takes
   the records of DIDs in about 0.1 s at a round trip of 13.6 ms and 0.6 s
   at 70.4 ms (the testbed's WAN Europe and Trans-Atlantic profiles), and
   in about 1 and 5 s with ten times as many records; a lost request adds
   at most `RPC_TIMEOUT`, 2.5 s. These are estimates from the round trips,
   not measurements, and leave out the verification of the signatures on a
   slow device. The deadline is for a neighbour that lists keys it never
   shows, each of which costs a fetch until `RPC_TIMEOUT`. The node serves
   requests meanwhile, so a long synchronization delays no one. A
   responder builds one page at a time, as the welcome scan runs one node
   at a time, whoever asks: a request that arrives while it builds one gets
   no answer, and the requester goes on with its other neighbours. A page
   is about 1.4 KB for a request of about 50 bytes; a whole record leaves
   only when the requester asks for it by `FindValue`, as today.

## Consequences

A node that restarts empty is refilled within seconds instead of at the
next republication, up to a day, and a node restarted from its data
directory takes at once the rotations and the records published while it
was down. The daily republication stays safe for availability, and a node
with no data directory becomes a full replica again as soon as it has
looked itself up. With DID records only a node holds about `k` records, so
a synchronization is one page from each of ten neighbours with `k` = 20,
about 14 KB, plus the records it fetches: about twenty, 140 KB, for an
empty node, and none for a node that missed nothing. Each record travels
once, whatever the number of neighbours that list it. An empty node's
synchronization costs about what one republication of one record costs,
167 KiB (`EXPERIMENTS.md`, R1), once per start.

A record first published while the node was down went to the `k` closest
nodes alive, one of them in its place. Once the node has taken it, the
record has `k` + 1 copies, as after a welcome today; the republication
goes to the `k` closest, so the extra copy is no longer renewed and
expires with its TTL.

Neighbours that lie can hide a record, or show a lower position than one
that exists, only if every neighbour asked does: the highest position shown
by any of them wins. They cannot make the node write a record the owner did
not sign. That is the limit of the empty-replica check (`DESIGN.md`,
section 13), and an attacker that controls every node close to the node
that starts remains out of scope (`DESIGN.md`, section 2).

The welcome replication, the daily republication and the owner's
republication stay as they are: the synchronization adds a pull to them,
it replaces none.

## Alternatives rejected

**Neighbours push on a restart.** A node could announce a new incarnation,
a number drawn at each start, and its neighbours would treat it as new and
run the welcome replication. One forged announcement would then make every
neighbour scan its storage and send records: the cost falls on the nodes
that answer, not on the one that asks. It also changes the wire format.

**Only after an empty restart.** A node restarted from its data directory
would keep, until a republication, the positions superseded while it was
down and lack the records published then, and serve the old positions to
readers, who must then repair them. When it missed nothing, a
synchronization costs it the lists only.

**The `alpha` closest neighbours.** Three nodes are cheap, but nodes next
to each other in the tree hold much the same keys: in the simulation of
point 2, the 3 closest held no copy of 1.0% of the keys with 127 nodes and
of 2.3% with 1000, which then wait up to a day for a republication.

**All `k` closest neighbours.** In the simulation of point 2 (`k` = 20),
on the same networks and keys, all 20 missed the same keys as 10 spread:
none of 9,529 with 127 nodes, 2 of 2,443 with 1000. Those keys are held by
none of the 20 nodes closest to the node, so asking more of them does not
reach them. All 20 listed each key 15.5 times instead of 7.7: twice the
lists, for no key more.

**Disjoint lookups.** S/Kademlia uses "parallel lookups over multiple
disjoint paths" ([S/KADEMLIA], abstract), so that nodes on one path cannot
decide the result alone. It needs several independent lookups of the
node's own id. An attacker that surrounds the node can only keep records
from it, which the next republication brings, and cannot make it write one
the owner did not sign; an attacker that controls every node close to a
DID is out of scope, and the many disjoint lookups against it are not
implemented (`DESIGN.md`, section 2).

**Republish every hour again.** It refills an empty restart within the
hour, with the traffic and the writes the daily republication removed.

**Persistence only.** Devices without a data directory and lost disks
would still restart empty, and a node with one would still miss what was
published while it was down.

**Merkle trees, as Dynamo's anti-entropy.** Dynamo compares trees of hashes
"to detect the inconsistencies between replicas faster and to minimize the
amount of transferred data" ([DYNAMO], section 4.7). A tree pays off over
large ranges of keys; a node here holds about `k` records, whose flat list
fits in a few datagrams. It is worth revisiting if a node comes to hold
many records.

**A list in one fragmented message.** It saves round trips only when a
neighbour lists more than one page, which DID records alone do not reach;
one lost fragment costs the whole list again, and each list takes a place
among the 8 messages in reassembly per neighbour while the fetches need
them.

**The network check for each record.** The check of an empty replica asks
the nodes closest to the key, about `k` − 1 holders instead of the 8 or so
that list it, so hiding a higher position would take more of them. It
costs one lookup per key, about twenty lookups of `FindHash` with their
answers, which by estimate costs as much as the synchronization itself or
more. What it adds is against neighbours that all hide the same position,
an attacker that surrounds the node, which is out of scope (`DESIGN.md`,
section 2). A repair writes what it finds the same way, without the check
(`install`). A superseded record written by a synchronization is the
limit of the empty-replica check (`DESIGN.md`, section 13): the next
republication replaces it, and a reader whose credential names a higher
key repairs it meanwhile.

**A limit of pages per requesting address.** It would not bound what a
node can be made to send: a `FindValue` of about 50 bytes already brings
back a whole record of about 7 KB, from any address, with no limit, and a
page is about 1.4 KB. Nor would it bound the work of building pages: a
sender over UDP can write another source address in each request, and
each address would get its own allowance. One page at a time bounds that
work whatever the addresses, and the most it costs an honest node is the
wait for a republication, as today.

**Whole records instead of lists.** A neighbour sending its records at once
would send several fragmented messages to one node, past its reassembly
limit of 8 per peer; the empty-replica check asks for hashes for the same
reason (`DESIGN.md`, section 7, "Why hashes, not records").

## Not in this ADR

- A periodic synchronization between running replicas.
- Keeping the node id across restarts. A node returns to its place in the
  key space only with the same id; `scripts/dht_node.rs` draws a new one
  at each start, which makes it a new node for its neighbours and leaves
  the records of its data directory at its old place. The synchronization
  serves either case, since the lists are computed for the id the node has
  now.
- Light clients, devices that read and publish without holding records.
- Record types other than DID records and the Status List.

## Acceptance cases

Use real nodes over loopback, with neighbours whose lists and records the
tests choose.

| Case | Expected result |
|---|---|
| A node restarts empty within a second while its neighbours hold its records | It holds them again without a republication |
| A node restarts from its data directory after a rotation it missed | It holds the higher position without a republication |
| A node restarts from its data directory after a record it should hold was first published | It holds that record |
| A node restarts from its data directory and nothing changed | It fetches no record |
| A neighbour lists the position the node holds, under another hash | Nothing is fetched; the record held stays |
| Twenty nodes answered its lookup | It asks ten: the closest first, then each time the farthest from those chosen |
| `k` = 3: three nodes answered its lookup, its table holds more | It asks the ten closest it knows |
| Several of the nodes that answered share one IP address | At most one of them is asked |
| It knows fewer than `max(alpha, ceil(k / 2), 10)` nodes | It asks all of them |
| A neighbour lists 5, another 6 | 6 is written |
| A neighbour lists 7 and does not show it, another shows 6 | 6 is written; the claim of 7 refuses nothing |
| A neighbour lists and shows a forged record | Nothing is written for that key |
| A neighbour lists hundreds of keys nobody else lists and says it holds none | The keys the others list are written first; after two such answers it is asked for no more records |
| A neighbour lists hundreds of keys nobody else lists and never answers a fetch | The keys the others list are written first; the synchronization ends at its deadline |
| A neighbour shows a record other than the one it listed | It is still asked for the other keys it listed |
| No neighbour answers | Nothing is written; the records come with a republication |
| The storage budget is reached | The synchronization stops; nothing held is evicted |
| A neighbour lists more keys than fit one datagram | The requester gets them all, page after page, each page one datagram |
| A request reaches a responder while it builds a page for another | No answer; the requester goes on with its other neighbours |

## References

Checked on the sources on 2026-11-25. Section numbers of [KADEMLIA] are
those of the LNCS version below. Only the abstract of [S/KADEMLIA] could be
read; it is cited for no more than the abstract says.

- [KADEMLIA] P. Maymounkov, D. Mazières, "Kademlia: A Peer-to-peer
  Information System Based on the XOR Metric", IPTPS 2002, sections 2.3
  and 2.5.
  https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf
- [DYNAMO] G. DeCandia et al., "Dynamo: Amazon's Highly Available Key-value
  Store", SOSP 2007, section 4.7, "Handling permanent failures: Replica
  synchronization".
  https://www.allthingsdistributed.com/files/amazon-dynamo-sosp2007.pdf
- [S/KADEMLIA] I. Baumgart, S. Mies, "S/Kademlia: A practicable approach
  towards secure key-based routing", ICPADS 2007,
  doi:10.1109/ICPADS.2007.4447808, abstract.
  https://publikationen.bibliothek.kit.edu/1000087134
