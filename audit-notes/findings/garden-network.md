# Garden network findings

These findings are based on the source tree and dependency versions named below. A local passing test does not replace the required green CI run.

## Live branch placement check

A fresh fetch still places remote Garden at `3467a0bababb7648c75631173228d460da935485`. That remote `net.rs` contains neither `CodecScope` nor `decode_bounded_bincode`. Local numbered Garden commit 27, `f0fc88e02c268f71443bba9cbdeb0b5b3c097715`, independently applies the connection/substream ownership repair without importing the upper-stack decoder. Final local source `2574882aa35d4f3787e53aa1911af7b20df6b760` passes 17/17 network tests and 121/121 Garden library tests on Debian and on Ubuntu userland, plus 18/18 real-process scenarios on both userlands and the Debian real-NAT test. The changes are not pushed at this snapshot and have no final-SHA CI evidence. B-0042 remains absent from the lower Garden branch, and B-0043 remains open: the read helper still returns `Vec<u8>` while its local permit vectors are dropped.

The canonical bounded decoder is absent from main (`1bd93561`). Respect the main-only dependency rule before importing it into a new Garden change. The per-connection ownership repair can be reviewed independently because it does not need that decoder.

## B-0041: per-connection frame shares are recreated for each substream

- Location: `src/garden/net.rs:259-270` at `garden` commit `c34cc016cf15e512be2861a92be2b8649f4e02ae`.
- Severity: high, availability.
- Faulty lines:

  ```rust
  conn_large_frames: Arc::new(Semaphore::new(
      MAX_CONN_LARGE_FRAME_BYTES_IN_FLIGHT / LARGE_FRAME_UNIT_BYTES,
  )),
  response_frames: Arc::clone(&self.response_frames),
  conn_response_frames: Arc::new(Semaphore::new(
      MAX_CONN_RESPONSE_FRAME_BYTES_IN_FLIGHT / LARGE_FRAME_UNIT_BYTES,
  )),
  ```

- Cause: `libp2p-request-response` 0.30.0 clones its codec at connection creation and again in `handler.rs:132` and `handler.rs:185` for individual substreams. The code assumes only the first clone occurs.
- Effect: parallel substreams from one connection can each receive a separate connection allowance. One peer can consume much more than its intended share of the shared read budget and crowd out other peers.
- Repair: create connection-local semaphores when cloning the swarm prototype; share those semaphores when cloning the connection codec. Keep the swarm semaphores shared.
- Evidence: the upper-branch repair previously existed in `9c41b7eb`. The independently committed lower-branch repair is now numbered Garden commit 27, `f0fc88e02c268f71443bba9cbdeb0b5b3c097715`. It gives `GardenCodec` an explicit swarm/connection scope, mints one connection semaphore pair only on the first clone, and shares that pair among substream clones. The request and response regression checks both sibling-stream exclusion and independence of a second connection. An extracted pre-fix control fails (exit 101), while the repaired control passes (exit 0). Final local source `2574882a` passes all 17 network tests, 121 Garden library tests, 18 real-process scenarios and the real-NAT test on Debian; the network/library tests and 18 scenarios also pass on Ubuntu userland. Raw results and source digests are retained under `/home/user/validation/garden/final-network/` and `/home/user/validation/os/ubuntu-24.04/`. No final-SHA CI result exists yet. B-0043 is a separate remaining lifetime problem.
- Status: code committed locally, push and CI pending. Do not mark fully resolved yet.

## B-0042: peer-controlled bincode collection counts bypass payload-derived limits

- Location: `src/garden/net.rs:1006`, the admitted request decode around line 1027, and response decode around line 1066 at `garden` commit `c34cc016cf15e512be2861a92be2b8649f4e02ae`.
- Severity: medium, availability.
- Old code: `bincode::deserialize::<GardenRequest>(&request)` and the equivalent response call deserialize peer-supplied collections directly.
- Cause: a length prefix is exposed as a collection size hint before the claimed elements are checked against the actual frame. With the pinned Serde version, ordinary vector preallocation is capped at 1 MiB per allocation; this is not evidence of an unlimited 281 TB allocation.
- Effect: malformed short frames can cause allocation and work disproportionate to their actual length. The exact aggregate impact depends on concurrency and message shape.
- Repair: use the existing `decode_bounded_bincode` for both request paths and the response path. Bound bytes by the relevant frame cap and aggregate collection counts by the received payload length. Preserve the existing fixed-integer encoding and trailing-byte compatibility.
- Evidence: the upper-stack decoder has dedicated nested sequence and map tests, and its staged tree included `forged_length_prefix_garden_frames_are_rejected_without_allocating`. Those tests check rejection, not an allocator trace. The final lower Garden source `2574882a` still uses direct bincode decoding and does not contain the canonical bounded-decoder dependency. Passing its 17 network cases does not close this finding.
- Status: open on Garden. The upper-branch implementation is not a lower-branch repair, and the dependency is still absent from freshly fetched main `1bd93561f78564f6ab325ec0066dd2da7d5e4a76`. Preserve the main-only stop report and obtain final-source CI after the prerequisite is available.

## B-0043: the read budget is released before a completed frame leaves the queue

- Location: `src/garden/net.rs:296-375` on `garden` commit `c34cc016cf15e512be2861a92be2b8649f4e02ae`. `libp2p-request-response` 0.30.0 `src/handler.rs:136-145` sends the returned request to its inbound channel.
- Severity: high, availability. The source-level lifetime violation is established; an end-to-end memory exhaustion measurement remains pending.
- Faulty lines (noncontiguous excerpts):

  ```rust
  let mut conn_charged = Vec::new();
  let mut swarm_charged = Vec::new();
  ```

  ```rust
  Ok(buf)
  ```

  The permit vectors drop at return while the returned `Vec<u8>` still owns the frame bytes.
- Cause: the semaphore represents only bytes still being read, not bytes retained in a completed request, the handler channel, the 1,024-entry event channel, or the 256-entry backlog. The codec accepts up to 16 concurrent streams per connection.
- Effect: a peer can start another large read after a previous completed frame has released its permits even if that frame remains queued. The stated connection and swarm byte ceilings do not bound the full lifetime of buffered frames. A stalled consumer and multiple concurrent requests can therefore use substantially more memory than the advertised read budget.
- Repair plan: return an owned frame containing its byte vector and owned permits; transfer the permits through decoding and the request/response event into the node consumer; release them only after the associated event has been consumed or dropped. Preserve the separate per-connection and swarm budgets and release permits on every error path. Bound or reject decoded allocation amplification separately.
- Historical control: a standalone harness extracted the exact old `read_bounded_budgeted` from staged tree `d12cd194998aec69f0e091e4a7760e3f128e206a`: holding one completed frame did not prevent a sibling read, and the test failed as expected. The same harness passed with an experimental owned-permit implementation. Those were function-level results, not a fixing commit.
- Fresh final-source control: the exact helper from local `2574882a` fails the same retained-frame assertion with exit 101. The independently staged owned-permit helper passes with exit 0. Source/extracted-helper digests and both outputs are retained in `/home/user/validation/garden/frame-lifetime/control-*.log` and `control-results.txt`. The active Garden source is not changed during its separate all-features execution.
- Current module execution: a separate external harness compiles the staged production `net.rs` and the unchanged real Garden types, linking the existing project libraries. It exposes a test seed through a zeroizing wrapper that delegates signing/verification to the real project crypto; no signature check is bypassed. All 31 cases pass in 13.68 seconds: 21 network tests and 10 type tests, zero ignored, exit 0. This includes actual Noise swarms with a deliberately stalled node-event consumer, request and response retention after decode, malformed response cleanup, connection/swarm budget refusal, read error, oversize input, cancellation and the actual idle-chunk timeout. Evidence: `module-after{.log,.exit,-provenance.txt}` and the harness source in the same directory.
- Remaining scope: the prepared patch also transfers the guard through the bootstrap and validator consumers, explicitly keeping it across their awaited handlers. That changed `node.rs` has not yet had a whole-project build or scenario execution. The module harness is not evidence that the full node-consumer change compiles. After the immutable-source run finishes, apply the independently staged patch, project-test the consumer and real-process scenarios, repeat relevant OS execution and obtain final-SHA CI. Wire-byte accounting does not itself bound decoded allocation amplification, allocator capacity or independent downstream state/storage queues.
- Status: open. The patch and regression sources are retained outside the source tree under test; no B-0043 fixing commit, pushed lower-branch repair or green CI run exists yet.
