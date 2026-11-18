# Garden network findings

These findings are based on the source tree and dependency versions named below. A local passing test does not replace the required green CI run.

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
- Evidence: commit `9c41b7eb` includes `CodecScope` and `garden_codec_substream_clones_share_connection_frame_budget` on `budlum-stack`. The same patch is staged for the lower Garden branch. All 16 `garden::net::tests` passed locally on the staged tree. CI on the Garden fix is pending. B-0043 is a separate remaining lifetime problem.
- Status: code present, CI pending. Do not mark fully resolved yet.

## B-0042: peer-controlled bincode collection counts bypass payload-derived limits

- Location: `src/garden/net.rs:1006`, the admitted request decode around line 1027, and response decode around line 1066 at `garden` commit `c34cc016cf15e512be2861a92be2b8649f4e02ae`.
- Severity: medium, availability.
- Old code: `bincode::deserialize::<GardenRequest>(&request)` and the equivalent response call deserialize peer-supplied collections directly.
- Cause: a length prefix is exposed as a collection size hint before the claimed elements are checked against the actual frame. With the pinned Serde version, ordinary vector preallocation is capped at 1 MiB per allocation; this is not evidence of an unlimited 281 TB allocation.
- Effect: malformed short frames can cause allocation and work disproportionate to their actual length. The exact aggregate impact depends on concurrency and message shape.
- Repair: use the existing `decode_bounded_bincode` for both request paths and the response path. Bound bytes by the relevant frame cap and aggregate collection counts by the received payload length. Preserve the existing fixed-integer encoding and trailing-byte compatibility.
- Evidence: the existing decoder has dedicated nested sequence and map tests. The staged Garden tree includes `forged_length_prefix_garden_frames_are_rejected_without_allocating`; the Garden network test group passed locally. The test checks rejection, not an allocator trace. CI is pending.
- Status: code present, CI pending. Do not mark fully resolved yet.

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
- Verification in progress: a standalone harness extracted the exact old `read_bounded_budgeted` from staged tree `d12cd194998aec69f0e091e4a7760e3f128e206a`: holding one completed frame did not prevent a sibling read, and the test failed as expected. The same harness passed with the experimental owned-permit implementation. These are function-level results, not an end-to-end test or a fixing commit. The local repair worktree also has new request/response, cancellation and error tests plus a real queued-event test; their project build and execution are still pending. Test malformed data and an actual stalled consumer as well, then run the complete Garden tests and CI. The wire-byte accounting does not by itself bound decoded allocation amplification or allocator capacity.
- Status: open; an experimental worktree exists, but no fixing commit or green CI run yet.
