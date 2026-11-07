# Storage

Budlum has exactly one storage system: B.U.D. 3.0.

Status: in construction. The B.U.D. 3.0 modules live under `src/storage/bud3/`
and are exercised by their own tests and the golden vectors under
`tests/vectors/bud3/` while the legacy storage code is removed. Content
registration is refused (`StorageError::Bud3NotReady`) until the `StorageTx`
v3 door is wired into the transaction envelope.

Target model: content is stored once as a BOF-1 object, segmented, and
protected by the RFC 6330 fountain code. Validators hold custody shares, not
whole objects. The same symbols are the payloads of the optical QR frames.
This document makes no performance or availability claim; measured numbers
are written only after the proof network measures them.
