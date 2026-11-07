# Mobile validator

A validator can be a phone. This page records the duties of that class, what
the chain already enforces for it, and the parts of the mobile lane that are
not in the tree.

## The class

`ValidatorClass` in `src/validators/mod.rs` has three members: `Full`, `Mobile`
and `MobileOpportunistic`. Only `Full` holds a consensus seat. The registry
refuses the seat fields for the mobile classes, and the refusal is a test, not a
convention:

- `validator_mobile_refuses_seat_fields`: a mobile record cannot carry a VRF
  key, a PQ vote key or a leader commitment.
- `validator_mobile_refuses_relay_offer`: a phone does not offer a relay.
- `validator_mobile_refuses_gateway_offer`: a phone does not offer a gateway.

## The duties

1. Store pieces of B.U.D. 3.0 objects up to the quota the owner chose.
2. Answer storage audits with a custody proof (`src/storage/bud3/custody.rs`).
3. Serve pieces to readers.
4. Sign presence and accept a duty handoff. A phone that leaves loses nothing:
   the network moves the duties to the next validator.
5. Follow the chain as a light client ([LIGHT_CLIENT.md](LIGHT_CLIENT.md)).

## Self hosting is not a storage promise

`src/storage/mobile_self.rs` carries the rule: a mobile device may self host
data, and it must never be sold as always online storage. A declaration is
checked against the profile that made it, and self hosting is refused when the
paid replicas the owner asked for are not open.

## Status

The chain side of the class exists. The application does not:

| Item | State |
| --- | --- |
| `ValidatorClass` and the registry refusals | In the tree. |
| Custody proof path and the audit answer | In the tree (`src/storage/bud3/custody.rs`). |
| Self host policy | In the tree (`src/storage/mobile_self.rs`). |
| Android application (`mobile/`) | Not in the tree. |
| iOS opportunistic application (`mobile/ios/`) | Not in the tree. |
| Device matrix (`docs/MOBILE_DEVICE_MATRIX.md`) | Not in the tree. |

A missing application is a red launch-gate row, not a documentation gap:
TLG-10 needs at least 20 real phones in the rehearsal and TLG-11 needs the
device matrix. Both are recorded as red in `docs/audit/TLG_REPORT.md`.
