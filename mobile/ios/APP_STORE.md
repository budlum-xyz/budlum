# App Store and TestFlight (WP-38)

Directive section 7.10, risk R-22.

## Distribution

1. TestFlight, external group. The opening build carries the note below.
2. App Store submission follows the external group, once the field-test
   measurements of `docs/MOBILE_DEVICE_MATRIX.md` include at least one iPhone.

Device tests and the on-device procedure are in `devicetests/README.md`.

## The review risk, and what the app does about it

R-22 records the risk that a reviewer reads "validator" as "miner" and rejects
the app for background computation. The risk is real and the answer is not to
argue with the guideline: it is to make the app's behaviour match what the
screen says.

The registration screen states, in plain text and not behind a link:

> This app does not mine. It performs no proof-of-work, no repeated hashing and
> no computation for its own sake. It stores data it was given and answers
> questions about that data. Nothing runs on battery in the background.

That sentence is true of the code:

* no proof-of-work, no hashing loop, no benchmark, no puzzle solver;
* the background task requests external power, so it cannot run on battery;
* the background task does no computation beyond answering an audit and signing
  one presence message;
* no `BGTaskScheduler` request is submitted without both requirements set.

## Declarations and capabilities

| Item | Value |
|---|---|
| Background modes | `processing` (`BGTaskSchedulerPermittedIdentifiers`: `dev.budlum.validator.duty`) |
| Category | Utilities |
| Encryption export | uses only the platform's own CryptoKit; no proprietary encryption |
| Data collection | none. No analytics SDK, no crash reporter, no identifier for vendors |
| Third-party SDKs | none |
| Accounts | not required to run the app; a wallet exists on the device |

## Review notes to paste into App Store Connect

The note text, so the same words reach the reviewer and the user:

> Budlum is a distributed storage network. This app turns the iPhone into a
> storage validator: it holds encrypted pieces of content and answers the
> network's periodic questions about what it holds.
>
> It does not mine and it does not perform proof-of-work. It runs no
> computation other than answering an audit and signing one presence message.
>
> While the app is open it serves data to the network over Wi-Fi. While the app
> is closed, iOS runs a single `BGProcessingTask` that answers pending audits;
> that task requires external power and network connectivity, so it never runs
> on battery. The user can turn every network path off in Settings, and turning
> off symbol serving halves the reward rather than blocking the app.
>
> The user chooses how much storage to offer, between 1 GiB and 8 GiB, and can
> leave at any time. Leaving releases the data the device holds and starts
> unbonding the stake. No data leaves the device except the pieces the device
> agreed to serve.

## Turkish strings

The app ships English strings only in this delivery. `README.tr.md` is the
Turkish surface of the repository; in-app localisation follows the device
matrix results, so a translation is measured before it is written rather than
the other way round.
