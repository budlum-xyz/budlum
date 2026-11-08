# Aptos REST compatibility

The Aptos compatibility surface has two layers in `src/rpc/compat/aptos.rs`:

- `AptosGateway` is the production HTTP transport. It owns request routing, the dedicated listener contract, local health/information responses, named refusals, and the optional full-node proxy.
- `AptosCompatGateway` retains the state/Move compatibility handlers used by the compatibility tests and embedders. Its 18-route classification table is kept in lockstep with the transport table.

This is not a claim that the Aptos SDK conformance suite is complete.

## Listener and admission behavior

Normal public node startup opens the dedicated `127.0.0.1:18549` listener. It serves Aptos REST only and has no JSON-RPC dispatcher. The bind must be a numeric loopback socket. A non-loopback bind, a shared JSON-RPC/Aptos address, or a bind failure stops startup instead of silently exposing or dropping the gateway.

The dedicated listener reuses RPC IP admission, authentication, CORS, rate, connection-limit, and TLS configuration. The public reverse-proxy address `https://aptos.<TESTNET_DOMAIN>/v1` still needs separate proxy configuration before it is ready.

An embedded or test public `RpcServer` does not open a port implicitly. Without `with_aptos_listener`, its configured HTTP listener can route `/v1` to the same Aptos transport; operator mode never does. Normal node startup sets the dedicated listener, so `/v1` stays off the JSON-RPC port. Unknown `/v1` paths return `404`, and known paths with the wrong method return `405`.

The route table records the listener and effect of every route. `RpcServer::run` checks the table at startup. Tests cover the complete route list, route matching, listener/effect consistency, response shapes, native refusal doors, listener admission, and proxy limits.

## Local transport responses

Without an upstream, the production transport serves two local node reads:

### `GET /v1/-/healthy`

Returns `200` and the plain-text body `aptos-node:ok` when the node is not syncing. While the node is syncing, it returns `503` and `aptos-node:syncing`. This route does not return a JSON-RPC wrapper.

### `GET /v1`

Returns Aptos-shaped node information derived from the current Budlum head:

- `chain_id` is `205`, the Aptos foreign-envelope chain id.
- `epoch`, `block_height`, and `ledger_timestamp` come from the head block. Budlum milliseconds become Aptos microseconds with checked arithmetic.
- `ledger_version` is the Budlum head height in this compatibility layer. It is not evidence that a Move transaction version exists.
- `oldest_ledger_version` and `oldest_block_height` are `0` only when the node can still read genesis. Otherwise the route returns `503`.
- `node_role` is `full_node`. `git_hash` uses optional build-time `BUDLUM_GIT_HASH`, or `unknown` when no build hash was recorded.

The other 16 transport routes return HTTP `503` with `error_code = move_execution_environment_unavailable` and a native Budlum `door`. The refusal identifies the closest native read or transaction entry point; it does not assert that the native result has Aptos/Move meaning. A client must not translate it into an empty account, zero balance, missing transaction, or successful submission. Local refusal paths do not read an untrusted POST body merely to discard it.

The existing `AptosCompatGateway` state handlers are not silently replaced by these transport refusals. They remain available to embedders and tests, including foreign-envelope verification, account/resource compatibility views, and request-size enforcement. The production transport does not yet claim that those helpers constitute committed transaction submission or complete Move execution.

## Optional full-node proxy

Setting `BUDLUM_APTOS_UPSTREAM_URL=https://fullnode.example.com/v1` forwards all 18 known routes, including health and node information, to that explicitly selected Aptos full node. The URL must end in `/v1` and cannot contain credentials, a query, or a fragment. Remote upstreams require HTTPS; plain HTTP is accepted only for a numeric loopback address. An invalid URL stops listener startup. This mode serves the upstream chain's responses, not a fabricated Budlum Move ledger.

The proxy preserves the request method, path, query, `Accept`, `Content-Type`, bounded body, upstream status, and eligible response headers; local CORS policy remains authoritative. It never forwards downstream `Authorization` or `x-api-key` credentials. Redirects are disabled, connection/request timeouts are bounded, and request and response bodies use the validated RPC body limit. An oversized request returns `413`; upstream transport or response-limit failures return `502`. Unknown paths and wrong methods remain local and do not contact the upstream.

## Work not claimed

- Complete production wiring of the state/Move helpers into every Aptos REST route.
- Complete committed Aptos transaction submission, transaction-version history, events, tables, views, and SDK-compatible simulation.
- The public Aptos reverse-proxy endpoint and Aptos CLI/TypeScript SDK nightly conformance runs.

Proxy mode does not replace the Move worker and does not by itself establish Aptos SDK conformance.
