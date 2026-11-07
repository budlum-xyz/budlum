# Upload gateway

Role: accept B.U.D. 3.0 object uploads over the public API and hand them to
storage. It never holds a validator signer key.

1. Run `ops/TESTNET_FIRST_RUN.md` steps 1 to 3 only if this host also runs a
   node. A standalone gateway needs no HSM token.
2. Put the gateway behind `ops/Caddyfile.testnet`. The `common` snippet caps
   the request body and sets HSTS; the node's own per-IP quota is the rate
   limit.
3. Start with `docker compose -f ops/docker-compose.testnet.yml --profile four-node up -d gateway`.
4. Smoke test: a small object upload returns a content id, and a body above
   the Caddy limit is refused before it reaches the gateway.
5. Watch `budlum_storage_challenge_rows` and
   `budlum_storage_reallocation_rows`; the launch-boundary alerts in
   `ops/monitoring/alerts.yml` fire on unresolved challenges and reallocations.

Do not expose the operator listener (18546) or the metrics listener (19090).
