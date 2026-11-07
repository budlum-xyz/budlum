# RPC node

Role: serve the six public gateways in section 8.11.1 over HTTPS through
Caddy. It is the only role with public DNS names.

1. Run `ops/TESTNET_FIRST_RUN.md` steps 1 to 3 on the host.
2. Set `TESTNET_DOMAIN` and `TESTNET_ACME_EMAIL` in Caddy's environment and
   create the six A/AAAA records plus `faucet.` and `explorer.`.
3. `TESTNET_DOMAIN=<domain> caddy run --config ops/Caddyfile.testnet`
4. Start with `docker compose -f ops/docker-compose.testnet.yml --profile single up -d node`.
5. Smoke test on each host: `rpc.`, `evm.`, `solana.`, `aptos.`,
   `cosmos-rpc.` and `cosmos-rest.` answer; `explorer.` and `faucet.` answer;
   `bud_chainId` through the proxy returns 45261.
6. Watch `budlum_rpc_rate_limited_total` and `budlum_faucet_grants_total`.
   The first is the node's per-IP quota; the second is the faucet's own
   exporter on `GET /metrics`.

`requestAirdrop` is testnet-only. The Solana compatibility gateway translates
the base58 public key to the node's 32-byte address, obtains a challenge from
the faucet's `POST /challenge`, solves it and then calls
`POST /requestAirdrop` with the `budlum` proof object. A direct
`requestAirdrop` without that object is refused by design (R-15).
