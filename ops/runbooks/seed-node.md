# Seed node

Role: hold a stable libp2p identity and publish an address other nodes can
dial. It does not need to be a validator.

1. Run `ops/TESTNET_FIRST_RUN.md` steps 1 to 3 on the host.
2. Generate the identity: `bud node identity --identity-file ./secrets/seed.key --host <public-ip> --port 5001 --seed-domain seeds.<TESTNET_DOMAIN>`.
3. Add the printed multiaddress to `bootnodes` in `config/testnet.toml` on
   every other node, or publish `seeds.<TESTNET_DOMAIN>` A/AAAA records and
   set `dns_seeds`. An empty list fails the `has_peer_source` check.
4. Start with `docker compose -f ops/docker-compose.testnet.yml --profile four-node up -d seed`.
5. Smoke test: `journalctl -u budlum-core -f` shows the listen address, and
   two other nodes report a peer count above zero within one minute.

The identity file is a secret. Back it up with the drill in
`ops/BACKUP_DRILL.md`; losing it changes the peer id and invalidates every
bootnode record that names the old one.
