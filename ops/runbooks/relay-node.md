# Relay node

Role: carry cross-domain and storage relay work. It needs a signer and a
persisted reservation file.

1. Run `ops/TESTNET_FIRST_RUN.md` steps 1 to 3 on the host.
2. Set `bootnodes` or `dns_seeds` in `config/testnet.toml` to the seed nodes
   from `seed-node.md`.
3. Start with `docker compose -f ops/docker-compose.testnet.yml --profile four-node up -d relay`.
4. Smoke test: the startup log reports peer connections and the relay
   reservation file appears under the backup directory.
5. Watch `budlum_relayer_pending_rows` in Grafana. A reservation held with an
   external action in flight is intentional; a monotonically growing count is
   an operator incident, not a retry loop.

Relay reservations are persisted state. `ops/BACKUP_DRILL.md` restores them
together with the database and the node identity.
