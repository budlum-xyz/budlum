# Operator runbooks

Each file describes one testnet role from a clean host to a smoke-tested
service. All of them assume `config/testnet.toml`, the SoftHSM first-run steps
in `ops/TESTNET_FIRST_RUN.md` and `ops/Caddyfile.testnet`.

| Role | Runbook |
| --- | --- |
| Seed node | `seed-node.md` |
| Relay node | `relay-node.md` |
| Upload gateway | `upload-gateway.md` |
| RPC node | `rpc-node.md` |

The four roles are profiles of `ops/docker-compose.testnet.yml`: `single`,
`four-node` and `rehearsal`. A host never runs two roles against the same
data directory.
