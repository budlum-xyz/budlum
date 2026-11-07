# Testnet SoftHSM preparation

This guide prepares the SoftHSM signer named by `config/testnet.toml`;
but a fresh host had neither a SoftHSM2 configuration nor a token. The node
refuses to start with `softhsm` until both exist.

The commands below are deliberately explicit. Run them on the testnet host as
an operator with `sudo`. No secret value is stored in this repository.

## 1. Install and create the token directory

    sudo apt-get install -y softhsm2
    sudo install -d -o budlum -g budlum -m 0700 /var/lib/budlum/softhsm/tokens
    sudo install -d -o root -g budlum -m 0750 /etc/budlum
    sudo install -m 0644 ops/softhsm2.conf /etc/budlum/softhsm2.conf

`ops/softhsm2.conf` sets `directories.tokendir`. SoftHSM2 reads its location
from `SOFTHSM2_CONF`; the systemd unit in `ops/budlum-core.service` exports
that variable, so the service and these commands see the same token store.

## 2. Initialise the token

    export SOFTHSM2_CONF=/etc/budlum/softhsm2.conf
    SO_PIN="$(openssl rand -hex 16)"
    BUDLUM_HSM_PIN="$(openssl rand -hex 16)"
    sudo -u budlum env SOFTHSM2_CONF=/etc/budlum/softhsm2.conf \
      softhsm2-util --init-token --slot 0 \
      --label budlum-testnet --so-pin "$SO_PIN" --pin "$BUDLUM_HSM_PIN"
    printf 'Record this security-officer PIN offline: %s\n' "$SO_PIN"
    sudo install -o root -g budlum -m 0640 /dev/null /etc/budlum/hsm.env
    printf 'BUDLUM_HSM_PIN=%s\n' "$BUDLUM_HSM_PIN" | sudo tee /etc/budlum/hsm.env >/dev/null
    unset SO_PIN BUDLUM_HSM_PIN

Run this only on a private testnet shell: the SoftHSM utility receives PINs as
arguments. A production validator uses its hardware HSM's enrollment process.

`ops/hsm.env.example` shows the shape. The security officer PIN belongs in
the operator's offline record, not on the host.

## 3. Wire the config

`config/testnet.toml` carries `[validator.signer]` with `backend = "softhsm"`
and `[validator.signer.pkcs11]` with `module_path`, `slot_id` and
`token_pin_env`. The config loader maps these to the same settings as the
corresponding `--pkcs11-*` CLI flags; explicit flags take precedence. Install
the SoftHSM configuration before selecting that signer.

## 4. Complete the node launch separately

The shipped `ops/budlum-core.service` is a generic mainnet example. Do not
start it unchanged for this testnet. A testnet deployment still needs an
operator-reviewed systemd override that clears the example `ExecStart` and
loads its testnet config, plus all of the following:

- the actual testnet genesis at the path named by `genesis_file`;
- validator and P2P identity keys with owner-only permissions;
- a non-empty, operator-supplied peer source (`bootnodes` or `dns_seeds`);
- database, snapshot, backup, banned-peer and vote-history paths writable by
  `budlum`, with the vote-history path included in backup/restore;
- the RPC secret in `/etc/budlum/rpc.env` and Caddy's configured DNS names.

No startup or hardware validation is implied by this preparation guide. After
an operator supplies those pieces and starts the node, check `bud_chainId`,
the signer self-test and faucet health before proceeding to
`ops/BACKUP_AND_RESTORE.md`.

A real validator does not use SoftHSM. Replace the module path, slot and PIN
environment name with the hardware HSM's values and keep the same config
shape.
