# Testnet first run

This guide closes DOC-GAP-01: `config/testnet.toml` names the SoftHSM signer,
but a fresh host had neither a SoftHSM2 configuration nor a token. The node
refuses to start with `softhsm` until both exist.

The commands below are deliberately explicit. Run them on the testnet host as
an operator with `sudo`. No secret value is stored in this repository.

## 1. Install and create the token directory

    sudo apt-get install -y softhsm2
    sudo install -d -o budlum -g budlum -m 0700 /var/lib/budlum/softhsm/tokens
    sudo install -m 0644 ops/softhsm2.conf /etc/budlum/softhsm2.conf
    sudo install -d -o root -g budlum -m 0750 /etc/budlum

`ops/softhsm2.conf` sets `directories.tokendir`. SoftHSM2 reads its location
from `SOFTHSM2_CONF`; the systemd unit in `ops/budlum-core.service` exports
that variable, so the service and these commands see the same token store.

## 2. Initialise the token

    export SOFTHSM2_CONF=/etc/budlum/softhsm2.conf
    sudo -u budlum softhsm2-util --init-token --slot 0 \
      --label budlum-testnet --so-pin "$(openssl rand -hex 16)" \
      --pin "$(openssl rand -hex 16)"

Record the user PIN in `/etc/budlum/hsm.env` as `BUDLUM_HSM_PIN`, then:

    sudo chown root:budlum /etc/budlum/hsm.env
    sudo chmod 0640 /etc/budlum/hsm.env

`ops/hsm.env.example` shows the shape. The security officer PIN belongs in
the operator's offline record, not on the host.

## 3. Wire the config

`config/testnet.toml` carries `[validator.signer]` with `backend = "softhsm"`
and `[validator.signer.pkcs11]` with `module_path`, `slot_id` and
`token_pin_env`. `src/cli/commands.rs` canonicalises `softhsm` to `pkcs11`,
and `src/main.rs` requires `--pkcs11-module-path` and
`--pkcs11-token-pin-env` on that path. The systemd unit documents the two
flags; pass the same values when starting the node by hand.

## 4. Start the node

    sudo systemctl daemon-reload
    sudo systemctl enable --now budlum-core
    journalctl -u budlum-core -f

The public RPC, operator RPC and metrics listeners stay on loopback
(`config/testnet.toml`); `ops/Caddyfile.testnet` is the only public edge.

## 5. Verify

- `bud_chainId` on `127.0.0.1:18545` returns the testnet chain id 45261.
- The signer self-test in the startup log reports the PKCS#11 module path.
- `GET /health` on the faucet reports the same chain id.
- `ops/BACKUP_DRILL.md` is run before any public launch.

A real validator does not use SoftHSM. Replace the module path, slot and PIN
environment name with the hardware HSM's values and keep the same config
shape.
