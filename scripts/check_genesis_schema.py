#!/usr/bin/env python3
"""
check_genesis_schema.py — Task 8.11 genesis JSON şema kapısı (vacuous-gate kanaryalı)

config/mainnet-genesis.json (ve gelecekteki genesis varyantları) için sıkı alan/tip
kapısı. stdlib-only (CI'da ek paket yok).

Kullanım:
    python3 scripts/check_genesis_schema.py <genesis.json>
    python3 scripts/check_genesis_schema.py --self-test
"""
import copy
import json
import sys

REQUIRED_TOP = [
    "chain_id", "allocations", "validators", "block_reward",
    "base_fee", "gas_schedule", "timestamp", "bud_tokenomics",
]
GAS_KEYS = [
    "base_fee", "gas_per_byte", "gas_per_signature", "transfer_gas",
    "stake_gas", "vote_gas", "contract_call_gas",
]
TOKENOMICS_KEYS = [
    "community", "liquidity", "ecosystem", "team", "burn_reserve",
    "epochs_per_year", "annual_burn_ratio_fixed", "team_cliff_epochs",
    "team_vesting_epochs", "tx_fee_burn_ratio_fixed", "block_reward",
    "validator_annual_yield_ratio_fixed", "slot_duration_secs",
    "epoch_length_slots",
]
POSITIVE_KEYS = {"chain_id", "epochs_per_year", "slot_duration_secs", "epoch_length_slots"}


def _is_int(v):
    # bool'lar int sayılmaz (True/False genesis değeri değildir)
    return isinstance(v, int) and not isinstance(v, bool)


def validate(g):
    errs = []
    if not isinstance(g, dict):
        return ["kök obje JSON object olmalı"]
    for k in REQUIRED_TOP:
        if k not in g:
            errs.append(f"eksik zorunlu alan: {k}")
    if errs:
        return errs  # alanlar yoksa derin kontrol anlamsız
    int_top = ["chain_id", "block_reward", "base_fee", "timestamp"]
    for k in int_top:
        if not _is_int(g[k]):
            errs.append(f"{k}: tam sayı (int) olmalı, bool/str değil")
    if not isinstance(g["allocations"], list):
        errs.append("allocations: liste olmalı")
    if not isinstance(g["validators"], list):
        errs.append("validators: liste olmalı")
    if not isinstance(g["gas_schedule"], dict):
        errs.append("gas_schedule: obje olmalı")
    else:
        for k in GAS_KEYS:
            if k not in g["gas_schedule"]:
                errs.append(f"gas_schedule.{k} eksik")
            elif not _is_int(g["gas_schedule"][k]) or g["gas_schedule"][k] < 0:
                errs.append(f"gas_schedule.{k}: int >= 0 olmalı")
    if not isinstance(g["bud_tokenomics"], dict):
        errs.append("bud_tokenomics: obje olmalı")
    else:
        for k in TOKENOMICS_KEYS:
            if k not in g["bud_tokenomics"]:
                errs.append(f"bud_tokenomics.{k} eksik")
            elif not _is_int(g["bud_tokenomics"][k]) or g["bud_tokenomics"][k] < 0:
                errs.append(f"bud_tokenomics.{k}: int >= 0 olmalı")
    if _is_int(g["chain_id"]) and g["chain_id"] < 1:
        errs.append("chain_id >= 1 olmalı (mainnet=1)")
    return errs


def self_test():
    good = json.load(open("config/mainnet-genesis.json"))
    if validate(good):
        print("BOZUK KAPI: mevcut genesis reddedildi!")
        return 1
    variants = {
        "chain_id=0": lambda g: g.update(chain_id=0),
        "eksik alan": lambda g: g.pop("gas_schedule"),
        "str block_reward": lambda g: g.update(block_reward="50"),
        "bool chain_id": lambda g: g.update(chain_id=True),
        "negatif gas": lambda g: g["gas_schedule"].update(transfer_gas=-5),
    }
    for name, mut in variants.items():
        bad = copy.deepcopy(good)
        mut(bad)
        if not validate(bad):
            print(f"VACUOUS GATE: '{name}' varyantı reddedilmedi!")
            return 1
    print(f"kanarya OK: {len(variants)} bozuk varyantın tamamı reddedildi, mevcut genesis PASS.")
    return 0


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        return self_test()
    if len(sys.argv) != 2:
        print("kullanım: check_genesis_schema.py <genesis.json> | --self-test")
        return 1
    errs = validate(json.load(open(sys.argv[1])))
    if errs:
        for e in errs:
            print(f"FAIL: {e}")
        return 1
    print(f"OK: {sys.argv[1]} şema kapısını geçti.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
