#!/usr/bin/env python3
"""arena_claude.py — Claude Code'u Arena API'nin Arena Router'ı üzerinden çalıştırır.

Model seçimi yok: Claude Code'un bütün model alanları router moduna (auto / fast)
bağlanır; hangi modelin cevap vereceğine Arena karar verir.
Sadece standart kütüphane kullanır (Python 3.8+).

Anahtar: ARENA_API_KEY ortam değişkeni (yoksa terminalde gizli sorulur).

Komutlar:
  check      anahtarı ve router'ı dener, hangi modelin cevap verdiğini gösterir
  run        Claude Code'u router ile başlatır (ek argümanlar claude'a geçer)
             örnek: python arena_claude.py run --resume
  install    ayarları ~/.claude/settings.json'a yazar; düz `claude` da router'ı kullanır
  uninstall  install'ın yazdıklarını siler

İsteğe bağlı ortam değişkenleri:
  ARENA_GATEWAY_URL  varsayılan https://api.preview.arena.ai (sonunda /v1 olmadan)
  ARENA_MODE         ana router modu, varsayılan auto
  ARENA_FAST_MODE    hafif / arka plan işleri için mod, varsayılan fast
"""
import getpass
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

GATEWAY = os.environ.get("ARENA_GATEWAY_URL", "https://api.preview.arena.ai").rstrip("/")
if GATEWAY.endswith("/v1"):  # Claude Code /v1/messages yolunu kendisi ekler
    GATEWAY = GATEWAY[:-3]
MODE = os.environ.get("ARENA_MODE", "auto")
FAST_MODE = os.environ.get("ARENA_FAST_MODE", "fast")
SETTINGS = Path.home() / ".claude" / "settings.json"


def claude_env(key):
    """Claude Code ortamı: her model alanı bir router moduna bağlı, model adı yok."""
    return {
        "ANTHROPIC_BASE_URL": GATEWAY,
        "ANTHROPIC_AUTH_TOKEN": key,
        "ANTHROPIC_API_KEY": "",  # boş kalmalı; yoksa Claude Code doğrudan Anthropic'e gider
        "ANTHROPIC_MODEL": MODE,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": MODE,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": MODE,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": FAST_MODE,
        "ANTHROPIC_SMALL_FAST_MODEL": FAST_MODE,
        "CLAUDE_CODE_SUBAGENT_MODEL": MODE,
    }


def get_key():
    key = os.environ.get("ARENA_API_KEY", "").strip()
    if not key and sys.stdin.isatty():
        key = getpass.getpass("Arena API anahtarı (yazarken görünmez): ").strip()
    if not key:
        sys.exit(
            "ARENA_API_KEY tanımlı değil.\n"
            "  bash/zsh:   export ARENA_API_KEY=...\n"
            "  PowerShell: $env:ARENA_API_KEY='...'"
        )
    return key


def check(key):
    """Router'a küçük bir istek atar ve kimin cevap verdiğini yazar. Başarılıysa True döner."""
    body = json.dumps({
        "model": MODE,
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "Say hello in exactly five words"}],
    }).encode()
    req = urllib.request.Request(
        GATEWAY + "/v1/messages",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
            "x-api-key": key,
            "User-Agent": "arena-claude/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            headers = resp.headers
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        if e.code == 401:
            hint = "Anahtar reddedildi. Arena panelindeki Keys sayfasında anahtarın aktif mi bak."
        elif e.code == 403:
            hint = "Erişim yok. Anahtarın bu uç noktaya yetkili olduğundan emin ol."
        elif e.code == 404:
            hint = "Adres bulunamadı. ARENA_GATEWAY_URL kök adres olmalı (sonunda /v1 olmadan)."
        elif e.code == 429:
            hint = "Hız sınırı. Biraz bekleyip tekrar dene."
        elif e.code >= 500:
            hint = "Arena tarafında geçici bir hata olabilir; biraz sonra tekrar dene."
        else:
            hint = ""
        print(f"HATA {e.code}: {detail}\n{hint}".rstrip(), file=sys.stderr)
        return False
    except OSError as e:  # URLError, zaman aşımı, bağlantı reddi
        print(f"Bağlanılamadı: {getattr(e, 'reason', e)}", file=sys.stderr)
        return False

    try:
        data = json.loads(raw)
        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict)).strip()
        body_model = data.get("model")
    except (ValueError, AttributeError):
        print(f"Beklenmeyen cevap: {raw[:200]}", file=sys.stderr)
        return False

    resolved = headers.get("X-Arena-Resolved-Model") or body_model or "?"
    print(f"OK  mod: {headers.get('X-Arena-Routing-Mode') or MODE}")
    print(f"    cevap veren model: {resolved}")
    print(f"    katman: {headers.get('X-Arena-Routing-Tier') or '?'}")
    print(f"    cevap: {text or '(boş)'}")
    if resolved != "?" and "claude" not in resolved.lower():
        print("    not: bu istekte router Claude olmayan bir model seçti (router kararı).")
    return True


def cmd_run(args):
    skip_check = bool(args) and args[0] == "--no-check"
    claude_args = args[1:] if skip_check else args
    key = get_key()
    if not skip_check and not check(key):
        sys.exit("Router testi başarısız, Claude Code başlatılmadı (atlamak için: run --no-check).")
    exe = shutil.which("claude")
    if not exe:
        sys.exit("`claude` komutu PATH'te yok; Claude Code kurulu mu?")
    env = {**os.environ, **claude_env(key)}
    if os.name == "nt":
        return subprocess.call([exe, *claude_args], env=env)
    os.execvpe(exe, [exe, *claude_args], env)


def load_settings():
    if not SETTINGS.exists():
        return {}
    try:
        data = json.loads(SETTINGS.read_text(encoding="utf-8") or "{}")
    except ValueError:
        sys.exit(f"{SETTINGS} geçerli JSON değil; önce onu düzelt.")
    if not isinstance(data, dict) or not isinstance(data.get("env", {}), dict):
        sys.exit(f"{SETTINGS} beklenen biçimde değil (kök ve env nesne olmalı).")
    return data


def save_settings(data):
    SETTINGS.parent.mkdir(parents=True, exist_ok=True)
    if SETTINGS.exists():
        backup = SETTINGS.with_name(SETTINGS.name + ".bak")
        if not backup.exists():  # ilk (orijinal) hâli bir kez saklanır
            shutil.copy2(SETTINGS, backup)
    tmp = SETTINGS.with_name(SETTINGS.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)  # anahtar içeriyor: sadece sen oku
    except OSError:
        pass
    os.replace(tmp, SETTINGS)


def cmd_install():
    key = get_key()
    if not check(key):
        sys.exit("Router testi başarısız, ayar yazılmadı.")
    data = load_settings()
    data.setdefault("env", {}).update(claude_env(key))
    save_settings(data)
    print(f"Yazıldı: {SETTINGS}")
    print("Anahtar bu dosyada düz metin olarak durur; dosyayı paylaşma, git'e koyma.")
    print("Açık Claude Code oturumlarını kapatıp yeniden aç; düz `claude` artık router'ı kullanır.")
    return 0


def cmd_uninstall():
    if not SETTINGS.exists():
        print("Ayar dosyası yok, yapılacak bir şey kalmadı.")
        return 0
    data = load_settings()
    env = data.get("env", {})
    removed = [name for name in claude_env("") if name in env]
    for name in removed:
        del env[name]
    if "env" in data and not env:
        del data["env"]
    save_settings(data)
    print("Silindi: " + (", ".join(removed) or "(zaten yoktu)"))
    return 0


def main(argv):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    cmd, rest = (argv[0], argv[1:]) if argv else ("help", [])
    try:
        if cmd == "check":
            return 0 if check(get_key()) else 1
        if cmd == "run":
            return cmd_run(rest)
        if cmd == "install":
            return cmd_install()
        if cmd == "uninstall":
            return cmd_uninstall()
    except KeyboardInterrupt:
        return 130
    print(__doc__)
    return 0 if cmd in ("help", "-h", "--help") else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
