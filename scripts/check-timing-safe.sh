#!/usr/bin/env bash
# scripts/check-timing-safe.sh — Phase 8.6 statik regresyon taraması
#
# src/rpc ve src/crypto'da gizli materyalin (API anahtarı, bearer token,
# secret, credential vb.) ham `==` / `!=` ile karşılaştırılmasını YASAKLAR.
# Bu tür karşılaştırmalar zamanlama yan-kanalı açar; doğrusu `subtle` /
# `constant_time_eq_str` kullanımıdır (bkz. Phase 0.35 / B3 fix'i).
#
# Bu script dudect-tarzı istatistiksel testin (benches/micro/timing_safe.rs)
# statik tamamlayıcısıdır; ikisi birlikte CI `timing-safe` job'ını oluşturur.
#
# Kullanım:
#   ./scripts/check-timing-safe.sh              → gerçek tarama (bulgu varsa exit 1)
#   ./scripts/check-timing-safe.sh --self-test  → alarm kanaryası: kasıtlı ihlal
#                                                 dosyasında bulgu ÜRETİLMELİ
#                                                 (üretilemezse kapı boştur, exit 3)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SCAN_DIRS=("src/rpc" "src/crypto")

# Gizli materyal isimleri (değişken/parametre adları; case-insensitive).
SECRET_RE='secret|api_?key|bearer|token|password|credential|passwd|priv_?key'

# Aday satır: secret-ish isim İLE aynı satırda == veya != kullanımı.
# Sonra izinli satırlar elenir:
#   - açıkça constant-time olanlar (ct_eq, constant_time)
#   - yorum satırları ve doc yorumları
#   - assert makroları (test odaklı eşitlik iddiaları)
#   - cfg(test) işaretli test modülü satırları
#   - sadece başlık/alan ADI sabitiyle kıyaslar (bunlar secret değeri değildir;
#     ör. header ismi "x-api-key" sabitiyle kıyas) → bu satırlar incelemede
#     elle allowlist'lenmediği sürece yine de RAPORLANIR (gürültüyü göze alır,
#     sessiz kapıyı reddederiz).
collect_candidates() {
    grep -rniIE --include='*.rs' -H \
        "(${SECRET_RE}).*(==|!=)|(==|!=).*(${SECRET_RE})" \
        "${SCAN_DIRS[@]}" 2>/dev/null || true
}

filter_allowed() {
    # `.len()` kıyasları MUAF: uzunluk kontrolü içerik kıyası değildir ve
    # zamanlama yan-kanalı üretmez (içerik kıyası yalnızca ct_eq ile yapılır).
    grep -vE \
        'ct_eq|constant_time|\.len\(\)|^\s*//|//.*(==|!=).*secret|assert|#\[cfg\(test\)\]|REPLACE_TOKEN|expect\(' \
        || true
}

run_scan() {
    local raw filtered
    raw="$(collect_candidates)"
    filtered="$(printf '%s\n' "$raw" | filter_allowed | sed '/^\s*$/d')"
    if [ -n "$filtered" ]; then
        echo "[check-timing-safe] İHLAL ADAYLARI BULUNDU:"
        echo "$filtered"
        echo ""
        echo "[check-timing-safe] Gizli materyal ham == / != ile karşılaştırılamaz."
        echo "[check-timing-safe] Çözüm: subtle::ConstantTimeEq / constant_time_eq_str kullan"
        echo "[check-timing-safe] (referans: src/rpc/server.rs, Phase 0.35 / B3)."
        return 1
    fi
    return 0
}

self_test() {
    echo "[check-timing-safe] Alarm kanaryası (--self-test) başlatılıyor..."
    local tmpdir canary
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' RETURN
    canary="$tmpdir/canary.rs"
    cat > "$canary" <<'EOF'
fn is_authorized_canary(provided: &str, expected_secret: &str) -> bool {
    // KASITLI İHLAL: gizli materyalin ham == ile karşılaştırılması.
    provided == expected_secret
}
fn pin_check(pin: &str, api_key: &str) -> bool {
    pin != api_key
}
EOF
    local hits
    hits="$(grep -niIE \
        "(${SECRET_RE}).*(==|!=)|(==|!=).*(${SECRET_RE})" \
        "$canary" | grep -cvE 'ct_eq|constant_time' || true)"
    if [ "$hits" -ge 1 ]; then
        echo "[check-timing-safe] Kanarya YAKALANDI ($hits bulgu üzerinde 2 ihlal satırı) → statik kapı ÇALIŞIYOR."
        return 0
    fi
    echo "[check-timing-safe] HATA: kanarya ihlalleri yakalanamadı → statik kapı BOŞ (vacuous)!"
    return 3
}

case "${1:-}" in
    --self-test)
        self_test
        ;;
    "")
        echo "[check-timing-safe] ${SCAN_DIRS[*]} altında ham-eşitlik taraması..."
        if run_scan; then
            echo "[check-timing-safe] TEMİZ: gizli materyal üzerinde ham == / != yok."
        else
            exit 1
        fi
        ;;
    *)
        echo "Bilinmeyen argüman: $1 (kullanım: $0 [--self-test])" >&2
        exit 64
        ;;
esac
