---
model: claude-haiku-4-5
description: 受電前 / 受電直後 / /incident 投入前のベースライン確認。両機並行でサービス稼働 / listen ポート / 直近変更 / 負荷を取得し、異常を flag する
---

# /preflight — 環境状態ベースライン取得

引数: なし or オプション
- `/preflight`              — 両機並行（victor + bravo）
- `/preflight victor`       — 片方のみ
- `/preflight bravo`        — 片方のみ
- `/preflight --baseline`   — 結果を `/tmp/preflight_baseline.json` に保存（次回 `--diff` 比較用）
- `/preflight --diff`       — 前回 baseline との差分のみ表示
- `/preflight --brief`      — サマリ行のみ（フルレポートは省略）

## 0. 前提

- /incident 投入の **前** に状態スナップショットを取り、受電内容との整合確認 + 異常 flag を出すための skill
- read-only。サービス起動 / 設定変更は一切しない
- victor (Rocky / 本番は Rocky 同等) と bravo (デモ Rocky / 本番 FreeBSD) で OS 差を吸収
- /incident §0〜§0.6 を読み返してから実行 (本番サーバ定数 / 既侵害前提 / 触らない哲学)

**本番環境前提 (必読)**: 本 skill を呼ぶ前に必ず `docs/booth1_production.md` を Read ツールで読む。Booth1 (com1.local) のネットワーク構成 / 認証情報 / OS 差分 / 触禁機器 / DHCP 配布範囲 / CIC DNS 関係 / 既侵害前提などの本番固有情報をすべて踏まえてから判断・コマンド生成する。本番接続前に必ず Read。

```bash
SSH_VICTOR="${SSH_VICTOR:-manage@10.1.1.2}"
SSH_BRAVO="${SSH_BRAVO:-manage@10.1.1.1}"
SHIRAHAMA_DIR="${SHIRAHAMA_DIR:-/Users/ryu/Desktop/shirahama}"
cd "$SHIRAHAMA_DIR"

# INCIDENT_ID 自動検出 (env > .current_id > 最新 dir > _unscoped fallback)
if [ -z "${INCIDENT_ID:-}" ]; then
    if [ -f "data/incidents/.current_id" ]; then
        INCIDENT_ID="$(cat data/incidents/.current_id)"
    fi
    [ -z "$INCIDENT_ID" ] && INCIDENT_ID="$(ls -1t data/incidents/ 2>/dev/null | grep -v '^\.' | head -1)"
fi
export INCIDENT_ID  # ← emit_skill_json.sh helper に渡すため必須
```

## 1. 取得項目（両機並行）

| 観点 | victor (Rocky) | bravo (FreeBSD 想定 / OCI は Rocky) |
|---|---|---|
| サーバ疎通 | `ping -c1 -W2 10.1.1.2` | `ping -c1 -W2 10.1.1.1` |
| サービス起動 | `systemctl is-active httpd dovecot named sendmail sshd mariadb` | `service apache24 onestatus; service named onestatus; service sendmail onestatus` (FreeBSD) / Rocky なら同左 |
| listen ポート | `ss -tlnp` | `sockstat -l4` (FreeBSD) / `ss -tlnp` (Rocky) |
| ファイル構成 | `ls -la /etc/{httpd,dovecot,mail}/` | `ls -la /usr/local/etc/{apache24,dovecot,namedb}/` (FreeBSD) |
| ディスク | `df -h /var/log /var/www` | 同左 |
| 直近変更 | `find /etc /var/www -mtime -1 -type f 2>/dev/null \| head -20` | 同左 |
| 負荷 | `uptime; ss -s` | `uptime; netstat -s \| head` |
| ログイン履歴 | `last -10` | 同左 |
| プロセス棚卸 | `systemctl list-units --type=service --state=running --no-pager` | `service -e` (FreeBSD) |

OS 差は冒頭で `uname -s` で判定して分岐する。デモ (Rocky) では両機とも systemd で読める。

```bash
# OS 自動判定 — Rocky なら Linux 系コマンド、FreeBSD なら FreeBSD 系
detect_os() {
  ssh -o ConnectTimeout=5 -o BatchMode=yes "$1" 'uname -s' 2>/dev/null || echo "UNKNOWN"
}
```

## 2. 実行（両機並行）

```bash
cd "$SHIRAHAMA_DIR"
TARGET="${1:-both}"   # both / victor / bravo
MODE="${2:-full}"     # full / --brief / --baseline / --diff

run_preflight() {
  local label="$1"   # victor or bravo
  local host="$2"    # SSH alias
  local os
  os=$(ssh -o ConnectTimeout=5 -o BatchMode=yes "$host" 'uname -s' 2>/dev/null || echo UNKNOWN)

  echo "─── /preflight §1 $label ($os) ───"

  # 1. ping
  if ping -c1 -W2 -q "$host" >/dev/null 2>&1; then
    echo "[OK ] ping ok"
  else
    echo "[🚨 ] ping FAILED — host unreachable"
    return
  fi

  if [ "$os" = "Linux" ]; then
    ssh -o BatchMode=yes "$host" 'bash -s' << 'REMOTE_LINUX'
echo "--- services ---"
for svc in httpd dovecot named sendmail sshd mariadb php-fpm atd; do
  state=$(systemctl is-active "$svc" 2>/dev/null)
  case "$state" in
    active)   echo "[OK ] $svc active" ;;
    inactive) echo "[🚨 ] $svc INACTIVE — 受電内容と整合確認" ;;
    failed)   echo "[🚨 ] $svc FAILED" ;;
    *)        echo "[--] $svc: $state (未インストール / 未定義)" ;;
  esac
done
echo "--- listen ports ---"
sudo ss -tlnp 2>/dev/null | awk 'NR>1 {split($4,a,":"); p=a[length(a)]; if (p ~ /^[0-9]+$/) print p}' | sort -un | tr '\n' ' '
echo
echo "--- /etc 直近変更 (1h以内) ---"
find /etc -mtime -0.04 -type f 2>/dev/null | head -10
echo "--- /var/www 直近変更 (1h以内) ---"
find /var/www -mtime -0.04 -type f 2>/dev/null 2>&1 | head -10
echo "--- disk ---"
df -h /var/log /var/www 2>/dev/null | tail -n +2
echo "--- load ---"
uptime
echo "--- last 10 ---"
last -10 -F | head -10
echo "--- running services count ---"
systemctl list-units --type=service --state=running --no-pager 2>/dev/null | grep -c "loaded active running"
REMOTE_LINUX
  elif [ "$os" = "FreeBSD" ]; then
    ssh -o BatchMode=yes "$host" 'bash -s' << 'REMOTE_BSD'
echo "--- services ---"
for svc in apache24 dovecot named sendmail sshd mysql-server; do
  if service "$svc" onestatus 2>/dev/null | grep -q "is running"; then
    echo "[OK ] $svc running"
  else
    echo "[🚨 ] $svc NOT running — 受電内容と整合確認"
  fi
done
echo "--- listen ports ---"
sockstat -l4 2>/dev/null | awk 'NR>1 {n=split($6,a,":"); print a[n]}' | sort -un | tr '\n' ' '
echo
echo "--- /etc 直近変更 (1h以内) ---"
find /etc /usr/local/etc -mtime -1h -type f 2>/dev/null | head -10
echo "--- disk ---"
df -h /var/log 2>/dev/null
echo "--- load ---"
uptime
echo "--- last 10 ---"
last -10 | head -10
REMOTE_BSD
  else
    echo "[🚨 ] OS 判定失敗 ($os) — manual triage"
  fi
}

case "$TARGET" in
  victor) run_preflight victor "$SSH_VICTOR" ;;
  bravo)  run_preflight bravo  "$SSH_BRAVO" ;;
  both|"") run_preflight victor "$SSH_VICTOR"; echo; run_preflight bravo  "$SSH_BRAVO" ;;
esac
```

## 3. 異常検知ルール（出力末尾で flag）

| ルール | 判定 |
|---|---|
| 既知サービスが `inactive` | 🚨 落ちてる — 受電内容と整合確認（DDoS / RCE / 攻撃側プロセスキル疑い） |
| load average > CPU コア数 × 3 | 🚨 高負荷 — DDoS 疑い |
| `/var/log` 使用率 > 90% | ⚠️ ログあふれ — rotation 確認 |
| `/etc` 配下に直近 1h 以内の変更 | 🚨 改ざん疑い — 具体ファイル名を出す |
| listen ポートに想定外（8080 / 31337 / 4444 / 6667 等） | ⚠️ 不審サービス — `ss -tlnp` 詳細確認 |
| `last` 出力に既侵害 IP (10.1.129.0/24) | 🚨 §0.5 既侵害前提 — /incident で時間窓指定 → /review で 4 列突合し既侵害 vs 急性発症切り分け |

判定ロジックは `run_preflight` 内で実行。サマリは末尾でカウントして出す。

## 4. 出力例

```
─── /preflight §1 victor (Linux) ───
[OK ] ping ok
[OK ] httpd active
[OK ] dovecot active
[OK ] sendmail active
[--] named: <missing> (未インストール / 未定義)
[OK ] sshd active
[OK ] mariadb active
[OK ] php-fpm active
[OK ] atd active
listen: 22 23 25 80 110 143 3306 33060
/etc 直近変更: 0 件 (1h 以内)
disk: /var/log 7% used / /var/www 4% used
load average: 0.12, 0.18, 0.22  (CPU 1 core, threshold 3.0)
last 10: rocky@<mac IP> ok / 10.1.129.10 by obuchi (★既侵害)

─── /preflight §1 bravo (Linux/Rocky) ───
[OK ] ping ok
[OK ] httpd active
[OK ] dovecot active
[OK ] named active
[OK ] sendmail active
[OK ] sshd active
[OK ] mariadb active
[OK ] atd active
listen: 22 25 53 80 110 143 953 3306
/etc 直近変更: 0 件 (1h 以内)
disk: /var/log 5% used
load average: 0.05, 0.07, 0.09

─── /preflight summary ───
🚨 1 件: victor last に 10.1.129.10 由来ログイン (既侵害 §0.5)
⚠️ 0 件
推奨次手順: /incident <時間窓> victor (受電内容に合わせて起動) → /review で 4 列突合し 10.1.129.10 由来の動向を判定
```

## 5. オプション動作

- `--baseline` : 上記取得結果を JSON にして `/tmp/preflight_baseline.json` に保存
- `--diff`     : 前回 `/tmp/preflight_baseline.json` と比較して `services / listen / load` の差分のみ表示
- `--brief`    : 各機の サマリ 1 行のみ（[🚨/⚠️/OK] カウント） 出力

baseline JSON の最小スキーマ：

```json
{
  "ts": "2026-05-03T08:50:00+09:00",
  "victor": {
    "services": {"httpd": "active", "dovecot": "active", ...},
    "listen": [22, 25, 80, 110, 143, 3306, 33060],
    "load1": 0.12,
    "etc_recent_changes": []
  },
  "bravo":  {"services": {...}, "listen": [...], "load1": 0.05, "etc_recent_changes": []}
}
```

`--diff` 出力例：

```
─── /preflight §1 diff (前回: 2026-05-03T08:50 → 今回: 2026-05-03T09:15) ───
[Δ ] victor.services.httpd: active → inactive  ★受電「サイト落ち」と整合
[Δ ] bravo.listen: +6667 (新規)               ★IRC 系不審ポート
[OK] それ以外の差分なし
```

## 6. settings.json への影響

新規 allow ルール候補（read-only 系のみ）:

- `Bash(systemctl is-active *)`, `Bash(service * onestatus)`, `Bash(sockstat *)`
- `Bash(ss *)`, `Bash(uptime)`, `Bash(df -h *)`
- `Bash(find /etc * -mtime *)`, `Bash(last *)`, `Bash(systemctl list-units *)`, `Bash(service -e)`
- `Bash(ping -c * *)` (既存)

これらは観察系で破壊性なし。settings.json の `allow` に追加。

## 7. 次のアクション

- 異常 0 件 → そのまま `/incident <時間窓> <ホスト>` に進む
- 🚨 1 件以上 → 受電担当に「受電内容と整合する症状を観測」を伝え、`/incident` 起動
- 🚨 が「既侵害 IP 由来ログイン」のみ → 平時運用扱い (§0.5)、ただし /incident → /review で 4 列突合は必ず実施 (preflight ✅ + incident ✅ で既侵害確定)

## 8. JSON 永続化（HTML dashboard 連携）

§2 で取得した結果を `/tmp/preflight_state.json` に常時書き出し、`/incident` の §0.4 が拾えるようにする。`INCIDENT_ID` env が設定されている場合 (= `/incident` 経由で呼ばれた場合) は `data/incidents/<id>/preflight__*.json` にも永続化される (helper script 側の挙動)。

### 8.1 スキーマ

```json
{
  "skill": "preflight",
  "incident_id": "<id or auto-generated>",
  "timestamp": "<ISO 8601 JST (+09:00)>",
  "actor": "ai_auto",
  "inputs": {
    "target": "both | victor | bravo",
    "mode": "full | brief | baseline | diff"
  },
  "outputs": {
    "victor": {
      "ping_ms": 1.2,
      "services": {"httpd": "active", "dovecot": "active", "named": "missing", "sendmail": "active", "sshd": "active", "mariadb": "active"},
      "listen_ports": [22, 23, 25, 80, 110, 143, 3306, 33060],
      "etc_changed_recently": ["/etc/named.conf"],
      "load_avg": 0.12,
      "last_logins": ["rocky@<mac IP>", "10.1.129.10 by obuchi"],
      "anomalies": [
        {"severity": "🚨", "kind": "service_down", "detail": "named INACTIVE"},
        {"severity": "⚠️", "kind": "recent_etc_change", "detail": "/etc/named.conf modified 30 min ago"}
      ]
    },
    "bravo": { "...同形式..." }
  },
  "verdict": {
    "status": "🚨 | ⚠️ | ✅",
    "summary": "anomalies 集計の 1 行 (例: 🚨 1 / ⚠️ 0 / 既侵害ログイン 1 件)"
  },
  "next_skills": ["/incident <window> <host>", "/review"]
}
```

### 8.2 書き出し（§2 末尾で実行）

§2 の `run_preflight` を全 host 分流し終えたあと、Claude が結果を JSON 化して helper に渡す:

```bash
# 1. /tmp/preflight_state.json (incident_id 不問・常時最新)
#    /incident.md §0.4 が読む。最新 1 件のみ。
# 2. helper 経由で data/incidents/<id>/preflight__*.json も生成
#    (INCIDENT_ID env 未設定時は <auto-generated>_unscoped 配下に出る)

cat <<JSON_EOF | tee /tmp/preflight_state.json | scripts/emit_skill_json.sh preflight
{
  "inputs": {
    "target": "${TARGET:-both}",
    "mode": "${MODE:-full}"
  },
  "outputs": {
    "victor": {
      "ping_ms": <数値 or null>,
      "services": { ...§2 で集めた systemctl is-active 結果... },
      "listen_ports": [ ...§2 ss -tlnp の数値配列... ],
      "etc_changed_recently": [ ...§2 find /etc -mtime -0.04 の配列... ],
      "load_avg": <uptime の 1 分平均>,
      "last_logins": [ ...§2 last -10 の配列... ],
      "anomalies": [
        ...§3 異常検知ルールに該当するもの...
      ]
    },
    "bravo": { ...同形式... }
  },
  "verdict": {
    "status": "🚨 | ⚠️ | ✅",
    "summary": "<anomalies 集計の 1 行>"
  },
  "next_skills": [ ...§7 次のアクションで決めた推奨手順... ]
}
JSON_EOF
```

- `tee /tmp/preflight_state.json` で `/incident §0.4` が読む最新状態を更新
- `scripts/emit_skill_json.sh preflight` でメタデータ (skill / timestamp / actor) を補完しつつ `data/incidents/<id>/preflight__*.json` に永続化
- `INCIDENT_ID` が export されてない (= `/incident` 前単独実行) ときは helper 側で fallback id (`${TODAY_JST}T${HMS}_unscoped`) を生成。`/tmp/preflight_state.json` だけが最新で残るので運用上は問題なし

### 8.3 dashboard 表示

`docs/incident_dashboard.html` が `data/incidents/<id>/preflight__*.json` を fetch し、`outputs.victor.anomalies[]` と `outputs.bravo.anomalies[]` をバッジ集計して表示する (`skill == "preflight"` で specialized renderer に振り分け)。

## 9. 参照

- /incident §0〜§0.6 — 本番定数 / 既侵害前提 / 触らない哲学
- /incident §0.4 — `/tmp/preflight_state.json` を読み込んで §4 Claude 推論にブースト
- archive/checks/check-static-recon.md — SELinux/firewalld/iptables 等の静的設定確認 (歴史参照、現行は AI が ad-hoc 実施 or /review が必要に応じて指示)
- archive/checks/check-known-attacker-ip.md — 10.1.129.0/24 由来ログインの確認手順 (歴史参照、現行は /incident → /review で 4 列突合)
- docs/22_デモE2E実機検証_20260503.md — preflight の前提となる E2E 試験 runbook
- scripts/emit_skill_json.sh — JSON 永続化 helper

---

## §10. 次に打つコマンド (案内)

```text
─── 次のステップ ───
  /incident <時間窓> [host...]   ← 引数なしの場合は両機。例:
                                    /incident 13:00-13:30 victor
                                    /incident 13:00-13:30 victor bravo
  ↓ その後 /review → 採択 → 対応 → /report → /call_close → /ticket
```
