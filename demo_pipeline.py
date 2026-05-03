#!/usr/bin/env python3
"""
4層パイプライン エンドツーエンドデモ
架空インシデント: WP brute + dotfile + webshell設置 の3段攻撃
Signal → PatchProposal → Validate → nginx snippet まで全部追う
"""
import json, textwrap
from agent.analyzer import analyze_nginx, analyze_secure, analyze_maillog
from agent.backends.mock_backend import MockBackend
from agent.validator import validate_patches, PatchValidationError
from agent.renderers.nginx_renderer import render_patches

THICK = "━" * 72
THIN  = "─" * 72

def section(title):
    print(f"\n{THICK}\n  {title}\n{THICK}")

def subsection(title):
    print(f"\n{THIN}\n  {title}\n{THIN}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 架空インシデント
# 2026-05-03 14:30 UTC
# 攻撃者 IP: 203.0.113.77
# 手口: ①スキャン → ②dotfile 窃取 → ③WP brute → ④webshell設置
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ATTACKER = "203.0.113.77"

nginx_logs = [
    # --- ①スキャン (nikto UA) ---
    {"path": "/", "method": "GET", "ip": ATTACKER, "status": 200,
     "user_agent": "Nikto/2.1.6", "ts": "2026-05-03T14:30:01Z"},

    # --- ②dotfile 窃取 ---
    {"path": "/.env",        "method": "GET", "ip": ATTACKER, "status": 200, "ts": "2026-05-03T14:30:05Z"},
    {"path": "/.git/config", "method": "GET", "ip": ATTACKER, "status": 200, "ts": "2026-05-03T14:30:06Z"},

    # --- ③WP brute (POST x12 → 閾値10超) ---
    *[{"path": "/wp-login.php", "method": "POST", "ip": ATTACKER,
       "status": 200, "ts": f"2026-05-03T14:31:{i:02d}Z"} for i in range(12)],

    # --- ④webshell 設置後に実行 ---
    {"path": "/uploads/wp-content/upgrade/shell.php", "method": "GET",
     "ip": ATTACKER, "status": 200, "ts": "2026-05-03T14:35:01Z"},
    {"path": "/uploads/wp-content/upgrade/shell.php?cmd=id",
     "method": "GET", "ip": ATTACKER, "status": 200, "ts": "2026-05-03T14:35:02Z"},

    # --- 被害拡大: CMDi (system() 呼び出し) ---
    {"path": "/vuln.php?x=system%28%27cat+/etc/passwd%27%29",
     "method": "GET", "ip": ATTACKER, "status": 200, "ts": "2026-05-03T14:36:00Z"},

    # --- 通常ユーザ (攻撃ではない) ---
    {"path": "/wp-login.php", "method": "GET", "ip": "10.1.11.55",
     "status": 200, "ts": "2026-05-03T14:30:00Z"},  # 自チームIP → whitelist
]

secure_logs = [
    # SSH brute (8回) → 閾値5超
    *[f"May  3 14:38:{i:02d} victor sshd[{2000+i}]: Failed password for root from {ATTACKER} port 22 ssh2"
      for i in range(8)],
    # pkexec (侵入成功後の権限昇格)
    "May  3 14:40:01 victor pkexec[9999]: GCONV_PATH=/tmp/.x; [/bin/bash]",
]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 層 1: 観測層 (analyzer)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
section("層 1: 観測層 (analyzer.py)  logs → list[Signal]")

web_signals  = analyze_nginx(nginx_logs)
sec_signals  = analyze_secure(secure_logs)
all_signals  = web_signals + sec_signals

print(f"  nginx ログ {len(nginx_logs)} 行 → {len(web_signals)} Signal")
print(f"  secure ログ {len(secure_logs)} 行 → {len(sec_signals)} Signal")
print(f"  合計 Signal: {len(all_signals)} 件\n")

for i, s in enumerate(all_signals, 1):
    tag = s.evidence.get("pattern_tag", s.type)
    ip  = s.evidence.get("ip", "")
    cnt = s.evidence.get("count", "")
    cnt_str = f"  count={cnt}" if cnt else ""
    print(f"  [{i:02d}] {s.severity:<8} {s.type:<22} {tag}{cnt_str}")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 層 2: 判断層 (MockBackend)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
section("層 2: 判断層 (MockBackend)  list[Signal] → list[PatchProposal]")

backend = MockBackend()
patches = backend.propose_patches(all_signals)

print(f"  Signal {len(all_signals)} 件 → PatchProposal {len(patches)} 件\n")
for i, p in enumerate(patches, 1):
    print(f"  [{i:02d}] action={p.action:<12} confidence={p.confidence:.2f}  rule_id={p.rule_id}")
    print(f"       target={p.target}  {p.match_type}:{p.match_operator}:{p.match_value!r:.60}")
    print(f"       {p.rationale_ja[:80]}")

subsection("MockBackend whitelist 動作確認")
print(f"  自チームIP (10.1.11.55) からのアクセスは whitelist で除外: filtered_count={backend.filtered_count}")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 層 3: 検証層 (validator)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
section("層 3: 検証層 (validator.py)  PatchProposal 健全性チェック")

try:
    validate_patches(patches)
    print(f"  ✅ 全 {len(patches)} 件 検証通過")
except PatchValidationError as e:
    print(f"  ❌ 検証失敗: {e}")

subsection("わざと不正なパッチを作って検証失敗を見る")
from agent.llm import PatchProposal

bad_patches = [
    PatchProposal(
        rule_id="INVALID ID!!",        # rule_id に記号混入
        target="/",
        match_type="path",
        match_operator="regex",
        match_value=r"(\w+\w+)+",      # ReDoS 疑いパターン
        action="block",
        confidence=1.5,                 # 範囲外 (>1.0)
        rationale_ja="x",               # 10文字未満
    )
]
for bp in bad_patches:
    from agent.validator import validate_patch
    try:
        validate_patch(bp)
        print("  (通過)")
    except PatchValidationError as e:
        print(f"  ❌ 検証失敗 (期待通り): {e}")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 層 4: 提案層 (nginx_renderer)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
section("層 4: 提案層 (nginx_renderer.py)  PatchProposal → nginx snippet")

render_results = render_patches(patches)

rendered   = [r for r in render_results if r.status == "rendered"]
skipped    = [r for r in render_results if r.status == "skipped"]
advisories = [r for r in render_results if r.status == "rendered" and r.patch.action == "advisory"]

print(f"  レンダリング成功: {len(rendered)} 件")
print(f"  スキップ (nginx で表現不能): {len(skipped)} 件")

subsection("nginx snippet (rendered のみ)")
for rr in rendered:
    print(f"\n  --- rule_id: {rr.rule_id} ---")
    for line in rr.nginx_snippet.splitlines():
        print(f"  {line}")

subsection("スキップされたパッチと理由")
for rr in skipped:
    print(f"  rule_id={rr.rule_id}")
    print(f"  スキップ理由: {rr.skip_reason}")
    print()

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 「通過した」攻撃の行方
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
section("「analyzerを通過した攻撃」はどうなるか")
print(textwrap.dedent("""
  analyzer で Signal が出なかった攻撃 (例: Credential Stuffing / SSRF) は:

  ①  list[Signal] に含まれない
  ②  そのため backend.propose_patches() に渡されない
  ③  PatchProposal が生成されない
  ④  validator / renderer / nginx snippet → 何も起きない
  ⑤  ログとして nginx の access.log には残るが WAF ルールは生成されない

  つまり「analyzer が見逃した攻撃 = パイプライン全体が沈黙する」。
  これが「観測層の限界 = パイプライン全体の限界」を意味する。

  対策の選択肢:
    A. analyzer.py にパターンを追加 (根本対策、決定論的)
    B. Claude backend のように LLM が「意味」で判断する
       → SSRF の場合 Claude は URL パラメータの意図を読んで検出可能
    C. 別センサー (IDS/EDR/UEBA) と連携してここに Signal を注入
"""))

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# オペレータ向け説明 (MockBackend.explain_to_operator_ja)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
section("MockBackend オペレータ向け説明")
print(backend.explain_to_operator_ja(all_signals, patches))
