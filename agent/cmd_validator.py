"""
ai-agent: ShellCommand 検証層

`/playbook:*` が提示する shell コマンドを、リーダーに見せる直前で検証する。
PatchProposal (nginx WAF ルール) 用の `agent/validator.py` の姉妹モジュール。

設計原則 (incident.md §0.6 / settings.production.json _comment_deny より):
    封じ込め系 + 復旧系 (cp /etc/, sysctl -w, mv /etc/, ln -s /etc/ 等) コマンドは
    settings.production.json の deny で物理的に AI 実行禁止。
    playbook では ```text フェンスで表示し、人間がリーダー承認後に手で打つ。
    validator は人間に見せる前の最終チェック (誤射弾き / 自爆 / GW block / 触禁ホスト) を担当。

使い方:
    # ファイルから読む
    python3 -m agent.cmd_validator /tmp/playbook_commands.txt

    # stdin から読む
    cat /tmp/cmds.txt | python3 -m agent.cmd_validator -

終了コード:
    0 = 全 PASS / WARN のみ → リーダー承認後に人間が打つ
    1 = ERROR あり → AI に再生成させる (リーダーに見せない)
    2 = 引数エラー
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass


PROTECTED_HOSTS = {
    "10.1.1.1": "bravo (自機)",
    "10.1.1.2": "victor (自機)",
    "10.1.1.254": "RTX1200 GW",
    "10.1.1.201": "ESXi",
    "10.1.130.1": "CIC DNS (forwarder / 管理対象外)",
    "133.42.49.151": "VPN 入口 (運営機器)",
}

_BLOCK_PATTERN = re.compile(
    r"(-j\s+(DROP|REJECT)|--add-drop|deny[-_ ]from|"
    r"pfctl.*block|nft.*drop|ipfw.*deny)",
    re.IGNORECASE,
)

_RULE_TARGET_IP = re.compile(
    r"(?:-s|--source|-d|--destination)\s+(\d{1,3}(?:\.\d{1,3}){3})"
)

_BRAVO_MANAGE_SUDO = re.compile(r"ssh\s+manage@10\.1\.1\.1\b.*\bsudo\b")

_MUTATION_PATTERN = re.compile(
    r"(\bsystemctl\s+(start|stop|restart|reload|disable|enable)\b|"
    r"\bservice\s+\S+\s+(start|stop|restart)\b|"
    r"\bsed\s+-i\b|"
    r">\s*/etc/|>>\s*/etc/|>\s*/var/|>>\s*/var/|"
    r"\brm\s+-[rfRF]+\b|"
    r"\bkill\s+-9\b|\bpkill\b|\bkillall\b|"
    r"\buserdel\b|\busermod\s+-[LU]\b|"
    r"\bnsupdate\b|\brndc\s+(reload|flush)\b|"
    r"\bdnf\s+(install|remove)\b|\byum\s+(install|remove)\b|"
    r"\bpkg\s+(install|delete)\b)"
)

_IPTABLES_INPUT_DROP = re.compile(
    r"iptables\s+.*-[AI]\s+INPUT\b.*-j\s+(DROP|REJECT)", re.IGNORECASE
)
_IPTABLES_FORWARD = re.compile(
    r"iptables\s+.*-[AI]\s+FORWARD\b", re.IGNORECASE
)
_HAS_SOURCE = re.compile(r"-s\s+\S+|--source\s+\S+")
_HAS_INTERFACE = re.compile(r"-i\s+\S+|--in-interface\s+\S+")

_APPROVAL_HEADER_NEAR = re.compile(r"リーダー承認後|リーダー承認|leader\s+approval", re.IGNORECASE)


@dataclass
class Violation:
    code: str
    severity: str
    message: str


def validate_command(cmd: str, context_lines: list[str] | None = None) -> list[Violation]:
    """
    1 行の shell コマンドを検証する。

    引数:
        cmd: 検証対象の 1 行
        context_lines: 直前の数行 (「リーダー承認後」明記の確認に使う)

    返り値:
        Violation のリスト (空なら ✅ 合格)
    """
    violations: list[Violation] = []
    context_lines = context_lines or []

    if _BLOCK_PATTERN.search(cmd):
        rule_targets = set(_RULE_TARGET_IP.findall(cmd))
        for ip in rule_targets:
            if ip in PROTECTED_HOSTS:
                violations.append(Violation(
                    code="self-block",
                    severity="error",
                    message=f"触禁ホスト {ip} ({PROTECTED_HOSTS[ip]}) を block しようとしています — 自爆 / GW 切断 / 復旧不能リスク",
                ))

    if _IPTABLES_INPUT_DROP.search(cmd) and not _HAS_SOURCE.search(cmd):
        violations.append(Violation(
            code="iptables-no-source",
            severity="error",
            message="iptables INPUT DROP に -s ソース IP 指定なし → 全閉鎖事故",
        ))

    if _IPTABLES_FORWARD.search(cmd) and not _HAS_INTERFACE.search(cmd):
        violations.append(Violation(
            code="iptables-no-interface",
            severity="warn",
            message="iptables FORWARD に -i 指定なし → 全 IF 適用、意図外伝搬の可能性",
        ))

    if _BRAVO_MANAGE_SUDO.search(cmd):
        violations.append(Violation(
            code="bravo-manage-sudo",
            severity="error",
            message="bravo (10.1.1.1) の manage は sudo 不可 — ssh root@10.1.1.1 を使うこと (incident.md §0)",
        ))

    if _MUTATION_PATTERN.search(cmd):
        approval_nearby = any(_APPROVAL_HEADER_NEAR.search(line) for line in context_lines)
        if not approval_nearby:
            violations.append(Violation(
                code="mutation-needs-approval",
                severity="warn",
                message="副作用ありコマンド — 直前に「※リーダー承認後」明記が見当たりません (playbook 規約違反の可能性)",
            ))

    if " 10.1.130.1" in cmd or cmd.endswith("10.1.130.1") or "/10.1.130.1" in cmd or cmd.startswith("10.1.130.1"):
        if any(verb in cmd for verb in ("dig", "host", "nslookup", "ping")):
            pass
        else:
            violations.append(Violation(
                code="cic-dns-touch",
                severity="error",
                message="CIC DNS (10.1.130.1) は管理対象外 — read-only な dig/host/nslookup/ping 以外で触れないこと",
            ))

    return violations


def validate_commands(lines: list[str]) -> list[tuple[str, list[Violation]]]:
    """
    引数:
        lines: 全行 (コメント行 / 空行 / 実行行 が混在)。コメント行は context 扱い。

    返り値:
        実行行ごとに (cmd, violations) のタプル
    """
    results: list[tuple[str, list[Violation]]] = []
    for i, line in enumerate(lines):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        ctx = lines[max(0, i - 5): i]
        results.append((s, validate_command(s, ctx)))
    return results


def format_report(results: list[tuple[str, list[Violation]]]) -> str:
    lines: list[str] = []
    error_count = 0
    warn_count = 0

    for cmd, vios in results:
        if not vios:
            lines.append(f"  ✅  {cmd}")
            continue

        errors = [v for v in vios if v.severity == "error"]
        warns = [v for v in vios if v.severity == "warn"]
        prefix = "  🚨 " if errors else "  ⚠️ "
        lines.append(f"{prefix} {cmd}")
        for v in errors:
            lines.append(f"      ERROR  [{v.code}] {v.message}")
            error_count += 1
        for v in warns:
            lines.append(f"      WARN   [{v.code}] {v.message}")
            warn_count += 1

    lines.append("")
    lines.append(f"━━━ summary: error={error_count}  warn={warn_count}  total={len(results)} ━━━")
    if error_count > 0:
        lines.append("🚨 ERROR あり — リーダーに見せず、AI に再生成させること")
    elif warn_count > 0:
        lines.append("⚠️ WARN あり — リーダー判断、承認後に人間が手で実行")
    else:
        lines.append("✅ 全件 PASS — リーダー承認後に人間が手で実行")
    return "\n".join(lines)


def _read_lines_from(source) -> list[str]:
    return [line.rstrip("\n") for line in source]


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: python3 -m agent.cmd_validator <file> | python3 -m agent.cmd_validator -", file=sys.stderr)
        return 2

    if argv[1] == "-":
        lines = _read_lines_from(sys.stdin)
    else:
        with open(argv[1]) as f:
            lines = _read_lines_from(f)

    results = validate_commands(lines)
    if not results:
        print("(no commands to validate)", file=sys.stderr)
        return 0

    print(format_report(results))
    error_count = sum(1 for _, vios in results for v in vios if v.severity == "error")
    return 1 if error_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
