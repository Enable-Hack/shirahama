"""
ai-agent.analyzer

観測層（Observation Layer）: nginx / WordPress などのログから
構造化された Signal を抽出する。LLM 非依存のルールベース実装。

4層分離における位置づけ:
    1. 観測層（このファイル）     : logs → list[Signal]
    2. 判断層（backends/）       : Signal → PatchProposal
    3. 検証層（validator.py）    : PatchProposal の健全性検証
    4. 提案層（renderers/）      : PatchProposal → WAF 固有構文

教材上の意義:
    - LLM が使えなくてもここは動き続ける（可用性の下支え）
    - 検出パターンは _PATTERNS 定数として公開されており、
      受講者が「パターン追加→検出される」を実体験できる
    - ログ→シグナル変換のルールベース実装を読み、
      Day 2 で「ここを LLM で置き換えたらどうなるか」を議論する素材になる

既存コードからの変更点:
    - 返り値の dict を Signal データクラスに統一
    - SQLi / XSS / path_traversal のパターン検出を追加
    - encoding='utf-8' を明示（Windows での文字化け事故対策）
    - LOG_DIR を関数引数化してテスタビリティ向上
"""
from __future__ import annotations

import json
import pathlib
import re
import urllib.parse
from collections import defaultdict
from typing import Pattern

from .llm import Severity, Signal


DEFAULT_LOG_DIR = pathlib.Path("/logs")
PATH_SCAN_THRESHOLD = 10


# ─── 検出パターン（公開定数。受講者が拡張可能） ───────────
# 各タプル: (コンパイル済み正規表現, 識別タグ)

SQLI_PATTERNS: list[tuple[Pattern[str], str]] = [
    # UNION SELECT: スペース / + (URLエンコード空白) / %20 / コメント挿入 (/**/) を
    # 区切り文字として許容する。WAF バイパスの典型技法をひとつのパターンでカバー。
    # (?i) で大文字小文字混在 (uNiOn SeLeCt 等) も同時に検出される。
    (re.compile(r"(?i)union(?:\s|\+|%20|/\*.*?\*/){1,10}select"), "union-select"),
    (re.compile(r"(?i)drop\s+table"),   "drop-table"),
    (re.compile(r"(?i)\bor\s+\d+\s*=\s*\d+"), "or-tautology"),
]

XSS_PATTERNS: list[tuple[Pattern[str], str]] = [
    (re.compile(r"(?i)<script"),         "script-tag"),
    (re.compile(r"(?i)javascript:"),     "javascript-protocol"),
    (re.compile(r"(?i)onerror\s*="),     "onerror-handler"),
    (re.compile(r"(?i)onload\s*="),      "onload-handler"),
]

PATH_TRAVERSAL_PATTERNS: list[tuple[Pattern[str], str]] = [
    (re.compile(r"\.\./"),                 "dotdot-slash"),
    (re.compile(r"(?i)%2e%2e%2f"),         "dotdot-encoded"),
    (re.compile(r"(?i)%252e%252e"),        "dotdot-double-encoded"),
]


# コマンドインジェクション (RCE 検出 / キャンプ Day 2 教材由来):
# URLエンコードされた system()/exec()/passthru()/popen()/backtick を検出。
# WAF (nginx $request_uri) は %28 を ( にデコードしないため素通りするが、
# この観測層は _iterative_unquote() で反復デコードしてからマッチさせる。
# → 「WAF では見逃すが analyzer なら意味を理解して検知できる」
# 18_ プレイブック #29 (PHP 7.2.24 + disable_functions=空) が刺さった瞬間の RCE を捕捉。
CMDI_PATTERNS: list[tuple[Pattern[str], str]] = [
    # \b で word boundary を入れて shell_exec/proc_open が exec-call として
    # 誤タグされないようにする (shell_exec は別パターンで拾う)
    (re.compile(r"(?i)\bsystem\s*\("),     "system-call"),
    (re.compile(r"(?i)\bshell_exec\s*\("), "shell-exec-call"),
    (re.compile(r"(?i)\bproc_open\s*\("),  "proc-open-call"),
    (re.compile(r"(?i)\bpassthru\s*\("),   "passthru-call"),
    (re.compile(r"(?i)\bpopen\s*\("),      "popen-call"),
    (re.compile(r"(?i)\bexec\s*\("),       "exec-call"),
    (re.compile(r"`[^`]+`"),               "backtick-exec"),
]


def _normalize_entry(entry: dict) -> dict:
    """parse_clf.py 等が出す src_ip/timestamp/ua を analyzer 標準名 ip/ts に揃える。
    既に ip/ts があればそちら優先。元 dict を破壊しないよう新 dict を返す。
    """
    if "ip" in entry and "ts" in entry:
        return entry
    out = dict(entry)
    if "ip" not in out and "src_ip" in out:
        out["ip"] = out["src_ip"]
    if "ts" not in out and "timestamp" in out:
        out["ts"] = out["timestamp"]
    return out


def _iterative_unquote(s: str, max_rounds: int = 3) -> str:
    """
    URL デコードを値が変化しなくなるまで最大 max_rounds 回繰り返す。

    二重エンコード（%2528 → %28 → (）や三重エンコードへの対策。
    無限ループ防止のため上限付き。完全ではない（%u00XX 等は別途）が、
    競技でよく見る Perl/PHP RCE ペイロードには十分。
    """
    for _ in range(max_rounds):
        decoded = urllib.parse.unquote(s)
        if decoded == s:
            break
        s = decoded
    return s


# ─── 拡張パターン (6 カテゴリ汎用化、白浜本番向け) ───────────
# 18_統合脆弱性プレイブック の 60 項目を 6 カテゴリに圧縮し、
# 過去環境固有値（rainloop 1.12.0 / WP 4.9.4 / com1.local 等）に依存せず
# 「攻撃カテゴリそのもの」を捕まえる汎用 pattern として定義する。
# 過学習を避けるため、特定 CVE 名や特定 URL を埋めない。

# Web app exploit: 既存 SQLI/XSS/PATH_TRAVERSAL に追加する 5 種
WEBAPP_DOTFILE_PATTERNS: list[tuple[Pattern[str], str]] = [
    # /cgi-bin/.my.cnf や /.env / /.git/config 等の dotfile 直叩き
    # (18_ #17 .my.cnf.6804 露出を一般化)
    (re.compile(r"/\.(my\.cnf|env|git/|htaccess|htpasswd|ssh/|aws/|npmrc|netrc|DS_Store)"),
     "webapp/dotfile-access"),
]

WEBAPP_UPLOAD_PHP_PATTERNS: list[tuple[Pattern[str], str]] = [
    # uploads / tmp / cache 配下に PHP/CGI 拡張子を書く / 叩く
    # WordPress, rainloop, 一般 PHP アプリ全般の webshell シナリオを汎用化
    (re.compile(r"(?i)/(uploads?|tmp|cache|temp)/[^?\s]*\.(php\d?|phtml|phar|pl|cgi|jsp)"),
     "webapp/upload-php"),
]

WEBAPP_AUTH_PATTERNS: list[tuple[Pattern[str], str]] = [
    # ログイン系エンドポイントへの POST。WordPress (#23), 一般管理画面を汎用化
    # 単発では誤検知になるため、_detect_auth_bruteforce で count 集計と組み合わせる
    (re.compile(r"(?i)/(wp-login\.php|wp-admin/|administrator/|admin/login|login\.php|signin)"),
     "webapp/auth-endpoint"),
    (re.compile(r"(?i)/xmlrpc\.php"),                 "webapp/xmlrpc"),
    (re.compile(r"(?i)/\?author=\d+"),                "webapp/author-scan"),
]

WEBAPP_SCANNER_PATTERNS: list[tuple[Pattern[str], str]] = [
    # 攻撃ツールの User-Agent / 既知スキャナの足跡
    (re.compile(r"(?i)(nikto|wpscan|sqlmap|nmap|masscan|acunetix|nuclei|burp|gobuster|dirbuster)"),
     "webapp/scanner-ua"),
]


# ─── DNS tampering (named.log 行ベース) ─────────────────
# 18_ #36-39 の BIND 系を汎用化。BIND 以外の DNS サーバでも近い表記なので拡張可能。
DNS_PATTERNS: list[tuple[Pattern[str], str]] = [
    # nsupdate 由来の動的更新成功 (18_ #36 が成立した瞬間の痕跡)
    # BIND 9 (Rocky 8) の実出力形式:
    #   "client @0x... IP#PORT: updating zone 'Z/IN': adding an RR at '...'"
    # → 成功 = unauthorized-update
    (re.compile(r"(?i)client\s+(?:@0x\S+\s+)?[\d.]+#\d+:?\s*(?:\([^)]+\):\s*)?updating\s+zone\s+'[^']+':"),
     "dns/unauthorized-update"),
    (re.compile(r"(?i)client\s+(?:@0x\S+\s+)?[\d.]+#\d+:?\s*(?:view\s+\S+:\s*)?update\s+'[^']+'\s*approved"),
     "dns/unauthorized-update"),
    (re.compile(r"(?i)signer\s+\".*\"\s+approved"),
     "dns/unauthorized-update"),
    # 拒否された update (allow-update に弾かれた = 監視対象だが脅威度低め)
    (re.compile(r"(?i)client\s+(?:@0x\S+\s+)?[\d.]+#\d+:?\s*(?:view\s+\S+:\s*)?update\s+'[^']+'\s*denied"),
     "dns/update-denied"),
    # AXFR / IXFR のゾーン転送 (started でも attempt 扱い、started+ended で完了 = 漏洩成立)
    (re.compile(r"(?i)transfer of '[^']+'.*AXFR\s+started"),
     "dns/axfr-attempt"),
    (re.compile(r"(?i)transfer of '[^']+' from\s+[\d.:#]+:\s+(?:failed|connection refused)"),
     "dns/axfr-attempt"),
    (re.compile(r"(?i)zone transfer.*denied"),
     "dns/axfr-attempt"),
    # ANY クエリ (DNS amplification の典型)
    (re.compile(r"(?i)query:\s+\S+\s+IN\s+ANY"),
     "dns/amplification-bait"),
]


# ─── Plain-text auth & Privesc (secure / auth.log 行ベース) ──
# 18_ #1, #10, #51 を一般化
SECURE_PATTERNS: list[tuple[Pattern[str], str]] = [
    # SSH brute force (1 行で確定はせず、_detect_ssh_brute で集計)
    (re.compile(r"(?i)Failed password for (?:invalid user )?(\S+) from"),
     "auth/ssh-failed"),
    (re.compile(r"(?i)Invalid user (\S+) from"),
     "auth/ssh-invalid-user"),
    # Telnet ログイン (平文プロトコル使用 = 異常)
    (re.compile(r"(?i)telnet(?:d|@\d)?\[\d+\]"),
     "protocol/telnet-access"),
    # PwnKit (CVE-2021-4034)
    (re.compile(r"(?i)pkexec.*(?:GCONV_PATH|CHARSET=|gconv)"),
     "privesc/pkexec-attempt"),
    # sudo 不正 (権限ない人 / NOPASSWD 不正利用)
    (re.compile(r"(?i)sudo:.*(?:user NOT in sudoers|authentication failure|3 incorrect password)"),
     "privesc/sudo-unauthorized"),
    # at job 永続化痕跡
    (re.compile(r"(?i)atd\[\d+\]:.*executing"),
     "persist/at-job"),
]


# ─── Mail 異常 (maillog 行ベース) ───────────────────────
# 18_ #31-35 を一般化
MAIL_PATTERNS: list[tuple[Pattern[str], str]] = [
    # SPF 失敗
    (re.compile(r"(?i)Received-SPF:\s*fail"),
     "mail/spf-fail"),
    (re.compile(r"(?i)spf=fail"),
     "mail/spf-fail"),
    # DKIM 失敗
    (re.compile(r"(?i)dkim=fail"),
     "mail/dkim-fail"),
    # From != Return-Path (なりすまし候補)
    (re.compile(r"(?i)reject:.*(?:Sender address|domain not found|relay access denied)"),
     "mail/relay-denied"),
    # Open relay 試行
    (re.compile(r"(?i)NOQUEUE: reject: RCPT from"),
     "mail/relay-attempt"),
    # 認証失敗 (SMTP AUTH brute)
    (re.compile(r"(?i)SASL\s+(?:LOGIN|PLAIN)\s+authentication failed"),
     "mail/sasl-failed"),
    # Dovecot IMAP/POP3 認証失敗 (本番想定 courier-imap / dovecot 共通)
    (re.compile(r"(?i)(imap|pop3)-login:.*auth(?:enticat\w+)? fail"),
     "mail/sasl-failed"),
    (re.compile(r"(?i)dovecot.*(?:Aborted login|disconnected).*\(auth failed"),
     "mail/sasl-failed"),
]


# ─── 集約閾値 (時系列カウント系) ─────────────────────────
SSH_BRUTE_THRESHOLD = 5      # 同一 IP/ユーザーから N 回失敗で brute 判定
WEBAPP_AUTH_THRESHOLD = 10   # 認証エンドポイントへの POST が N 回で brute 判定
MAIL_BURST_THRESHOLD = 20    # 同一送信元から N 通で burst 判定
DNS_AMPLIFICATION_RATIO = 0.3  # ANY クエリ比率がこれを超えたら amp 疑い


# ─── ログ読み込み ──────────────────────────────────────────
def load_logs(
    filename: str,
    log_dir: pathlib.Path | None = None,
) -> list[dict]:
    """
    JSONL 形式のログファイルを読み込む。

    挙動:
        - ファイル不在 → 空リスト（エラーにしない、運用上の現実）
        - JSON パース失敗行 → 黙って飛ばす（壊れた行で全体を失わない）
        - encoding は UTF-8 を明示（Windows での cp932 誤判定を防ぐ）
    """
    log_dir = log_dir or DEFAULT_LOG_DIR
    path = log_dir / filename
    if not path.exists():
        return []

    entries: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            # 壊れた行は黙って飛ばす（運用時にアラート対象にすべきだが
            # 観測層の責務としては「動き続ける」を優先）
            pass
    return entries


# ─── 単一エントリに対するパターン検出 ──────────────────────
def _match_first(uri: str, patterns: list[tuple[Pattern[str], str]]) -> tuple[str, str] | None:
    """
    uri に対してパターン列を順に試し、最初にマッチしたものを返す。
    どれもマッチしなければ None。
    """
    for pattern, tag in patterns:
        m = pattern.search(uri)
        if m:
            return tag, m.group(0)
    return None


def _detect_attack_in_entry(
    entry: dict,
    attack_type: str,
    patterns: list[tuple[Pattern[str], str]],
    severity: Severity = "high",
    decode_uri: bool = True,
) -> Signal | None:
    """
    1エントリに対して指定種類の攻撃パターンを検出する汎用関数。
    sqli / xss / path_traversal の各検出器の共通実装。

    decode_uri:
        True  = URL デコード後の URI でマッチ（sqli / xss 向け）
                %3Cscript%3E → <script> にしてからパターン適用
        False = 生 URI のままマッチ（path_traversal 向け）
                %2e%2e%2f と ../ を別パターンとして区別するため
    """
    uri = entry.get("path", "")
    if decode_uri:
        # $request_uri は URL エンコードされたまま記録される。
        # 例: <script> → %3Cscript%3E
        # パターンマッチ前にデコードすることで、
        # リテラル・エンコード両方の入力に同一パターンで対応できる。
        uri_to_match = urllib.parse.unquote(uri)
    else:
        # path_traversal は「どのエンコード段階で検出したか」を
        # タグで区別する設計のため、デコードしない。
        uri_to_match = uri
    match = _match_first(uri_to_match, patterns)
    if match is None:
        return None
    tag, matched_str = match
    return Signal(
        type=attack_type,
        path=uri,
        severity=severity,
        evidence={
            "pattern_tag": tag,
            "matched_substr": matched_str,
            "raw_uri": uri,
            "ip": entry.get("ip", ""),
            "method": entry.get("method", ""),
            "status": entry.get("status", 0),
        },
        timestamp=entry.get("ts", ""),
    )


def _detect_sqli(entry: dict) -> Signal | None:
    return _detect_attack_in_entry(entry, "sqli", SQLI_PATTERNS, "high")


def _detect_xss(entry: dict) -> Signal | None:
    return _detect_attack_in_entry(entry, "xss", XSS_PATTERNS, "high")


def _detect_path_traversal(entry: dict) -> Signal | None:
    # path_traversal はパターンタグ (dotdot-slash / dotdot-encoded /
    # dotdot-double-encoded) で「どのエンコード段階で検出したか」を
    # 区別する設計。URL デコードすると全てが dotdot-slash に集約されて
    # しまうため、生 URI のままマッチさせる。
    return _detect_attack_in_entry(
        entry, "path_traversal", PATH_TRAVERSAL_PATTERNS, "high",
        decode_uri=False,
    )


def _detect_cmdi(entry: dict) -> Signal | None:
    """
    コマンドインジェクション検出。反復 URL デコード後にパターンマッチする。

    なぜ専用関数が必要か:
        nginx の $request_uri は %28 を ( にデコードしない。
        そのため WAF の正規表現 ";\\s*(cat|ls|id)" は
        system%28%27cat... にマッチしない。

        この関数は _iterative_unquote() で %28→( 等のデコードを
        値が変化しなくなるまで最大 3 回繰り返す。二重エンコード
        （%2528 → %28 → (）にも対応する。

    severity:
        critical を採用。RCE = サーバ全権限取得 = 最重大の攻撃カテゴリ。
        18_ プレイブック #29 が刺さった瞬間に発火するセンサー。
    """
    uri_raw = entry.get("path", "")
    uri_decoded = _iterative_unquote(uri_raw)
    was_decoded = (uri_decoded != uri_raw)

    match = _match_first(uri_decoded, CMDI_PATTERNS)
    if match is None:
        return None

    tag, matched_str = match
    return Signal(
        type="cmdi",
        path=uri_raw,
        severity="critical",
        evidence={
            "pattern_tag": tag,
            "matched_substr": matched_str,
            "raw_uri": uri_raw,
            "decoded_uri": uri_decoded if was_decoded else None,
            "decoded": was_decoded,
            "ip": entry.get("ip", ""),
            "method": entry.get("method", ""),
            "status": entry.get("status", 0),
        },
        timestamp=entry.get("ts", ""),
    )


def _detect_dotfile(entry: dict) -> Signal | None:
    return _detect_attack_in_entry(
        entry, "webapp_dotfile", WEBAPP_DOTFILE_PATTERNS, "high",
        decode_uri=False,
    )


def _detect_upload_php(entry: dict) -> Signal | None:
    return _detect_attack_in_entry(
        entry, "webapp_upload_php", WEBAPP_UPLOAD_PHP_PATTERNS, "high",
        decode_uri=False,
    )


def _detect_auth_endpoint(entry: dict) -> Signal | None:
    return _detect_attack_in_entry(
        entry, "webapp_auth", WEBAPP_AUTH_PATTERNS, "low",
        decode_uri=True,
    )


def _detect_scanner_ua(entry: dict) -> Signal | None:
    """User-Agent ベースのスキャナ検出。entry["user_agent"] 想定。"""
    ua = entry.get("user_agent", "") or entry.get("ua", "")
    if not ua:
        return None
    for pattern, tag in WEBAPP_SCANNER_PATTERNS:
        m = pattern.search(ua)
        if m:
            return Signal(
                type="webapp_scanner",
                path=entry.get("path", ""),
                severity="medium",
                evidence={
                    "pattern_tag": tag,
                    "matched_substr": m.group(0),
                    "user_agent": ua,
                    "ip": entry.get("ip", ""),
                },
                timestamp=entry.get("ts", ""),
            )
    return None


def _detect_waf_block(entry: dict) -> Signal | None:
    """
    status=403 を waf_block シグナルとして観測。
    これは「既に防御が効いた」という情報で、severity は low。
    エージェントは通常これに追加のルールは生成しない（既に止まっているため）。
    """
    if entry.get("status") != 403:
        return None
    return Signal(
        type="waf_block",
        path=entry.get("path", ""),
        severity="low",
        evidence={
            "ip": entry.get("ip", ""),
            "status": 403,
            "upstream": entry.get("upstream", ""),
        },
        timestamp=entry.get("ts", ""),
    )


# ─── 集約ベース検出 ───────────────────────────────────────
def _detect_path_scans(
    entries: list[dict],
    threshold: int = PATH_SCAN_THRESHOLD,
) -> list[Signal]:
    """
    同一パスへのアクセス回数が threshold 以上なら path_scan シグナル。
    偵察（reconnaissance）やブルートフォースの兆候を表す。
    """
    path_count: dict[str, int] = defaultdict(int)
    latest_ts: dict[str, str] = {}
    for e in entries:
        p = e.get("path", "")
        if not p:
            continue
        path_count[p] += 1
        latest_ts[p] = e.get("ts", latest_ts.get(p, ""))

    signals: list[Signal] = []
    for path, cnt in path_count.items():
        if cnt >= threshold:
            signals.append(Signal(
                type="path_scan",
                path=path,
                severity="medium",
                evidence={
                    "count": cnt,
                    "threshold": threshold,
                    "ratio": cnt / threshold,
                },
                timestamp=latest_ts.get(path, ""),
            ))
    return signals


# ─── トップレベル解析関数 ─────────────────────────────────
def analyze_nginx(entries: list[dict]) -> list[Signal]:
    """
    nginx JSON アクセスログから Signal を抽出する。

    単一エントリ検出（sqli / xss / path_traversal / waf_block）と
    集約検出（path_scan）を組み合わせる。
    """
    signals: list[Signal] = []

    # 単一エントリに対する検出
    detectors = [
        _detect_sqli,
        _detect_xss,
        _detect_path_traversal,
        _detect_cmdi,
        _detect_dotfile,
        _detect_upload_php,
        _detect_auth_endpoint,
        _detect_scanner_ua,
        _detect_waf_block,
    ]
    entries = [_normalize_entry(e) for e in entries]
    for entry in entries:
        for detector in detectors:
            sig = detector(entry)
            if sig is not None:
                signals.append(sig)

    # 集約ベース検出
    signals.extend(_detect_path_scans(entries))
    signals.extend(_detect_auth_bruteforce(entries))

    return signals


def _detect_auth_bruteforce(entries: list[dict]) -> list[Signal]:
    """
    Web 認証エンドポイント (wp-login / xmlrpc / admin) への POST が
    同一 IP から閾値超なら brute force と判定。
    18_ #23 (WordPress brute) を IP 単位で汎用化。
    """
    auth_count: dict[str, int] = defaultdict(int)
    latest_ts: dict[str, str] = {}
    auth_re = WEBAPP_AUTH_PATTERNS[0][0]  # 認証エンドポイント パターン

    for e in entries:
        path = e.get("path", "")
        method = e.get("method", "")
        ip = e.get("ip", "")
        if not ip or not auth_re.search(path):
            continue
        if method.upper() != "POST":
            continue
        auth_count[ip] += 1
        latest_ts[ip] = e.get("ts", latest_ts.get(ip, ""))

    signals: list[Signal] = []
    for ip, cnt in auth_count.items():
        if cnt >= WEBAPP_AUTH_THRESHOLD:
            signals.append(Signal(
                type="webapp_bruteforce",
                path=f"<auth endpoint x{cnt}>",
                severity="high",
                evidence={
                    "pattern_tag": "webapp/auth-bruteforce",
                    "ip": ip,
                    "count": cnt,
                    "threshold": WEBAPP_AUTH_THRESHOLD,
                },
                timestamp=latest_ts.get(ip, ""),
            ))
    return signals


def analyze_named(lines: list[str]) -> list[Signal]:
    """
    BIND named.log の行ベース解析。
    18_ #36-39 を汎用化した DNS_PATTERNS でマッチ。
    """
    signals: list[Signal] = []
    any_count = 0
    total_query = 0
    for line in lines:
        # ANY クエリ比率の集計 (amplification 判定用)
        if re.search(r"(?i)query:", line):
            total_query += 1
            if re.search(r"(?i)\sIN\s+ANY\b", line):
                any_count += 1
        # 単発パターンマッチ
        for pattern, tag in DNS_PATTERNS:
            m = pattern.search(line)
            if m:
                signals.append(Signal(
                    type="dns",
                    path=line[:200],
                    severity="high" if "unauthorized" in tag else "medium",
                    evidence={
                        "pattern_tag": tag,
                        "matched_substr": m.group(0),
                        "raw_line": line[:300],
                    },
                    timestamp="",
                ))
                break  # 同一行で複数 tag は付けない
    # ANY 比率 amplification
    if total_query >= 50 and any_count / max(total_query, 1) >= DNS_AMPLIFICATION_RATIO:
        signals.append(Signal(
            type="dns",
            path=f"<ANY ratio {any_count}/{total_query}>",
            severity="medium",
            evidence={
                "pattern_tag": "dns/amplification-ratio",
                "any_count": any_count,
                "total": total_query,
                "ratio": any_count / total_query,
            },
            timestamp="",
        ))
    return signals


def analyze_secure(lines: list[str]) -> list[Signal]:
    """
    /var/log/secure (Linux) または auth.log (FreeBSD) の行ベース解析。
    SSH brute / telnet / pkexec / sudo を検出。
    18_ #1, #10, #51 を汎用化。
    """
    signals: list[Signal] = []
    ssh_fail_count: dict[str, int] = defaultdict(int)

    for line in lines:
        # SSH brute 用の集計を併走
        m = re.search(r"(?i)Failed password for (?:invalid user )?\S+ from (\S+)", line)
        if m:
            ssh_fail_count[m.group(1)] += 1
        # 単発パターンマッチ
        for pattern, tag in SECURE_PATTERNS:
            m = pattern.search(line)
            if m:
                # ssh-failed/invalid は集計側で出すので単発では出さない
                if tag.startswith("auth/ssh-"):
                    break
                severity = "high" if tag.startswith("privesc/") else "medium"
                signals.append(Signal(
                    type=tag.split("/")[0],
                    path=line[:200],
                    severity=severity,
                    evidence={
                        "pattern_tag": tag,
                        "matched_substr": m.group(0),
                        "raw_line": line[:300],
                    },
                    timestamp="",
                ))
                break
    # SSH brute 集約
    for src_ip, cnt in ssh_fail_count.items():
        if cnt >= SSH_BRUTE_THRESHOLD:
            signals.append(Signal(
                type="auth",
                path=f"<ssh brute from {src_ip}>",
                severity="high",
                evidence={
                    "pattern_tag": "auth/ssh-bruteforce",
                    "ip": src_ip,
                    "count": cnt,
                    "threshold": SSH_BRUTE_THRESHOLD,
                },
                timestamp="",
            ))
    return signals


def analyze_maillog(lines: list[str]) -> list[Signal]:
    """
    postfix / sendmail の maillog 行ベース解析。
    18_ #31-35 を汎用化した MAIL_PATTERNS でマッチ + 送信元 burst を集計。
    """
    signals: list[Signal] = []
    sender_count: dict[str, int] = defaultdict(int)

    for line in lines:
        # 単発パターン
        for pattern, tag in MAIL_PATTERNS:
            m = pattern.search(line)
            if m:
                signals.append(Signal(
                    type="mail",
                    path=line[:200],
                    severity="medium",
                    evidence={
                        "pattern_tag": tag,
                        "matched_substr": m.group(0),
                        "raw_line": line[:300],
                    },
                    timestamp="",
                ))
                break
        # client= の送信元 IP を集計
        m = re.search(r"client=[^\[]*\[(\d+\.\d+\.\d+\.\d+)\]", line)
        if m:
            sender_count[m.group(1)] += 1

    # burst 検出
    for ip, cnt in sender_count.items():
        if cnt >= MAIL_BURST_THRESHOLD:
            signals.append(Signal(
                type="mail",
                path=f"<mail burst from {ip}>",
                severity="medium",
                evidence={
                    "pattern_tag": "mail/burst",
                    "ip": ip,
                    "count": cnt,
                    "threshold": MAIL_BURST_THRESHOLD,
                },
                timestamp="",
            ))
    return signals


def load_text_log(filename: str, log_dir: pathlib.Path | None = None) -> list[str]:
    """
    プレーンテキストログ (named.log / secure / maillog) を 1 行ずつ読み込む。
    JSONL ではなく行ベースなので別関数。
    """
    log_dir = log_dir or DEFAULT_LOG_DIR
    path = log_dir / filename
    if not path.exists():
        return []
    return [
        line for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]


def analyze_wordpress(entries: list[dict]) -> list[Signal]:
    """
    WordPress アプリログ (camp-logger.php) から Signal を抽出する。

    現状は idor_violation のみを見ているが、将来的には:
        - 認証失敗の連続（brute force）
        - 権限昇格試行
        - 不審な wp-admin アクセスパターン
    なども追加可能。
    """
    signals: list[Signal] = []
    for e in entries:
        if e.get("idor_violation"):
            signals.append(Signal(
                type="idor",
                path=e.get("path", ""),
                severity="high",
                evidence={
                    "user_id": e.get("session_user_id"),
                    "detail":  e.get("idor_detail", ""),
                    "action":  e.get("action", ""),
                },
                timestamp=e.get("ts", ""),
            ))
    return signals


def run(log_dir: pathlib.Path | str | None = None) -> list[Signal]:
    """
    観測層のメインエントリポイント。

    引数:
        log_dir: ログディレクトリパス（None なら DEFAULT_LOG_DIR = /logs）
                 テスト時は tempdir を指定できる。

    返り値:
        検出された Signal のリスト。
        後段（判断層/patcher）は観測層の履歴に依存せず動作する前提。
    """
    log_dir_path: pathlib.Path | None = None
    if log_dir is not None:
        log_dir_path = pathlib.Path(log_dir)

    nginx_signals = analyze_nginx(load_logs("access.log", log_dir_path))
    wp_signals = analyze_wordpress(load_logs("wp-app.log", log_dir_path))

    # 6 カテゴリ拡張: line-based ログ群
    # ファイル名は parse_*.py の出力 / SSH 取得時の保存名に揃える
    named_signals: list[Signal] = []
    for fname in ("named.log", "incident_named.log", "bravo_named.log"):
        named_signals.extend(analyze_named(load_text_log(fname, log_dir_path)))

    secure_signals: list[Signal] = []
    for fname in (
        "secure", "incident_secure.log", "victor_secure.log",
        "auth.log", "incident_auth.log", "bravo_auth.log",
    ):
        secure_signals.extend(analyze_secure(load_text_log(fname, log_dir_path)))

    mail_signals: list[Signal] = []
    for fname in (
        "maillog", "incident_maillog.log",
        "victor_maillog.log", "bravo_maillog.log",
    ):
        mail_signals.extend(analyze_maillog(load_text_log(fname, log_dir_path)))

    return (
        nginx_signals + wp_signals
        + named_signals + secure_signals + mail_signals
    )
