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
        _detect_waf_block,
    ]
    for entry in entries:
        for detector in detectors:
            sig = detector(entry)
            if sig is not None:
                signals.append(sig)

    # 集約ベース検出
    signals.extend(_detect_path_scans(entries))

    return signals


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
    return nginx_signals + wp_signals
