"""
ai-agent.backends.mock_backend

非LLM擬似エージェント backend。

この backend は意図的に LLM を使わず、ルールベース + 状態保持のみで
「エージェンティックな挙動は LLM がなくとも成立する」ことを示す。

教材上の位置づけ:
    - Claude/Swallow との比較基準点（baseline）
    - ネット遮断時・API障害時の継続運用手段
    - 再現性100%が必要な自動テストでのフォールバック
    - 「エージェント = LLM」ではないことを示す設計教材

状態保持の例:
    - 直近シグナルの窓付き観測
    - 既適用パッチの重複抑止
    - 種別ごとの累積カウント（攻撃継続性の判定）
"""
from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from typing import Callable, Sequence

from ..llm import (
    Action,
    LLMBackend,
    PatchProposal,
    Signal,
)

# ─── ユーティリティ ──────────────────────────────────────
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _max_severity(signals: Sequence[Signal]) -> str:
    return max(signals, key=lambda s: _SEVERITY_ORDER.get(s.severity, 0)).severity


def _common_path_prefix(signals: Sequence[Signal]) -> str:
    """
    シグナル群の共通パスプレフィックスを推定する。
    見つからない場合は空文字を返す。
    """
    paths = [s.path for s in signals if s.path]
    if not paths:
        return ""
    prefix = paths[0]
    for p in paths[1:]:
        while prefix and not p.startswith(prefix):
            idx = prefix.rfind("/")
            if idx <= 0:
                prefix = ""
                break
            prefix = prefix[:idx]
    return prefix or ""


def _rule_id(slug: str, *content_parts: str) -> str:
    """
    内容ハッシュベースの rule_id を生成する（案B: 同一内容→同一ID）。

    これにより:
        - 同じシグナル入力に対して常に同じ rule_id が発行される（再現性）
        - 重複抑止が rule_id ベースで自然に実装できる
        - Day 2 の比較レポートで rule_id を diff キーに使える

    content_parts には target / match_type / match_operator / match_value を
    渡すことで、内容が同じなら ID も同じになる設計。
    """
    content = "|".join(content_parts)
    digest = hashlib.sha1(content.encode()).hexdigest()[:8]
    return f"mock-{slug}-{digest}"


# ─── MockBackend 本体 ───────────────────────────────────
class MockBackend(LLMBackend):
    """
    記憶保持＋ルール判定による擬似エージェント backend。

    内部状態:
        recent_signals:    直近N件のシグナル履歴（窓付き観測）
        applied_rule_ids:  既にパッチ化済みの rule_id 集合（重複抑止用）
                           案B採用により rule_id が内容ハッシュベースなので、
                           ここにあるだけで「同一内容の提案が再度来た」と判定できる
        signal_counts:     シグナル種別ごとの累積カウント
    """

    _WINDOW = 50
    _ESCALATION_THRESHOLD = 5  # 同種が閾値以上 → 対応を昇格

    def __init__(self) -> None:
        self.recent_signals: deque[Signal] = deque(maxlen=self._WINDOW)
        self.applied_rule_ids: set[str] = set()
        self.signal_counts: dict[str, int] = defaultdict(int)

    def name(self) -> str:
        return "mock-rulebased-v1"

    # ─── 提案生成 ────────────────────────────────────────
    def propose_patches(self, signals: list[Signal]) -> list[PatchProposal]:
        # 観測を記憶
        for s in signals:
            self.recent_signals.append(s)
            self.signal_counts[s.type] += 1

        # 種別ごとにハンドラへ分岐
        by_type: dict[str, list[Signal]] = defaultdict(list)
        for s in signals:
            by_type[s.type].append(s)

        proposals: list[PatchProposal] = []
        for sig_type, sigs in by_type.items():
            handler = self._HANDLERS.get(sig_type, MockBackend._handle_unknown)
            proposals.extend(handler(self, sigs))

        # 既適用 rule_id の重複抑止（advisory に降格）
        # 案B: rule_id が内容ハッシュベースなので、ID が既に登録されていれば
        # それは「同一内容の提案が再度来た」ことを意味する
        deduped: list[PatchProposal] = []
        for p in proposals:
            if p.rule_id in self.applied_rule_ids:
                # 降格: 元の action と rationale を保持しつつ、自然な日本語で表現
                original_action = p.action
                original_rationale = p.rationale_ja
                p.action = "advisory"
                p.rationale_ja = (
                    f"初回は {original_action} 候補でしたが、"
                    f"既適用パターンのため今回は advisory として扱います。"
                    f" 元の判断理由: {original_rationale}"
                )
            else:
                self.applied_rule_ids.add(p.rule_id)
            deduped.append(p)

        return deduped

    # ─── 日本語説明生成 ──────────────────────────────────
    def explain_to_operator_ja(
        self,
        signals: list[Signal],
        patches: list[PatchProposal],
    ) -> str:
        if not signals:
            return "新規に検知された異常はありません。"

        lines: list[str] = []
        lines.append(
            f"【MockBackend 判定結果】受信シグナル {len(signals)} 件、"
            f"生成提案 {len(patches)} 件。"
        )

        # 種別ごとの件数
        counts: dict[str, int] = defaultdict(int)
        for s in signals:
            counts[s.type] += 1
        breakdown = "、".join(f"{k}={v}" for k, v in sorted(counts.items()))
        lines.append(f"種別内訳: {breakdown}")

        # 累積観測から昇格判断の説明
        for sig_type, total in sorted(self.signal_counts.items()):
            if total >= self._ESCALATION_THRESHOLD:
                lines.append(
                    f"注意: '{sig_type}' の累積観測が {total} 件に達しました。"
                    "攻撃の継続性を示唆します。"
                )

        # 提案の概要
        for p in patches:
            lines.append(
                f"- [{p.action}] target={p.target} / "
                f"{p.match_type}:{p.match_operator}:{p.match_value!r} "
                f"(rule_id={p.rule_id}, conf={p.confidence:.2f}): "
                f"{p.rationale_ja}"
            )

        return "\n".join(lines)

    # ─── シグナル種別別ハンドラ ──────────────────────────
    def _handle_sqli(self, signals: Sequence[Signal]) -> list[PatchProposal]:
        """SQL インジェクション: 既知シグネチャで block を提案"""
        n = len(signals)
        severity_max = _max_severity(signals)
        action: Action = "block" if severity_max in ("high", "critical") else "log"

        target = _common_path_prefix(signals) or "*"
        match_type = "query"
        match_operator = "regex"
        # analyzer の SQLI_PATTERNS と同等のパターンを使用する。
        # - (?i)             大文字小文字混在 (uNiOn SeLeCt 等) を一括吸収
        # - union            固定リテラル
        # - (?:\s|\+|%20|/\*.*?\*/){1,10}
        #                    区切り文字として次を許容:
        #                      \s    空白
        #                      \+    URLエンコード + (空白のエンコード)
        #                      %20   URLエンコード %20
        #                      /*..*/ SQL コメント挿入によるバイパス
        #                    1〜10回まで繰り返し(ReDoS 防止の上限付き)
        # - select           固定リテラル
        match_value = r"(?i)union(?:\s|\+|%20|/\*.*?\*/){1,10}select"

        return [
            PatchProposal(
                rule_id=_rule_id(
                    "sqli-union", target, match_type, match_operator, match_value
                ),
                target=target,
                match_type=match_type,
                match_operator=match_operator,
                match_value=match_value,
                action=action,
                confidence=0.85 if n >= 2 else 0.70,
                rationale_ja=(
                    f"SQLインジェクション疑いを {n} 件観測しました。"
                    f"UNION SELECT 系パターン（空白・+・%20・/**/挿入を含む）を "
                    f"{action} 対象とします。"
                ),
            ),
        ]

    def _handle_idor(self, signals: Sequence[Signal]) -> list[PatchProposal]:
        """IDOR: WAF層では完全防御が困難なため advisory として提案"""
        n = len(signals)
        target = _common_path_prefix(signals) or "/"
        match_type = "path"
        match_operator = "prefix"
        match_value = target

        return [
            PatchProposal(
                rule_id=_rule_id(
                    "idor-advisory", target, match_type, match_operator, match_value
                ),
                target=target,
                match_type=match_type,
                match_operator=match_operator,
                match_value=match_value,
                action="advisory",
                confidence=0.60,
                rationale_ja=(
                    f"IDOR 疑いを {n} 件観測しました。"
                    "WAF層での自動防御は困難なため、"
                    "アプリ側での認可チェック強化を推奨します。"
                ),
            ),
        ]

    def _handle_xss(self, signals: Sequence[Signal]) -> list[PatchProposal]:
        """XSS: body 内の script タグを log 対象に追加"""
        n = len(signals)
        target = _common_path_prefix(signals) or "*"
        match_type = "body"
        match_operator = "contains"
        match_value = "<script"

        return [
            PatchProposal(
                rule_id=_rule_id(
                    "xss-body-script", target, match_type, match_operator, match_value
                ),
                target=target,
                match_type=match_type,
                match_operator=match_operator,
                match_value=match_value,
                action="log",
                confidence=0.55,
                rationale_ja=(
                    f"XSS 疑いを {n} 件観測しました。"
                    "body 内の script タグ出現を記録対象に追加します。"
                ),
            ),
        ]

    def _handle_path_traversal(
        self,
        signals: Sequence[Signal],
    ) -> list[PatchProposal]:
        """パストラバーサル: エンコード版を含めて block

        analyzer.PATH_TRAVERSAL_PATTERNS と同等のバリアントをカバーする:
            - ../                 素の ../
            - %2e%2e%2f           URL エンコード (大文字小文字不問)
            - %252e%252e          二重 URL エンコード (大文字小文字不問)
        (?i) で大文字小文字混在も一括吸収、交替のみなので ReDoS 安全。
        """
        target = _common_path_prefix(signals) or "*"
        match_type = "path"
        match_operator = "regex"
        match_value = r"(?i)(\.\./)|(%2e%2e%2f)|(%252e%252e)"

        return [
            PatchProposal(
                rule_id=_rule_id(
                    "path-traversal", target, match_type, match_operator, match_value
                ),
                target=target,
                match_type=match_type,
                match_operator=match_operator,
                match_value=match_value,
                action="block",
                confidence=0.90,
                rationale_ja=(
                    f"パストラバーサル疑いを {len(signals)} 件観測しました。"
                    "URL エンコード・二重エンコード版を含む既知パターンを "
                    "block します。"
                ),
            ),
        ]

    def _handle_cmdi(
        self,
        signals: Sequence[Signal],
    ) -> list[PatchProposal]:
        """コマンドインジェクション: URLデコード後のパターンで block

        MT CVE-2026-25776 のペイロードは URLエンコードされた状態で
        クエリパラメータに含まれる（例: system%28%27cat...%27%29）。

        WAF（nginx $request_uri）は %28 を ( にデコードしないため素通りする。
        MockBackend は「デコード後に system( 等が出現する」パターンを
        提案するが、これはルールベースの限界でもある:
            - エンコードの多段化（%2573ystem 等）で容易にバイパスされる
            - バッククォート (`id`) は別パターンが必要
            - 新しい関数名（open3 等）には対応できない

        → Claude backend なら「このパラメータが eval() に渡される文脈で、
          任意コード実行を意図している」と意味レベルで判定できる。
          これが Mock vs Claude の最も鮮明な差分になる。
        """
        n = len(signals)
        severity_max = _max_severity(signals)
        action: Action = "block" if severity_max in ("high", "critical") else "log"

        target = _common_path_prefix(signals) or "/mt/"
        match_type = "query"
        match_operator = "regex"
        # system / exec / passthru / popen の呼び出しをカバー。
        # (?i) で大文字小文字混在を吸収。
        # \s* で関数名とカッコの間の空白を許容。
        # バッククォートは別パターンとして交替に含める。
        match_value = r"(?i)(system|exec|passthru|popen)\s*\(|`[^`]+`"

        return [
            PatchProposal(
                rule_id=_rule_id(
                    "cmdi", target, match_type, match_operator, match_value
                ),
                target=target,
                match_type=match_type,
                match_operator=match_operator,
                match_value=match_value,
                action=action,
                confidence=0.75 if n >= 2 else 0.60,
                rationale_ja=(
                    f"コマンドインジェクション疑いを {n} 件観測しました。"
                    "URLデコード後に system()/exec() 等の関数呼び出しパターンを検出。"
                    f"{action} 対象とします。"
                    "ただしエンコード多段化によるバイパスの可能性があり、"
                    "アプリ側での eval() 除去が根本対策です。"
                    "注意: このルールはデコード後の意味解析に基づく観測結果であり、"
                    "raw request を検査する WAF では同一ペイロードを"
                    "捕捉できない可能性があります。"
                ),
            ),
        ]

    def _handle_unknown(self, signals: Sequence[Signal]) -> list[PatchProposal]:
        """未知のシグナル種別: advisory のみ"""
        sample = signals[0]
        # 未知種別はサフィックスに混入する場合があるので衛生化
        safe_slug = "".join(
            c for c in sample.type[:16] if c.isalnum() or c in "-_"
        ) or "x"
        target = _common_path_prefix(signals) or "*"
        match_type = "path"
        match_operator = "contains"
        match_value = sample.path or "/"

        return [
            PatchProposal(
                rule_id=_rule_id(
                    f"unknown-{safe_slug}",
                    target,
                    match_type,
                    match_operator,
                    match_value,
                ),
                target=target,
                match_type=match_type,
                match_operator=match_operator,
                match_value=match_value,
                action="advisory",
                confidence=0.30,
                rationale_ja=(
                    f"未知の攻撃パターン '{sample.type}' を "
                    f"{len(signals)} 件観測しました。手動レビューを推奨します。"
                ),
            ),
        ]

    # ハンドラ分岐テーブル
    # 型: Callable[[MockBackend, Sequence[Signal]], list[PatchProposal]]
    _HANDLERS: dict[str, Callable] = {
        "sqli": _handle_sqli,
        "idor": _handle_idor,
        "xss": _handle_xss,
        "path_traversal": _handle_path_traversal,
        "cmdi": _handle_cmdi,
    }
