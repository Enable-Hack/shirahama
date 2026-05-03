"""
ai-agent: LLMBackend 抽象インタフェース

観測層（analyzer.py）が出力した Signal を受け取り、
中立な PatchProposal として判断結果を返す契約を定義する。

このモジュールは WAF 実装に依存しない（白浜運用では Nginx 構文への
翻訳は行わず、PatchProposal はそのまま画面表示・報告書生成に使われる）。

教材上の位置づけ:
    観測層 → 判断層（このモジュール）→ 検証層 → 画面表示 / 報告書
    「判断」だけを差し替え可能にすることで、クラウドLLM・ローカルLLM・
    非LLMフォールバックの3者を同一コードから利用できる。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

# ─── 型エイリアス（語彙の固定）─────────────────────────────
# Literal で型チェッカに制約を伝えつつ、実行時検証のための
# 値タプルも下で定義する（validator.py が参照）
Severity = Literal["low", "medium", "high", "critical"]
MatchType = Literal["path", "query", "header", "body", "method"]
MatchOperator = Literal["equals", "contains", "regex", "prefix"]
Action = Literal["block", "log", "advisory", "rate_limit"]

# enum 値をランタイムでも参照可能にする（validator が利用）
SEVERITY_VALUES: tuple[str, ...] = ("low", "medium", "high", "critical")
MATCH_TYPE_VALUES: tuple[str, ...] = ("path", "query", "header", "body", "method")
MATCH_OPERATOR_VALUES: tuple[str, ...] = ("equals", "contains", "regex", "prefix")
ACTION_VALUES: tuple[str, ...] = ("block", "log", "advisory", "rate_limit")


@dataclass(frozen=True)
class Signal:
    """
    観測層（analyzer.py）が出力する構造化シグナル。

    Attributes:
        type:      検出した攻撃パターン種別
                   （"sqli", "idor", "xss", "path_traversal" など）
        path:      観測されたリクエストパス
        severity:  重大度（low/medium/high/critical）
        evidence:  判断根拠となった生ログやマッチ情報
        timestamp: ISO8601 形式の観測時刻
    """
    type: str
    path: str
    severity: Severity
    evidence: dict
    timestamp: str


@dataclass
class PatchProposal:
    """
    判断層（backend）が出力する、WAF非依存な中立パッチ提案。

    白浜運用では、このオブジェクトは検証層を通った後、画面に表示されて
    人間（指揮係）と AI が議論する材料になる。実機への適用コマンドは
    /playbook:* スキルが直接 ssh で発行する設計。

    フィールドの読み方:
        target          どの領域を保護するか（WHERE）
                        例: "/mt/", "/wp/wp-json/", "*"
        match_type      リクエストの何を検査するか（WHAT）
                        path | query | header | body | method
        match_operator  どう比較するか（HOW）
                        equals | contains | regex | prefix
        match_value     比較対象の値（operator に応じて意味が確定）
        action          検知時の挙動
                        block | log | advisory | rate_limit

    confidence について:
        backend 自身が「この提案にどれくらい自信があるか」を自己申告する値。
        真の事後確率ではなく、backend 間で絶対値を比較する用途には適さない。
        同一 backend 内での提案の相対順序付けに使うのが正しい用法。

        教材メッセージ: 「AIが95%の信頼度と言っているから正しい」と
        考えるのは危険。confidence は二次スクリーニング対象の優先度付けに使う。
    """
    rule_id: str
    target: str
    match_type: MatchType
    match_operator: MatchOperator
    match_value: str
    action: Action
    confidence: float
    rationale_ja: str


class LLMBackend(ABC):
    """
    判断層の抽象インタフェース。

    Claude / Swallow / Mock の3つの実装がこの契約に従う。
    受講者は同一コードから各 backend を利用して比較する。
    """

    @abstractmethod
    def propose_patches(self, signals: list[Signal], unmatched_logs: list[dict] | None = None) -> list[PatchProposal]:
        """
        シグナル列を解釈し、複数の仮想パッチ提案を返す。

        1回の入力から block/advisory/log-only が同時に出ることは自然なため、
        返り値は list[PatchProposal]（単数ではない）。
        """
        ...

    @abstractmethod
    def explain_to_operator_ja(
        self,
        signals: list[Signal],
        patches: list[PatchProposal],
        unmatched_logs: list[dict] | None = None,
    ) -> str:
        """SOC担当者向けの日本語状況説明を生成する。"""
        ...

    @abstractmethod
    def name(self) -> str:
        """ログ・比較レポート用の識別子（例: 'claude-haiku-4.5'）"""
        ...
