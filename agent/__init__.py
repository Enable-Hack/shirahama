"""
ai-agent: 白浜インシデント対応用の判断層パッケージ

3層構造（白浜運用版 / Renderer・Patcher は削除済）:
    1. 観測層 (analyzer.py)    : logs → list[Signal] + 未分類ログ
    2. 判断層 (backends/)      : Signal → PatchProposal (Mock + Claude)
    3. 検証層 (validator.py)   : PatchProposal の健全性検証

各層は /incident slash command が Bash で 1 ステップずつ呼び出す。
PatchProposal を nginx 構文に翻訳する Renderer 層、および
4層を 1 クラスでオーケストレートする Patcher は本フローでは使わない
（キャンプ B 教材版に残す）。
"""
from . import analyzer
from .llm import (
    Action,
    LLMBackend,
    MatchOperator,
    MatchType,
    PatchProposal,
    Severity,
    Signal,
)
from .validator import PatchValidationError, validate_patch, validate_patches

__all__ = [
    "analyzer",
    "Action",
    "LLMBackend",
    "MatchOperator",
    "MatchType",
    "PatchProposal",
    "Severity",
    "Signal",
    "PatchValidationError",
    "validate_patch",
    "validate_patches",
]
