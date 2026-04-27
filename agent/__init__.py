"""
ai-agent: Web防御エージェントの判断層パッケージ

4層構造:
    1. 観測層 (analyzer.py)    : logs → list[Signal]   ← LLM非依存
    2. 判断層 (backends/)      : Signal → PatchProposal ← 差し替え可能
    3. 検証層 (validator.py)   : PatchProposal の健全性検証（必須の関所）
    4. 提案層 (renderers/)     : PatchProposal → WAF固有構文

このパッケージは「AIエージェント時代のサイバー防衛入門」教材の中核で、
受講者はこの設計を通じて「防御エージェントの運用設計」を学ぶ。
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
from .patcher import Patcher, PatcherRunSummary
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
    "Patcher",
    "PatcherRunSummary",
    "PatchValidationError",
    "validate_patch",
    "validate_patches",
]
