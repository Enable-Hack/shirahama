"""
ai-agent.backends: LLMBackend の各種実装

利用可能な backend:
    - MockBackend   : 非LLM擬似エージェント（保険・比較基準点・再現性確保）
    - ClaudeBackend : Anthropic Claude (Haiku 4.5) 使用（標準デモ）
    - SwallowBackend: Llama-3.1-Swallow-8B (Ollama) 使用（閉域・ローカル）

MockBackend は純粋な標準ライブラリのみで動作する。
ClaudeBackend は anthropic SDK が必要（遅延 import）。
SwallowBackend は requests のみで動作（requirements.txt に同梱済み）。
"""
from .mock_backend import MockBackend

__all__ = ["MockBackend"]

# ClaudeBackend: anthropic SDK が未インストールの環境でも MockBackend だけで
# 動かせるよう遅延 import
try:
    from .claude_backend import ClaudeBackend  # noqa: F401
    __all__.append("ClaudeBackend")
except ImportError:
    pass

# SwallowBackend: requests は requirements.txt にあるので通常 import 成功するが
# 念のため遅延 import
try:
    from .swallow_backend import (  # noqa: F401
        SwallowBackend,
        OllamaError,
        OllamaConnectionError,
        OllamaModelNotFoundError,
        OllamaTimeoutError,
    )
    __all__.extend([
        "SwallowBackend",
        "OllamaError",
        "OllamaConnectionError",
        "OllamaModelNotFoundError",
        "OllamaTimeoutError",
    ])
except ImportError:
    pass
