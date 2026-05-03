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
import re
from collections import defaultdict, deque
from typing import Callable, Sequence

from ..llm import (
    Action,
    LLMBackend,
    PatchProposal,
    Signal,
)

# ─── 本番環境 whitelist (白浜本番向け / 18_§9 由来) ─────────
# 配布アカウント由来の活動は全て drop する。これらは「攻撃に使われない」と
# 16_本番環境クイックリファレンス §0 で明記されている = 攻撃者は別アカウントから来る。
KNOWN_GOOD_USERS: frozenset[str] = frozenset({
    "manage",   # 配布管理アカウント (両機 wheel)
    "root",     # 配布 root
    "admin",    # NW 機器管理
    "vty",      # NW 機器 vty
    "enable",   # NW 機器 enable
})

# 既侵害 IP (§0.5 既侵害前提)。/incident は時間窓を限定するが、
# このレンジ由来の活動は窓外でも保持する (forensic context)。
KNOWN_ATTACKER_IP_RE = re.compile(r"\b10\.1\.129\.\d{1,3}\b")

# Claude に投げる前に問答無用で drop するシステムノイズ。
# 「攻撃の物証ではないが /var/log/{secure,maillog,messages} に大量に残るチャター」
# - pam_unix session open/close: sudo / su / systemd-user の正常ライフサイクル
# - sshd preauth disconnect: 公開 SSH に来るランダムスキャナの自然な切断
# - sshd Connection closed by ... [preauth]: 同上
# - systemd-user session: ログイン時の DBus 起動
# - named "dumping master file: rename: ... permission denied": 周期的な named 内部処理
# - sendmail "unqualified host name": ローカル名前解決の警告 (毎分発生)
# - sendmail "alias database not present": startup 警告
NOISE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"pam_unix\([^)]+\):\s*session\s+(opened|closed)"),
    re.compile(r"sshd\[\d+\]:\s*Received\s+disconnect.*\[preauth\]"),
    re.compile(r"sshd\[\d+\]:\s*Connection\s+closed\s+by.*\[preauth\]"),
    re.compile(r"sshd\[\d+\]:\s*Disconnected\s+from.*\[preauth\]"),
    re.compile(r"named\[\d+\]:\s*dumping\s+master\s+file"),
    re.compile(r"sendmail\[\d+\]:\s*My\s+unqualified\s+host\s+name"),
    re.compile(r"sendmail\[\d+\]:\s*alias\s+database.*not\s+present"),
    re.compile(r"systemd\[\d+\]:.*systemd-user.*session"),
]


def _is_noise(raw: str) -> bool:
    """システムチャター系のノイズかどうか。True なら drop。"""
    return any(p.search(raw) for p in NOISE_PATTERNS)


# 自チーム (whiskey 班 / booth11-15) が DHCP で割り当てられる帯域。
# 競技中、自チーム 5 人の偵察トラフィック (tail / dig / curl 確認) を
# 「攻撃者として誤認」しないために除外する。
# 配布レンジは 16_本番環境クイックリファレンス §2.2 で 10.1.11.50-99。
def _is_team_ip(ip: str) -> bool:
    """自チーム DHCP 配布レンジ 10.1.11.50-99 の判定。"""
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        if parts[0] == "10" and parts[1] == "1" and parts[2] == "11":
            last = int(parts[3])
            return 50 <= last <= 99
    except ValueError:
        return False
    return False


def _is_known_good(signal) -> bool:
    """配布アカウント由来 / 自チーム IP 由来かどうか判定。
    True なら drop すべき (Mock も Claude も呼ばない)。

    判定ロジック:
        1. evidence.user が KNOWN_GOOD_USERS にあれば drop
        2. evidence.ip が自チーム DHCP レンジなら drop
        3. それ以外は通す
    """
    ev = signal.evidence or {}
    user = ev.get("user", "") or ""
    ip = ev.get("ip", "") or ""
    if user in KNOWN_GOOD_USERS:
        return True
    if _is_team_ip(ip):
        return True
    return False


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
        self.filtered_count: int = 0  # whitelist で drop した累積件数

    def name(self) -> str:
        return "mock-rulebased-v1"

    # ─── 本番 whitelist フィルタ ─────────────────────────
    def filter_known_good(self, signals: list[Signal]) -> list[Signal]:
        """
        配布アカウント / 自チーム IP 由来のシグナルを除外する。
        18_§9「攻撃は別アカウントから来る」前提に基づく。

        この処理は Claude API 呼び出しの前段に置くことで、
        自チームの偵察トラフィックが API コストとして発生するのを防ぐ。
        """
        kept: list[Signal] = []
        dropped = 0
        for s in signals:
            if _is_known_good(s):
                dropped += 1
                continue
            kept.append(s)
        self.filtered_count += dropped
        return kept

    def filter_known_good_logs(
        self,
        logs: list[dict],
        time_window: tuple[str, str] | None = None,
        attacker_ips: set[str] | None = None,
    ) -> list[dict]:
        """
        未分類ログを Claude に渡す前のフィルタ。階層構造:

        1. 配布アカウント / 自チーム IP 由来  → drop (既存)
        2. システムノイズ (pam_unix session 等) → drop (新規)
        3. 残りについて:
           3-1. 時間窓内                    → 保持
           3-2. 時間窓外で attacker_ips 由来  → 保持 (forensic context)
           3-3. 時間窓外で 10.1.129.0/24 由来 → 保持 (§0.5 既侵害前提)
           3-4. それ以外                    → drop

        time_window が None なら時間窓フィルタは無効化 (全件 raw 文字列で残す)。
        attacker_ips が None なら attacker_ips 突合は無効化。

        ts パース失敗 (None) の行は安全側に倒して保持する。
        - 落とすと「年跨ぎ / 異常 format の攻撃 pivot 行」を見逃すリスク
        - Claude には raw が渡るので最終判断は AI に任せる
        """
        # time_window は (start_iso, end_iso) で渡される ISO 8601 文字列。
        # 比較は文字列 lex 比較で OK (ISO 8601 は同 TZ なら lex 順 = 時系列順)
        win_start, win_end = (time_window or (None, None))

        attacker_ips = attacker_ips or set()
        # raw 文字列内の攻撃者 IP 突合用の正規表現を組み立て
        attacker_ip_re: re.Pattern[str] | None = None
        if attacker_ips:
            joined = "|".join(re.escape(ip) for ip in attacker_ips if ip)
            if joined:
                attacker_ip_re = re.compile(rf"\b({joined})\b")

        kept: list[dict] = []
        for log in logs:
            user = log.get("user", "") or ""
            ip = log.get("ip", "") or log.get("src_ip", "") or ""
            raw = log.get("raw", "") or ""

            # Layer 1: 配布アカウント / 自チーム IP
            if user in KNOWN_GOOD_USERS:
                continue
            if _is_team_ip(ip):
                continue

            # Layer 2: システムノイズ
            if raw and _is_noise(raw):
                continue

            # Layer 3: 時間窓 + IP cross-reference
            if win_start is not None and win_end is not None:
                ts = log.get("ts")
                if ts is None:
                    # パース失敗 → 安全側で保持
                    kept.append(log)
                    continue

                in_window = win_start <= ts <= win_end
                if in_window:
                    kept.append(log)
                    continue

                # 窓外でも attacker_ips に含まれるなら保持
                if attacker_ip_re and attacker_ip_re.search(raw):
                    kept.append(log)
                    continue
                # 窓外でも 10.1.129.0/24 (既知侵害 IP) なら保持
                if KNOWN_ATTACKER_IP_RE.search(raw):
                    kept.append(log)
                    continue
                # それ以外の窓外行は drop
                continue

            # time_window 未指定 = 後方互換 (既存 caller 用)
            kept.append(log)
        return kept

    # ─── 提案生成 ────────────────────────────────────────
    def propose_patches(self, signals: list[Signal], unmatched_logs: list[dict] | None = None) -> list[PatchProposal]:
        # 本番 whitelist で配布アカウント / 自チーム IP 由来を drop
        signals = self.filter_known_good(signals)

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
        unmatched_logs: list[dict] | None = None,
    ) -> str:
        if not signals:
            return "新規に検知された異常はありません。"

        lines: list[str] = []
        lines.append(
            f"【MockBackend 判定結果】受信シグナル {len(signals)} 件、"
            f"生成提案 {len(patches)} 件。"
        )
        if self.filtered_count > 0:
            lines.append(
                f"配布アカウント / 自チーム IP 由来として除外: 累積 {self.filtered_count} 件 "
                f"(18_§9 既侵害前提による whitelist 適用)。"
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

    def _handle_webapp_bruteforce(
        self,
        signals: Sequence[Signal],
    ) -> list[PatchProposal]:
        """Web 認証エンドポイントへの brute force: 送信元 IP を block。
        analyzer の _detect_auth_bruteforce で IP 単位の集約検知を経た
        シグナルなので、確度は高い (count >= 10)。
        """
        proposals: list[PatchProposal] = []
        for s in signals:
            ip = s.evidence.get("ip", "")
            if not ip:
                continue
            count = s.evidence.get("count", 0)
            proposals.append(PatchProposal(
                rule_id=_rule_id("webapp-brute-ip", ip, "header", "equals", ip),
                target="/",
                match_type="header",
                match_operator="equals",
                match_value=ip,
                action="block",
                confidence=0.90,
                rationale_ja=(
                    f"Web 認証エンドポイント (wp-login / xmlrpc / admin) への "
                    f"POST が IP {ip} から {count} 回観測されました。"
                    f"閾値 {s.evidence.get('threshold', 10)} を超過したため "
                    f"送信元 IP を block 対象とします。"
                ),
            ))
        return proposals

    def _handle_webapp_scanner(
        self,
        signals: Sequence[Signal],
    ) -> list[PatchProposal]:
        """攻撃ツール UA を block。nikto/wpscan/sqlmap 等の自己申告 UA は
        正規ブラウザでは出ないので確度高い。
        """
        n = len(signals)
        match_value = (
            r"(?i)(nikto|wpscan|sqlmap|nmap|masscan|"
            r"acunetix|nuclei|burp|gobuster|dirbuster)"
        )
        return [PatchProposal(
            rule_id=_rule_id(
                "webapp-scanner-ua", "*", "header", "regex", match_value
            ),
            target="*",
            match_type="header",
            match_operator="regex",
            match_value=match_value,
            action="block",
            confidence=0.85,
            rationale_ja=(
                f"攻撃ツール由来 User-Agent を {n} 件観測しました。"
                f"既知スキャナの自己申告 UA を block 対象とします。"
            ),
        )]

    def _handle_webapp_auth(
        self,
        signals: Sequence[Signal],
    ) -> list[PatchProposal]:
        """単発の auth endpoint アクセス。誤検知が多いので log のみ。
        ブルートに発展した場合は webapp_bruteforce が別途 block を提案する。
        """
        n = len(signals)
        match_value = (
            r"(?i)/(wp-login\.php|xmlrpc\.php|"
            r"administrator/|admin/login|wp-admin/)|/?\?author=\d+"
        )
        return [PatchProposal(
            rule_id=_rule_id(
                "webapp-auth-watch", "*", "path", "regex", match_value
            ),
            target="*",
            match_type="path",
            match_operator="regex",
            match_value=match_value,
            action="log",
            confidence=0.50,
            rationale_ja=(
                f"認証エンドポイント / author 列挙への単発アクセスを "
                f"{n} 件観測しました。誤検知が多いため log のみ。"
                f"集約閾値超過時は webapp_bruteforce で block 提案します。"
            ),
        )]

    def _handle_webapp_dotfile(
        self,
        signals: Sequence[Signal],
    ) -> list[PatchProposal]:
        """dotfile (.env / .git / .my.cnf 等) 直叩きを block。
        正規ブラウザでは到達しない。
        """
        n = len(signals)
        match_value = (
            r"/\.(my\.cnf|env|git/|htaccess|htpasswd|"
            r"ssh/|aws/|npmrc|netrc|DS_Store)"
        )
        return [PatchProposal(
            rule_id=_rule_id(
                "webapp-dotfile", "*", "path", "regex", match_value
            ),
            target="*",
            match_type="path",
            match_operator="regex",
            match_value=match_value,
            action="block",
            confidence=0.95,
            rationale_ja=(
                f"dotfile (.env / .my.cnf / .git 等) への直接アクセスを "
                f"{n} 件観測しました。情報漏洩リスク高、block します。"
            ),
        )]

    def _handle_webapp_upload_php(
        self,
        signals: Sequence[Signal],
    ) -> list[PatchProposal]:
        """uploads/ 配下の PHP/CGI 実行可能ファイル = webshell 高確度。"""
        n = len(signals)
        match_value = (
            r"(?i)/(uploads?|tmp|cache|temp)/"
            r"[^?\s]*\.(php\d?|phtml|phar|pl|cgi|jsp)"
        )
        return [PatchProposal(
            rule_id=_rule_id(
                "webapp-upload-php", "*", "path", "regex", match_value
            ),
            target="*",
            match_type="path",
            match_operator="regex",
            match_value=match_value,
            action="block",
            confidence=0.95,
            rationale_ja=(
                f"uploads/tmp/cache 配下の PHP/CGI 実行可能ファイルを "
                f"{n} 件観測しました。webshell 設置の高確度シグナルとして "
                f"block します。"
            ),
        )]

    def _handle_path_scan(
        self,
        signals: Sequence[Signal],
    ) -> list[PatchProposal]:
        """同一パス連打: rate_limit 提案。誤検知 (CDN warmup 等) もあるので
        block ではなく rate_limit。
        """
        proposals: list[PatchProposal] = []
        for s in signals:
            count = s.evidence.get("count", 0)
            proposals.append(PatchProposal(
                rule_id=_rule_id(
                    "path-scan", s.path, "path", "equals", s.path
                ),
                target=s.path,
                match_type="path",
                match_operator="equals",
                match_value=s.path,
                action="rate_limit",
                confidence=0.65,
                rationale_ja=(
                    f"パス {s.path} への連続アクセスを {count} 回観測しました。"
                    f"偵察 / brute の前段の可能性があり rate_limit を提案します。"
                ),
            ))
        return proposals

    def _handle_dns(
        self,
        signals: Sequence[Signal],
    ) -> list[PatchProposal]:
        """DNS 異常: tag に応じて action を変える。
        unauthorized-update → critical block 提案
        axfr-attempt → block
        amplification → rate_limit
        """
        proposals: list[PatchProposal] = []
        seen_tags: set[str] = set()
        for s in signals:
            tag = s.evidence.get("pattern_tag", "")
            if tag in seen_tags:
                continue
            seen_tags.add(tag)
            if "unauthorized" in tag:
                action: Action = "block"
                conf = 0.95
                msg = "認証なしでの DNS レコード更新成功を検知。即時 block を強く推奨。"
            elif "axfr" in tag:
                action = "block"
                conf = 0.85
                msg = "AXFR (ゾーン転送) 試行を検知。情報漏洩リスク、block 推奨。"
            elif "amplification" in tag:
                action = "rate_limit"
                conf = 0.70
                msg = "DNS amplification 兆候 (ANY クエリ比率高)。rate_limit を提案。"
            else:
                action = "log"
                conf = 0.50
                msg = "DNS 異常パターンを検知 (詳細確認要)。"
            proposals.append(PatchProposal(
                rule_id=_rule_id("dns", tag, "header", "contains", tag),
                target="dns/*",
                match_type="header",
                match_operator="contains",
                match_value=tag,
                action=action,
                confidence=conf,
                rationale_ja=f"[{tag}] {msg}",
            ))
        return proposals

    def _handle_auth(
        self,
        signals: Sequence[Signal],
    ) -> list[PatchProposal]:
        """SSH brute / privesc: 送信元 IP block + 全社注意喚起レベル。"""
        proposals: list[PatchProposal] = []
        for s in signals:
            ip = s.evidence.get("ip", "")
            tag = s.evidence.get("pattern_tag", "")
            count = s.evidence.get("count", 0)
            if ip and "brute" in tag:
                proposals.append(PatchProposal(
                    rule_id=_rule_id(
                        "auth-ssh-brute", ip, "header", "equals", ip
                    ),
                    target="/",
                    match_type="header",
                    match_operator="equals",
                    match_value=ip,
                    action="block",
                    confidence=0.90,
                    rationale_ja=(
                        f"SSH brute force from {ip} ({count} 回失敗)。"
                        f"送信元 IP を block 推奨。"
                    ),
                ))
        return proposals

    def _handle_privesc(
        self,
        signals: Sequence[Signal],
    ) -> list[PatchProposal]:
        """pkexec PwnKit / sudo 不正: critical advisory (人間判断要)。"""
        n = len(signals)
        return [PatchProposal(
            rule_id=_rule_id(
                "privesc-alert", "*", "path", "contains", "privesc"
            ),
            target="*",
            match_type="path",
            match_operator="contains",
            match_value="privesc",
            action="advisory",
            confidence=0.85,
            rationale_ja=(
                f"権限昇格試行 (pkexec/sudo) を {n} 件観測しました。"
                f"既に root 権限取得済みの可能性が高く、"
                f"WAF 層では遮断不能。即時にホスト隔離 + 影響範囲調査を推奨。"
            ),
        )]

    def _handle_mail(
        self,
        signals: Sequence[Signal],
    ) -> list[PatchProposal]:
        """メール異常: open relay / SPF 失敗 / burst を action 別に提案。"""
        proposals: list[PatchProposal] = []
        seen: set[str] = set()
        for s in signals:
            tag = s.evidence.get("pattern_tag", "")
            ip = s.evidence.get("ip", "")
            key = f"{tag}|{ip}"
            if key in seen:
                continue
            seen.add(key)
            if "relay" in tag or "burst" in tag:
                action: Action = "block"
                conf = 0.85
                msg = "open relay 悪用 / 送信 burst を検知。送信元を block 推奨。"
            elif "spf" in tag or "dkim" in tag:
                action = "log"
                conf = 0.55
                msg = "SPF/DKIM 失敗 = なりすまし候補。log 強化。"
            elif "sasl" in tag:
                action = "block"
                conf = 0.80
                msg = "SMTP AUTH brute force。送信元 block 推奨。"
            else:
                action = "log"
                conf = 0.50
                msg = "メール異常パターン (詳細確認要)。"
            proposals.append(PatchProposal(
                rule_id=_rule_id(
                    "mail", tag, ip or "*", "contains", tag
                ),
                target="mail/*",
                match_type="header",
                match_operator="contains",
                match_value=tag if not ip else f"{tag}|{ip}",
                action=action,
                confidence=conf,
                rationale_ja=f"[{tag}] {msg}" + (f" 送信元={ip}" if ip else ""),
            ))
        return proposals

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
        "webapp_auth": _handle_webapp_auth,
        "webapp_bruteforce": _handle_webapp_bruteforce,
        "webapp_scanner": _handle_webapp_scanner,
        "webapp_dotfile": _handle_webapp_dotfile,
        "webapp_upload_php": _handle_webapp_upload_php,
        "path_scan": _handle_path_scan,
        "dns": _handle_dns,
        "auth": _handle_auth,
        "privesc": _handle_privesc,
        "mail": _handle_mail,
    }
