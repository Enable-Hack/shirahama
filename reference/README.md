# reference/

実装の参考にするコードを置く場所（白浜本体では使わない）。

## dns2_main.rs

セキュリティ・キャンプ Day2 で実装した Rust DNS サーバー（`security-day2/dns2/src/main.rs` のコピー）。

**参考にしたいポイント**:
- `serde_json::json!()` で 1 リクエスト 1 行の JSON Lines を出力
- `chrono::Utc::now().to_rfc3339()` で ISO8601 タイムスタンプ
- `println!` で stdout、`tee dns.log | jq .` で見やすく整形

**白浜での応用**: `scripts/preprocess/_common.py` の `emit()` 関数で同じ流儀を Python 移植。テキストログを JSONL に変換して analyzer.py に渡す。
