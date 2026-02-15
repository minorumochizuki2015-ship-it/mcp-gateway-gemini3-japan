---
title: "MCP Gateway — Gemini 3で13,000+ MCPサーバーのセキュリティ課題を解決する"
emoji: "🛡️"
type: "idea"
topics: ["gch4", "gemini", "mcp", "security", "agenticai"]
published: false
---

## 概要：AIエージェント時代のセキュリティ空白地帯

AIエージェントが爆発的に普及する中、MCP（Model Context Protocol）エコシステムは **17,500以上のサーバー** に急拡大しました（[mcp.so](https://mcp.so/)、2026年2月時点）。しかし、**標準的なセキュリティレイヤーは存在しません**。

2026年2月、セキュリティ研究者チーム [Koi Security](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html) がOpenClaw ClawHubマーケットプレイスを監査し、**2,857スキル中341件（12%）が悪意あるスキル** であることを発見しました。学術研究でも、12種類の攻撃カテゴリにおいて **94%の攻撃成功率** が報告されています（[Zhao et al., arxiv:2509.24272](https://arxiv.org/abs/2509.24272)）。

**MCP Gateway** は、この「セキュリティ空白地帯」を **Gemini 3の推論能力** で埋める、初のAI駆動型セキュリティゲートウェイです。

### 対象ユーザー

- AIエージェントを業務利用する企業のセキュリティ担当者
- MCPサーバーを開発・運用するエンジニア
- Claude Code / Gemini CLI / ChatGPT等のAIクライアントユーザー

---

## 課題：なぜ既存のツールでは不十分か

### 3つのMCP固有攻撃

| 攻撃 | 手法 | 既存ツールの限界 |
|------|------|-----------------|
| **ツールシャドウイング** | `read_fi1e`（数字の1）で `read_file` を偽装 | ルールベースでは文字レベル類似性を検出困難 |
| **シグネチャクローキング** | 登録後にツール説明文を変更（「分析データ一覧」→「システムコマンド実行」） | 静的スキャナは初回承認時のみチェック |
| **ベイト＆スイッチ** | 無害な説明 + 悪意あるスキーマ（`password`, `api_key`フィールド） | 説明文とスキーマの意味的不一致を検出不可 |

### 検出率の比較

| 手法 | 精度 (Precision) | 再現率 (Recall) | F1スコア |
|------|-----------------|----------------|----------|
| ハッシュベース（VirusTotal等） | 高 | 極低 | — |
| ルールベース（~3%検出率） | 0.917 | 0.846 | 0.880 |
| **Gemini 3エージェント（本作品）** | **1.000** | **1.000** | **1.000** |

26ケースの固定コーパス（良性13 + 悪性13）による再現可能なベンチマーク。

---

## 解決策：Gemini 3による6層セキュリティパイプライン

### アーキテクチャ

```
AIクライアント (Claude Code / Gemini CLI / ChatGPT)
         │
    MCP Gateway（FastAPI + Gemini 3）
    ┌────┼────┐────────┐────────┐────────┐
    │    │    │        │        │        │
  AI   Semantic RedTeam  Causal  Agent  Audit
Council Scanner Gen+Eval  Web   Scan   QA Chat
         │    │   Sandbox  │
         └────┴────┴────┴────┘
              Evidence Trail (JSONL)
```

### 7つのGemini 3統合ポイント

すべてのコンポーネントが **Gemini 3固有の機能** を活用しています：

| # | コンポーネント | Gemini 3機能 | 役割 |
|---|-------------|-------------|------|
| 1 | **AI Council** | Thinking Level (high) + Google Search + 構造化出力 | サーバー単位の許可/拒否判定 |
| 2 | **Semantic Scanner** | Thinking Level (high) + Google Search + 構造化出力 | ツール定義の意味的分析 |
| 3 | **RedTeam Generator** | Thinking Level (low) + 構造化出力 | 攻撃シナリオの高速生成 |
| 4 | **RedTeam Evaluator** | Thinking Level (high) + 構造化出力 | ペイロード安全性評価 |
| 5 | **Causal Web Sandbox** | **URL Context + Google Search + Thinking + 構造化出力** | URLの直接訪問・多角的分析 |
| 6 | **Agent Scan** | **Function Calling + Thinking (high) + Google Search + マルチターン** | 自律型セキュリティエージェント |
| 7 | **Audit QA Chat** | Thinking Level (high) + 構造化出力 | 判定理由の自然言語説明 |

### 「Gemini 3でなければできない」機能

**Causal Web Sandbox** は、Gemini 3の **URL Context** 機能でURLを直接訪問し、**Google Search** でリアルタイム脅威情報を取得し、**Thinking Level** で因果関係を推論します。この3機能の組み合わせは他のLLMでは実現できません。

**Agent Scan** では、Gemini 3が **Function Calling** で自律的にセキュリティツールを選択・実行します。`.com`ドメインにはDGAチェックのみ、`.tk`ドメインにはフルスキャン——固定パイプラインではなく、脅威に応じた柔軟な調査を実現します。

---

## NEW: MCP透過型セキュリティプロキシ

**ゼロ設定で任意のMCPサーバーを保護** する透過型プロキシを新たに実装しました。

```bash
# 1コマンドでMCPサーバーを保護
python -m src.mcp_gateway.mcp_proxy \
  --gateway-url http://localhost:4100 \
  --fail-closed \
  -- npx -y @modelcontextprotocol/server-filesystem .
```

3スレッドアーキテクチャ（client→server / server→client / stderr drain）により、MCPクライアントとサーバー間のstdio通信を全二重で中継しつつ、`tools/call`リクエストをGateway APIで検査します。AIクライアント側の設定変更は不要です。

---

## 実装の特徴

### テストスイート

**449テスト** が全パス。セキュリティ製品として信頼性を担保しています。

### ダッシュボードUI（日英バイリンガル）

9ページの管理UIを実装。日本語/英語の切り替えに対応しています。

| ページ | 機能 |
|--------|------|
| Dashboard | KPIカード、攻撃検出タイムライン、ライブパイプラインデモ |
| Web Sandbox | URL入力 → DOM分析 → Gemini判定をリアルタイム表示 |
| Audit Log | 判定根拠の証跡ビュー + **Audit QA Chat（Gemini 3）** |
| Billing | トークン消費量・APIコール数・コスト試算 |

### Google Cloudデプロイ

```bash
# Cloud Build + Cloud Run（東京リージョン）
gcloud builds submit --config=cloudbuild.yaml
```

Dockerfile + cloudbuild.yaml で **ワンコマンドデプロイ** 。Cloud Run上で自動スケーリング（最大3インスタンス）。

---

## デモ動画

<!-- YouTube動画URL：TODO: アップロード後に差し替え -->
@[youtube](VIDEO_ID_HERE)

ダッシュボードからの **Live Pipeline Demo** で、6層パイプラインの全フローを30秒で体験できます：
1. MCPサーバー登録 → 2. セキュリティスキャン → 3. AI Council判定 → 4. 攻撃検出 → 5. Web Sandbox分析 → 6. ツール呼び出しインターセプション

---

## システム構成図

![Architecture Overview](https://raw.githubusercontent.com/minorumochizuki2015-ship-it/mcp-gateway-gemini3-japan/main/docs/images/architecture-overview.svg)

---

## 技術スタック

| レイヤー | 技術 |
|---------|------|
| **AI推論** | Gemini 3 Flash Preview（Google AI Studio） |
| **バックエンド** | Python 3.12 / FastAPI / Uvicorn |
| **フロントエンド** | Vanilla HTML/CSS/JS（バイリンガルUI） |
| **デプロイ** | Cloud Run / Cloud Build / Docker |
| **セキュリティ** | SSRF防止 / プロンプトインジェクション防御 / 構造化証跡 |

---

## まとめ

MCPエコシステムの急拡大に対し、セキュリティは後回しにされています。MCP Gatewayは **Gemini 3の推論能力** を核に、**allow/denyの二値判定ではなく、構造化された証跡** でセキュリティ判断を **監査可能** にします。

**17,500+サーバー × 94%攻撃成功率** という現実に対し、**F1スコア1.000** の検出精度と **449テスト** の品質保証で応えます。

---

**GitHub**: https://github.com/minorumochizuki2015-ship-it/mcp-gateway-gemini3-japan
**デプロイURL**: <!-- TODO: Cloud Run URL -->
