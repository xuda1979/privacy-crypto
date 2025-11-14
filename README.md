# privacy-crypto

面向隐私的加密货币原型项目，展示如何构建具备匿名性、抗审查性与可扩展性的链上系统。

> ✅ **What’s new in this PR**
>
> - 新增 **去中心化 P2P 中继层**（基于 FastAPI WebSocket）并实现 **Dandelion++** 传播，显著降低交易源头暴露与定向阻断的可能性  
> - **抗资产冻结/阻断**：协议层完全基于密码学验证，无“冻结密钥/黑名单”入口；中继层只按有效性与费率收录，不区分地址  
> - **效率**：引入 `orjson`（自动回退到 `json`）、轻量级 **紧凑编码**（varint）、去重与 TTL 驱动的 mempool；可选 `uvloop`  
> - **易部署**：新增 `Dockerfile`、`docker-compose.yml`、`scripts/devnet.sh` 一键本地多节点网络；提供 `docs/DEPLOYMENT.md`  
> - **文档**：补充 `docs/PRIVACY.md`、`docs/INNOVATIONS.md`，并在本 README 汇总设计与隐私原理

---

## 1) Why this design preserves privacy & resists blocking

**On-chain privacy**

* **隐匿地址（Stealth addresses）**：收款方为每次收款生成一次性地址，将所有权与公开身份解耦。  
* **Pedersen 承诺 + 范围证明**：金额被承诺隐藏，同时仍可完成守恒校验（输入之和=输出之和+手续费），避免泄露数额。  
* **环签名 + 密钥映像（key image）**：花费者从诱饵集（环）中“匿名”签名，外界无法判断真实花费者，而 key image 阻止同一输出被二次花费。  

> 上述三点是本仓库原型既有的核心密码学组件；本 PR 在网络层继续加强隐私与抗审查能力。详见 `docs/PRIVACY.md`。

**Network privacy & censorship resistance**

* **Dandelion++ 交易传播**：每笔交易先经“茎（stem）”阶段沿随机单路径若干跳，再在“絮（fluff）”阶段向全网扩散。这样能显著弱化“最早看到交易的节点≈交易源”这一侧信道。  
* **中继策略不区分地址**：mempool 只按**有效性**与**费率阈值**接受交易，不存在地址黑名单/白名单代码路径，避免节点层面的“冻结/阻断”。  
* **协议层无管理钥**：共识与验证完全依赖密码学，不存在任何“管理员私钥”可以冻结 UTXO 或拒绝合法交易。  

> **现实边界**：抗审查依赖于网络中存在足够多的多样节点与连接路径；本设计减少阻断面，但并不承诺对所有外部条件具有形式化的不可阻断性。

---

## 2) Quick start

### Local (no Docker)
```bash
pip install -r requirements.txt
# API 节点（保留原有脚本）
./scripts/run_node.sh
# 另启一个终端：启动 P2P 中继（WebSocket + Dandelion++）
./scripts/run_p2p.sh
# 桌面端钱包 GUI（Tkinter）
python -m src.wallet_gui
```
环境变量：
- `HOST` / `PORT`：API 监听（默认 `0.0.0.0:8000`）
- `P2P_HOST` / `P2P_PORT`：P2P 监听（默认 `0.0.0.0:9000`）
- `PEERS`：逗号分隔的对等端，例如：`ws://node1:9000,ws://node2:9000`
- `MIN_FEE_RATE`：mempool 最低费率（默认 `0`）

### Docker (single node)
```bash
docker build -t privacy-crypto .
docker run --rm -p 8000:8000 -p 9000:9000 \
  -e HOST=0.0.0.0 -e PORT=8000 \
  -e P2P_HOST=0.0.0.0 -e P2P_PORT=9000 \
  privacy-crypto
```

### Docker Compose (multi-node devnet)
```bash
docker compose up --build
# 可选：将 p2p 服务扩容为 4 个节点
docker compose up --build --scale p2p=4
```
详见 `docs/DEPLOYMENT.md` 与 `scripts/devnet.sh`。

### Wallet GUI 功能

`src/wallet_gui.py` 提供了一个极简 Tkinter 图形界面，帮助测试者无需编写脚本即可：

- 生成新钱包、查看观测/花费密钥与导出的隐匿地址；
- 根据手工输入的私钥恢复钱包；
- 粘贴任意隐匿地址以查看解析后的公开密钥；
- 粘贴交易 JSON，快速检查交易是否属于当前钱包并解密金额。

该 GUI 仅依赖标准库 Tkinter，可在本地运行 `python -m src.wallet_gui` 启动。

### 测试 / 验证

为了确认 GUI 引入后没有破坏既有逻辑，可在本地运行完整的自动化测试并做一次手动 GUI 检查：

```bash
pytest                       # 覆盖 API、钱包、密码学与 P2P 逻辑
python -m src.wallet_gui     # 手动验证 GUI 操作流程
```

---

## 3) Using the API & the P2P relay together

典型流程（与原有 API 兼容）：
1. `POST /wallets` 创建钱包（观测/花费密钥分离、导出地址）
2. `POST /transactions` 生成环签名交易（指定 `ring_size`）
3. `POST /mine` 将待处理交易打包到新区块
4. 可选：通过 P2P 提交交易以获得网络层隐匿传播  
   ```bash
   curl -X POST http://localhost:9000/p2p/submit \
     -H 'content-type: application/json' \
     -d '{"tx": { ... raw tx json ... }}'
   ```
5. `GET /p2p/peers` 查看对等端与中继状态

---

## 4) What changed in code (high-level)

**新增**
- `src/p2p/`：最小可用 P2P 实现（FastAPI WebSocket + PyNaCl 加密管道 + Dandelion++ 路由 + 去重/TTL mempool）
- `src/utils/compact.py`：varint 紧凑编码/解码
- `src/utils/serialization.py`：统一的规范化哈希工具，支持审计证明签名
- `scripts/run_p2p.sh`、`scripts/devnet.sh`
- 容器化：`Dockerfile`、`docker-compose.yml`
- 文档：`docs/PRIVACY.md`、`docs/INNOVATIONS.md`、`docs/DEPLOYMENT.md`

**效率相关**
- `orjson` 优先用于编解码（自动降级到标准库 `json`）
- 可选 `uvloop`（非 Windows）
- 内置去重（seen-set）、按费率的简易 mempool 准入与过期

**抗审查设计钩子**
- mempool 准入仅依赖**交易有效性**与**最小费率**；没有任何地址名单或管理员开关
- Dandelion++ 传播随机化路径与延时，降低“先见”攻击可行性
- **选择性披露（Selective disclosure）**：交易创建时自动生成 `audit_bundle`（内含承诺盲因子、金额与观测公钥的 Schnorr 签名），可供用户在需要时向受信方证明资金来源，贴合 FATF Travel Rule 与 MiCA 合规诉求

---

## 5) Threat model & limitations

* 这是演示性质原型，密码学与网络实现尚未经过第三方审计。  
* Dandelion++ 降低但不能消灭网络层关联攻击；使用 Tor/I2P/混合拓扑可进一步增强（可在未来版本增加 SOCKS5 代理支持）。  
* PoW 与节点多样性仍是可用性的关键，请避免单点部署。

---

## 6) Repository status & original workflow (unchanged)

本仓库原有的 API 与开发流程保持不变（`./scripts/run_node.sh` 启动 FastAPI / OpenAPI / Swagger UI；工作量证明、隐匿地址、Pedersen 承诺、环签名与 key image、钱包扫描等核心模块仍可按原方式使用）。新引入的 P2P 与部署脚本是 **增量** 组件，不破坏现有 API。详见上文 Quick start。

更多细节请阅读：
* `docs/PRIVACY.md` — 隐私与抗审查原理、威胁模型  
* `docs/INNOVATIONS.md` — 本次引入的创新点清单与未来工作  
* `docs/DEPLOYMENT.md` — Docker / Compose / 本地多节点网络
