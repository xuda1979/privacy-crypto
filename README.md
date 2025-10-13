# privacy-crypto

面向隐私的加密货币原型项目，展示如何构建具备匿名性与可扩展性的链上系统。

## 功能特性

- 基于工作量证明（Proof-of-Work）的区块链，实现确定性哈希与区块谱系校验。
- 采用隐匿地址、Pedersen 承诺、加密金额与带有密钥映像的环签名，确保交易隐私并防止双重支付。
- 钱包工具区分观察密钥与花费密钥，支持生成一次性地址，并可解密收到的隐匿输出以导出一次性花费密钥。
- `WalletScanner` 模块可扫描链上区块与待处理交易，聚合钱包的来款与花费记录，辅助构建完整的余额视图。

## 开发指南

### 环境依赖

首先安装项目所需的 Python 依赖：

```bash
pip install -r requirements.txt
```

项目主要依赖 [`ecdsa`](https://pypi.org/project/ecdsa/) 与 [`PyNaCl`](https://pypi.org/project/PyNaCl/) 来实现底层密码学操作。

### 运行测试

执行完整的单元测试套件：

```bash
pytest
```

为了保持测试的执行速度，创世区块的难度被刻意设置得较低。

### 启动 HTTP API

项目基于 [FastAPI](https://fastapi.tiangolo.com/) 提供 HTTP API，涵盖区块链访问、钱包管理以及交易提交等端点。本地启动服务：

```bash
./scripts/run_node.sh
```

 
默认监听地址为 `0.0.0.0:8000`。如需变更监听地址或端口，可设置 `HOST`、`PORT` 环境变量。服务启动后，可在 `http://<host>:<port>/docs` 访问自动生成的 OpenAPI 描述与交互式 Swagger UI。

典型的 API 使用流程如下：

1. `POST /wallets`：创建新钱包。响应体中包含供后续调用使用的 `wallet_id` 与导出的公开地址。
2. `GET /wallets`：列出现有钱包，但不会泄露私钥信息。
3. `POST /transactions`：从某个钱包向另一个钱包发起带环签名保护的交易，其中 `ring_size` 参数决定参与的诱饵钱包数量。
4. `POST /mine`：挖掘挂起交易，生成新区块。
5. `GET /chain` 与 `GET /pending`：查看链上状态与待处理交易。

## 迈向生产级隐私加密货币的路线图

当前仓库演示了隐私币所需的核心密码学组件，但仍定位为原型。`docs/PROJECT_COMPLETION_PLAN.md` 汇总了迈向可部署、类比特币的隐私货币所需补齐的架构差距，以及为交付安全节点、完善钱包体验与运维工具所规划的里程碑。
 
The helper script creates (or reuses) a virtual environment in `.venv`, installs
the Python dependencies, and starts the node with
[uvicorn](https://www.uvicorn.org/). By default the server listens on
`0.0.0.0:8000`. Override the `HOST`, `PORT`, `PYTHON`, or `VENV_DIR` environment
variables if you need to customise how the service is launched. The generated
OpenAPI schema and interactive Swagger UI are available at
`http://<host>:<port>/docs` once the server is running.

The API supports the following workflow:

1. `POST /wallets` to create a new wallet. The response includes a `wallet_id`
   used to reference the wallet in future calls alongside the exported public
   address.
2. `GET /wallets` to enumerate known wallets without exposing private keys.
3. `POST /transactions` to create a ring-signature protected transaction from
   one wallet to another. The `ring_size` parameter determines how many decoy
   wallets participate in the ring.
4. `POST /mine` to mine pending transactions into a new block.
5. `GET /chain` and `GET /pending` to inspect chain state and queued
   transactions.
 
