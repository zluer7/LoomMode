# 2.0.0 支持范围

| 范围 | 可用能力与验证条件 |
| --- | --- |
| 环境 | 普通 Windows 本地用户会话。源码要求 Python 3.11+，既有构建和安装使用 3.13.5。Git 与兼容的 Codex app-server 由使用者自行准备。 |
| 流程 | Codex-only 受管单任务，显式项目授权和固定测试，人工逐次推进。任务接受后停在 `COMMIT_AUTHORIZATION` 并正常关闭 Host，流程不自动提交 Git。 |
| 既有验证 | 2.0.0 已有可重复离线构建、隔离安装、模块来源与定向测试证据。既有同机真实单任务记录覆盖任务接受及手动停点。 |
| 实验方向 | Multi-AI、第三方后端与角色路由有实现及有限历史验证，尚未纳入首发支持。独立第二物理设备、通用恢复或迁移、多任务无人值守、跨平台与任意 Codex 版本兼容性仍待验证。 |

已知限制包括历史 HTTP 回退及请求超时、原生命令正文审计不完整，以及实际模型费用未独立计量。本地 Caller relay 记录可核对的本地转达材料。对未知调用终态，应保留现有状态、证据和文件改动。

进一步阅读 [快速开始](QUICK_START.md)、[已知问题](Retest_KNOWN_ISSUES.md) 和 [2.0.0 候选验证记录](Agent_Test_Release_Notes.md)。欢迎在 [GitHub Issues](https://github.com/zluer7/LoomMode/issues) 提交经过脱敏的可复现问题。
