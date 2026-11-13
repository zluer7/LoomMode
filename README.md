# LoomMode

LoomMode 是由 Owner 主导委托、多 AI 角色协作的本地软件研发工作流。Owner 提出目标并保留关键授权。Decision、Promoter、Constraint、Discussant 和 Executor 分担决策、推进、约束、讨论与执行，Host 和 Engine 衔接调用、材料、验证证据和停止节点。

**2.0.0 首发范围**为普通 Windows 用户环境、Codex-only、受管单任务和手动推进。确认任务接受后停在 `COMMIT_AUTHORIZATION`，由操作者正常关闭原 Host。此路径不自动提交 Git。更多模型、连续托管、跨平台和通用恢复仍需验证。

## 开始使用

从 [快速开始](docs/QUICK_START.md) 获取完整工作包，或直接从本仓库离线构建，再在独立环境验证安装。需要 Python 3.11 或更高版本和 Git。真实运行还需兼容的 Codex app-server、有效登录和实际项目授权。

## 文档

- [LoomMode 2.0 正式项目说明书（PDF）](docs/LoomMode_2.0_说明书.pdf)。首页图示涵盖协作设计和探索方向，包含 DeepSeek 与自动执行。2.0.0 的实际支持范围见 [支持说明](docs/SUPPORT.md)。
- [项目概览](docs/PROJECT.md)介绍适用场景与五角色的责任。
- [技术架构](docs/ARCHITECTURE.md)介绍 Host、Engine、角色运行层、权限和执行证据。
- [贡献指南](.github/CONTRIBUTING.md)介绍如何通过 GitHub Issues 和 Pull Requests 参与。

开发者与版权署名为 **争流儿**。项目源码采用 [Apache License 2.0](LICENSE)，名称与标识见 [TRADEMARK](TRADEMARK.md)。
