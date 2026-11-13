# LoomMode

LoomMode 是由 Owner 主导委托、多 AI 角色协作的本地软件研发工作流。Owner 提出目标并保留关键授权。Decision、Promoter、Constraint、Discussant 和 Executor 分担决策、推进、约束、讨论与执行，Host 和 Engine 衔接调用、材料、验证证据和停止节点。

**2.0.0 首发范围**为普通 Windows 用户环境、Codex-only、受管单任务和手动推进。确认任务接受后停在 `COMMIT_AUTHORIZATION`，由操作者正常关闭原 Host。此路径不自动提交 Git。更多模型、连续托管、跨平台和通用恢复仍需验证。

## 开始使用

- **从 GitHub 源码安装**适合开发者与贡献者。克隆本仓库，离线构建完整工作包，再在独立环境安装验证。 [源码安装步骤](docs/QUICK_START.md#方式一从-github-源码安装)
- **从 Release 下载工作包**适合首次体验。发布后，从 [GitHub Releases](https://github.com/zluer7/LoomMode/releases) 下载完整 ZIP 和 `SHA256SUMS.txt`，或按需下载独立 wheel。ZIP 附带运行所需的工具、配置、角色和同一 wheel。单独的 wheel 适用于安装 Python 包。可将源码目录或下载文件交给 Codex，使用 [可复制的安装提示词](docs/QUICK_START.md#交给-codex-协助安装)。

在普通 Windows 用户环境使用 Python 3.11 或更高版本。源码获取及受管任务还需 Git。真实任务另需兼容的 Codex app-server、有效登录和项目授权。

## 文档

- [LoomMode 2.0 正式项目说明书（PDF）](docs/LoomMode_2.0_说明书.pdf)。首页图示涵盖协作设计和探索方向，包含 DeepSeek 与自动执行。2.0.0 的实际支持范围见 [支持说明](docs/SUPPORT.md)。
- [项目概览](docs/PROJECT.md)介绍适用场景与五角色的责任。
- [技术架构](docs/ARCHITECTURE.md)介绍 Host、Engine、角色运行层、权限和执行证据。
- [贡献指南](.github/CONTRIBUTING.md)介绍如何通过 GitHub Issues 和 Pull Requests 参与。

开发者与版权署名为 **争流儿**。项目源码采用 [Apache License 2.0](LICENSE)，名称与标识见 [TRADEMARK](TRADEMARK.md)。本仓库是项目的 GitHub 入口。

### 历史构建资料

[构建记录](BUILD.md)、`SOURCE_MANIFEST.json`、`SOURCE_SHA256SUMS`、根目录 `CONTRIBUTING.md` 和 `docs/Agent_Test_*`、`docs/Retest_*` 保留了 2.0.0 原始构建与测试交接。部分链接按 ZIP 解压后的目录布局编写。贡献请使用上方现行指南，安装请从 [快速开始](docs/QUICK_START.md) 进入。早期交接中出现的 `HANDOFF.json`、rc.3 和候选状态描述用于追溯构建。内部过程报告与验证日志留在项目记录中。
