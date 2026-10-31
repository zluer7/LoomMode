# LoomMode 2.0.0 待发布候选：从这里开始

状态：OWNER_ACCEPTANCE_PENDING / PUBLICATION_NOT_AUTHORIZED。
开发者与版权展示名：争流儿；代码许可 Apache License 2.0。
这是独立新构建，不是 rc.3 改名；旧候选和失败证据保留。
LoomMode 不设独立官网；真实 GitHub 仓库获批建立后作为公开入口，目前不虚构 URL。

1. 核对 `LoomMode-2.0.0-Release-Candidate-Handoff.zip` 及同名 `.sha256`。
   解压后核对 HANDOFF.json、`LoomMode-2.0.0-Agent-Test.zip` 及核心校验文件。
   核心包仍使用现有 Agent-Test 格式；版本为 2.0.0。
2. 解压到新的目录，阅读 README.md、AGENT_INSTALL.md、RELEASE_NOTES.md、
   KNOWN_ISSUES.md。运行 `python -B tools/agent_test_integrity.py --directory <核心目录>`。
3. 按安装指南创建全新 venv，离线安装 `wheels/loommode-2.0.0-py3-none-any.whl`，
   保存导入来源/版本结果。采用普通 Windows 用户环境、独立证据目录和短临时根。
4. 定向离线 runner 只调用合成夹具，不启动真实模型。真实项目/模型使用需你明确授权
   目标、文件、固定测试、合法 Codex 路径、限额和截止时间；示例配置不产生授权。
5. 首个支持范围为 Windows / Codex-only / 受管单 Task / manual / 无 Git 自动提交。
   首次 START 选 `automatic:false`，每次一个 advance，等待原 worker joined。
   正常窗口、Notice 与 Caller Relay 仍须保留，不修改保护或缩短窗口。
6. 实际 TASK_ACCEPTED 后停在 COMMIT_AUTHORIZATION，不再 advance，正常关闭同一 Host，
   核实 Writer、lease、worker、owned processes 释放。Host CLOSED 不等于任务完整收尾、
   Git checkpoint、Stage/Owner 接受或关闭后恢复许可。

历史 P012、transport flags、独立物理设备身份及通用恢复限制见 KNOWN_ISSUES.md。
原 FAILED/UNKNOWN 不因新包、模型或编号被重放/退款/清零。不复制凭据、旧State/Grant、
个人配置或无关项目；不改共享 ACL。不自动 Git、发布或进入下一 Task。
报告按 TEST_REPORT_TEMPLATE.md / ISSUES_TEMPLATE.md 写实际结果，脱敏副本与原件哈希分开。
