# 2.0.0 受管单任务指南

先按 [快速开始](QUICK_START.md) 构建或下载完整工作包并完成离线安装。下文引用构建时安装指南的操作章节，其第 5 节的 `rc.3 package` 指首次引入人工停点的候选。对应步骤适用于当前 2.0.0 工作包。采用 GitHub Release 时，用发布页的 `SHA256SUMS.txt` 及包内清单核验，旧交接件 `HANDOFF.json` 只用于原始交接流程。

## 准备项目与配置

1. 在普通 Windows 用户会话中准备独立的 Workspace、Records、Runtime、原始输入及新的生成输入目录。用一项有明确可改文件和固定测试的小任务开始。取得项目 Owner 的明确授权，约定实际项目、任务、资源、时限及停止点。完整输入说明见 [原指南第 3 节](Agent_Test_Install.md#3-prepare-fresh-isolated-work-only-after-later-authorization)。
2. 参照工作包的 `config/agent_test_request.example.json` 和 `config/agent_test_resource.example.json` 填写实际请求。示例含无效占位值。使用合法、兼容且已登录的 Codex app-server。按 [原指南第 4 节](Agent_Test_Install.md#4-generate-inert-pins-review-then-explicitly-activate) 生成 inert 配置、检查来源并运行只读预检。核实实际授权后，在另一新目录生成 active 配置。

## 启动、逐次推进与关闭

按 [原指南第 5 节](Agent_Test_Install.md#5-real-foreground-canonical-run-and-actual-notice-relay-separate-authorization) 使用 active binding 预检并启动 canonical 前台 Host。在同一实例上读取状态与实际 revision，发送 `start` 时指定 `automatic=false`。每次只发一个 `advance`，等待原 Worker 结束并核对实际状态。保留真实通知转达、回执和原审阅窗口。

确认原始 Promoter 结果为 `TASK_ACCEPTED`、节点为 `COMMIT_AUTHORIZATION` 且 `local_commit_authorized=false` 时，停止推进。按 [原指南第 6 节](Agent_Test_Install.md#6-close-and-hand-back-raw-evidence) 正常关闭原 Host，核对 Writer 释放及交付证据。对未知终态保留现场、运行记录和计量账本。更多环境与能力边界见 [支持说明](SUPPORT.md)。
