# 技术架构

LoomMode 将角色的专业判断、Engine 的节点控制、Host 的实际运行核验放在不同组件中。2.0.0 的首发入口使用本地 Python 工具与 Codex app-server。

| 组件 | 责任与源码入口 |
| --- | --- |
| 首次使用配置 | [agent_test_setup.py](../tools/agent_test_setup.py) 读取真实请求并生成带摘要的配置。默认生成 inert 输入。 |
| Canonical Host | [loommode.py](../tools/loommode.py) 进入 [canonical](../src/loommode/host/canonical.py) 和 [bootstrap](../src/loommode/host/bootstrap.py)，依据 binding 核验工作区、加载 factory、管理 Writer 和 Host 实例。 |
| Engine | [engine.py](../src/loommode/workflow/engine.py) 与 [transitions.py](../src/loommode/workflow/transitions.py) 维护工作节点、合法动作和产物交接。 |
| 角色与 Codex | [角色运行层](../src/loommode/roles/runtime.py) 组合角色职责、当前活动与指定原文，[Codex adapter](../src/loommode/codex/adapter.py) 和 [app-server](../src/loommode/codex/app_server.py) 连接模型通路。 |
| 受管实施与验证 | [Executor 运行层](../src/loommode/workflow/executor.py)、[Native 管理](../src/loommode/host/managed_native.py) 和 [固定测试](../src/loommode/tools/test_runner.py) 衔接受限实施、测试及结果。 |
| 状态与证据 | [状态](../src/loommode/workflow/state.py) 保存进度，[产物](../src/loommode/workflow/artifacts.py) 保存正式材料及引用，[失败证据](../src/loommode/workflow/failure_evidence.py) 记录已知事实和未知终态。 |

## 一次任务的流转

Promoter 提出任务意图，Constraint 草拟可执行范围，Discussant 独立审视，Constraint 处理意见并定稿。Executor 在实际授权和工具约束下实施、自测及报告。Promoter 核对结果和证据，决定接受或有界补正。Decision 统筹重要取舍和异常。正式报告、测试回执和任务接受分别记录。

Host 在绑定的工作区和上下文核对授权来源、可用资源及 Writer 租约。Engine 根据节点验证角色返回及必要产物。摘要用于绑定字节身份，Owner 授权和测试结果仍须来自相应原件。遇到未知副作用时保留状态和证据，停止受影响的执行。

首发运行以手动单任务为界。读到真实 `TASK_ACCEPTED` 且到达 `COMMIT_AUTHORIZATION` 时停止推进并正常关闭 Host。跨设备兼容、连续托管、第三方后端和通用恢复的验证边界见 [支持说明](SUPPORT.md)。
