# LoomMode 2.0.0 快速开始

使用普通 Windows 用户会话和 PowerShell，准备 Python 3.11 或更高版本及 Git。现有构建与安装证据来自 Python 3.13.5。真实运行另需可用的 Codex app-server 和合法登录，具体版本以实际预检为准。工作包同时包含 wheel、工具、配置、角色和定向测试。

## 1. 准备完整工作包

如果你已经取得完整的 2.0.0 Agent-Test 格式工作包，先按可信交接提供的 SHA-256 核对 ZIP，再解压到新目录，从第 2 步开始。

也可以从本仓库构建。在你有权使用的普通本地目录克隆仓库，从仓库根目录运行。离线构建需要预先具备 pip、setuptools（至少 68）和 wheel。复现实测结果使用 Python 3.13.5、pip 25.1、setuptools 72.1.0、wheel 0.45.1。选用尚不存在的输出根，避免覆盖先前的构建或项目。

```powershell
git clone https://github.com/zluer7/LoomMode.git
Set-Location LoomMode
python --version
git --version
python -m pip show setuptools wheel

$workRoot = Join-Path $env:LOCALAPPDATA 'LoomMode-first-use'
$candidateRoot = Join-Path $workRoot 'candidate'
$evidenceRoot = Join-Path $workRoot 'verification'
python -B tools/agent_test_package.py --source . `
  --specification config/agent_test_package.json --target $candidateRoot `
  --evidence (Join-Path $workRoot 'build-evidence') `
  --archive (Join-Path $workRoot 'LoomMode-2.0.0-Agent-Test.zip') `
  --source-date-epoch 1793318400
```

运行前，如果 `$workRoot` 已存在，先改用新的目录名。若从 ZIP 开始，请将 `$candidateRoot` 设为实际解压根，并设置一个独立的 `$evidenceRoot`。仓库的 `SOURCE_MANIFEST.json` 和 `SOURCE_SHA256SUMS` 记录了原始选定源码。构建器按仓库的打包清单选择文件，工作包有自己的完整性清单。可查看 [构建记录](../BUILD.md) 了解原始候选。

## 2. 离线核验和安装

```powershell
python -B "$candidateRoot\tools\agent_test_integrity.py" --directory $candidateRoot
python -m venv "$evidenceRoot\venv"
$testPython = Join-Path $evidenceRoot 'venv\Scripts\python.exe'
& $testPython -m pip install --no-index --no-deps "$candidateRoot\wheels\loommode-2.0.0-py3-none-any.whl"
& $testPython -I -B -c "import loommode, importlib.metadata; from loommode.version import __version__; print(loommode.__file__, __version__, importlib.metadata.version('loommode'))"
```

检查每条命令的结果。导入路径应位于新 venv，两个版本值均为 `2.0.0`。如果需要离线定向测试，可按 [完整安装指南第 2 节](Agent_Test_Install.md#2-offline-install-and-tests-no-model) 运行 `agent_test_verify.py`。该检查使用合成协议进程。

## 3. 配置并启动受管单任务

按 [受管单任务指南](MANAGED_TASK.md) 准备项目、原始 Owner 指令、任务范围、固定测试和资源限制。为 Workspace、Records、Runtime、原始输入和生成输入选择各自的独立目录。工作包附带配置示例，需填写实际项目、路径和授权来源。

先用 `agent_test_setup.py` 生成 inert 配置，检查其来源摘要并运行 `loommode_bootstrap_preflight.py`。实际授权齐备后，在另一个新目录生成 active 配置。按指南用 active binding 启动 canonical 前台 Host，在 `start` 指定 `automatic=false`。逐次调用 `advance`，每次等待当前 Worker 结束并核对状态后继续。

确认原始 Promoter 结果为 `TASK_ACCEPTED` 且节点到达 `COMMIT_AUTHORIZATION` 后，停止推进并正常关闭原 Host。Git 提交由 Owner 按项目需要另行处理。遇到未知调用终态时保留现有状态与改动，避免重放。详见 [支持说明](SUPPORT.md)。
