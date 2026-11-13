# LoomMode 2.0.0 快速开始

使用普通 Windows 用户会话和 PowerShell，准备 Python 3.11 或更高版本。源码获取与受管任务需要 Git。现有构建与安装证据来自 Python 3.13.5。真实运行另需可用的 Codex app-server 和合法登录，具体版本以实际预检为准。

## 方式一：从 GitHub 源码安装

在你有权使用的普通本地目录克隆仓库，从仓库根目录运行。离线构建需要预先具备 pip、setuptools（至少 68）和 wheel。复现实测结果使用 Python 3.13.5、pip 25.1、setuptools 72.1.0、wheel 0.45.1。若 `$workRoot` 已存在，先改用新的目录名。

```powershell
git clone -c core.autocrlf=false https://github.com/zluer7/LoomMode.git
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

`-c core.autocrlf=false` 只用于新检出，保留构建器校验的原始文件字节，包括 `LICENSE`。也可下载 GitHub 的 `Source code (zip)`，解压后进入源码根目录，从 `python --version` 开始。构建器按选定源码清单生成工作包及同名 `.sha256`。仓库的 `SOURCE_MANIFEST.json` 与 `SOURCE_SHA256SUMS` 保留原始选定源码记录，详细工具链见 [历史构建记录](../BUILD.md)。构建完成后，从 [离线安装与核验](#离线安装与核验) 继续。

## 方式二：下载正式 ZIP 或 wheel

版本发布后，在 [GitHub Releases](https://github.com/zluer7/LoomMode/releases) 找到 `v2.0.0`，从 Assets 下载所需文件及 `SHA256SUMS.txt`。在下载目录执行 `Get-FileHash -Algorithm SHA256 -LiteralPath <已下载的文件>`，逐个与同一 Release 的校验值比对。校验一致后再解压或安装。

- `LoomMode-2.0.0-Agent-Test.zip` 是完整工作包，包含 wheel、工具、配置、角色和定向测试。`Agent-Test` 是构建格式沿用的名称。选用 Release Assets 中的这个 ZIP。GitHub 自动生成的 `Source code (zip)` 走源码路线。
- `loommode-2.0.0-py3-none-any.whl` 是 Python 包，与 ZIP 内的 wheel 字节相同。已有完整 ZIP 时无需再下载。只有 wheel 时，可以验证安装及导入，受管任务仍需要完整工作包提供的工具和配置。

将 ZIP 解压到新目录，把 `$candidateRoot` 指向含 `MANIFEST.json` 的解压根，并为 `$evidenceRoot` 选择一个独立的新目录。ZIP 内部分文件保留构建时的候选状态和交接措辞。本流程使用 Release 校验文件与包内 `MANIFEST.json`、`SHA256SUMS`，无需历史交接件 `HANDOFF.json`。真实任务的配置见 [受管单任务指南](MANAGED_TASK.md)。

包内 `MANIFEST.json` 的 `release=false` 表示构建时生成的是待发布的冻结产物，GitHub 发布状态以 Release 页面为准。`runtime_acceptance=false` 表示该构建清单未记录真实项目运行验收，安装和只读预检可以照常进行。保留这些字段原值，才能继续校验原始 ZIP 和清单。

## 离线安装与核验

使用完整工作包时，先运行包内完整性检查，再设置 `$wheelPath`。

```powershell
python -B "$candidateRoot\tools\agent_test_integrity.py" --directory $candidateRoot
$wheelPath = Join-Path $candidateRoot 'wheels\loommode-2.0.0-py3-none-any.whl'
```

只安装独立 wheel 时，先按上文校验下载文件，将 `$wheelPath` 指向该文件的绝对路径，并为 `$evidenceRoot` 选择一个独立的新目录。随后执行以下命令。ZIP 和 wheel 均需用 Python 环境与以下步骤完成安装，受管运行还需项目配置。

```powershell
python -m venv "$evidenceRoot\venv"
$testPython = Join-Path $evidenceRoot 'venv\Scripts\python.exe'
& $testPython -m pip install --no-index --no-deps $wheelPath
& $testPython -I -B -c "import loommode, importlib.metadata; from loommode.version import __version__; print(loommode.__file__, __version__, importlib.metadata.version('loommode'))"
```

检查每条命令的结果。导入路径应位于新 venv，两个版本值均为 `2.0.0`。完整工作包可运行 `python -B "$candidateRoot\tools\loommode.py" --help` 核对命令入口。需要离线定向测试时，参考 [构建时安装指南第 2 节](Agent_Test_Install.md#2-offline-install-and-tests-no-model) 的 `agent_test_verify.py` 示例。该检查使用合成协议进程。

## 交给 Codex 协助安装

把源码目录，或下载的 ZIP／wheel 和 `SHA256SUMS.txt` 交给 Codex，复制 [INSTALL_WITH_CODEX.txt](../INSTALL_WITH_CODEX.txt) 中的提示词。两种路线都可以用它来完成安装准备。

## 配置并启动受管单任务

按 [受管单任务指南](MANAGED_TASK.md) 准备项目、原始 Owner 指令、任务范围、固定测试和资源限制。为 Workspace、Records、Runtime、原始输入和生成输入选择各自的独立目录。工作包附带配置示例，需填写实际项目、路径和授权来源。

先用 `agent_test_setup.py` 生成 inert 配置，检查其来源摘要并运行 `loommode_bootstrap_preflight.py`。实际授权齐备后，在另一个新目录生成 active 配置。按指南用 active binding 启动 canonical 前台 Host，在 `start` 指定 `automatic=false`。逐次调用 `advance`，每次等待当前 Worker 结束并核对状态后继续。

确认原始 Promoter 结果为 `TASK_ACCEPTED` 且节点到达 `COMMIT_AUTHORIZATION` 后，停止推进并正常关闭原 Host。Git 提交由 Owner 按项目需要另行处理。遇到未知调用终态时保留现有状态与改动，避免重放。详见 [支持说明](SUPPORT.md)。
