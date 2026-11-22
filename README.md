# 中兴微固件工具箱
中兴微设备编程器固件：在Windows电脑上查看、拆分、编辑、重打包固件，无需依赖其他工具或虚拟机。

## 下载
- [GitHub Releases · 正式版本](https://github.com/603717321/zxw-firmware-toolbox/releases)：如果已有带版本标签的发布，可在这里选择安装包；若暂无 Release，请使用下方的 Actions 构建。
- [GitHub Actions · 构建列表](https://github.com/603717321/zxw-firmware-toolbox/actions/workflows/build.yml)：选择最近一次成功运行，在页面底部 **Artifacts** 下载。
- [已验证的四平台构建 #1](https://github.com/603717321/zxw-firmware-toolbox/actions/runs/45020026722)：下表为该次运行的产物链接。

| 平台 | 构建下载 | 包内内容 |
| --- | --- | --- |
| Windows x64 | [windows-x64](https://github.com/603717321/zxw-firmware-toolbox/actions/runs/45020026722/artifacts/14753636356) | 64 位 `.exe` |
| Windows 旧系统兼容版 x86 | [windows-legacy-x86](https://github.com/603717321/zxw-firmware-toolbox/actions/runs/45020026722/artifacts/14753636374) | 32 位 `.exe`；Windows 7 SP1 为兼容目标，未实机验收 |
| Linux x64 | [linux-x64](https://github.com/603717321/zxw-firmware-toolbox/actions/runs/45020026722/artifacts/14753092465) | `.tar.gz`，构建环境为 Ubuntu 22.04 |
| macOS Apple Silicon | [macos-arm64](https://github.com/603717321/zxw-firmware-toolbox/actions/runs/45020026722/artifacts/14753252971) | `.app` 压缩包，未做面向公开分发的签名、公证验证 |

Actions 产物需登录 GitHub 下载，工作流配置的保留期为 14 天。若某个直链过期，请从构建列表选择更新的成功运行。下载得到的 Actions ZIP 内包含平台压缩包和对应的 SHA-256 校验文件。

## 功能
- **固件与分区工作区**：读取固件分区表、检查可识别的头部校验和；拆分分区，或载入已有工作区后合并。
- **解包与文件编辑**：支持兼容的 SquashFS、JFFS2 分区；可搜索、增删文件和目录，编辑文本、权限与属主，并查看变更清单。
- **重打包与回写**：分别生成文件系统镜像和分区镜像。
- **设备信息**：读取并另存固件中可识别的 Wi-Fi、序列号、版本和默认 SIM 等信息。

## 使用顺序
**载入整机固件 → 拆分或打开工作区 → 解包并编辑 → 生成镜像 → 回写所选分区 → 合并整机固件。**
