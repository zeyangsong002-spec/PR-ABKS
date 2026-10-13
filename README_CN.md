# PR-ABKS 开源发布版（2026-10-13）

本目录从 2026-10-12 修正版复制整理，作者代码采用 MIT，见 `LICENSE`。
原代码目录、论文、图片和历史实验数据均未修改。本版本没有自动上传仓库。

## 从哪里开始

1. 阅读 `INSTALL.md`，在 Ubuntu 或 Windows 的 WSL Ubuntu 中安装系统依赖。
2. 在项目根目录执行 `bash scripts/install_pbc.sh`，自动下载并校验 PBC 0.5.14，
   安装到本项目 `.deps/`；不替换已有系统 PBC。
3. 执行：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$PWD/.deps/pbc-0.5.14"
cmake --build build -j2
ctest --test-dir build --output-on-failure
./build/prabks --self-test
```

预期 CTest 1/1 通过，自测显示 `ALL 428 CHECKS PASSED`。不要使用旧 `.sln`。
新电脑上应重新构建，不复制旧 `build`。全部命令在 Ubuntu 终端执行。

## 实验入口

```bash
mkdir -p results
./build/prabks --benchmark --output results/example.csv \
  --users 10 --attrs 10 --policy 4 --eta 3 --tags 1 \
  --punctures 1 --keywords 10 --runs 10 --warmup 1
```

CSV 文件必须尚不存在。输出包含三个方案的总耗时、均值、样本标准差、最小值、
最大值，单位毫秒。实验输入由程序生成，不需要外部数据文件。

`docs/EXPERIMENT_MAPPING.md` 逐图对应 Fig.4—11、算法计时行和命令参数，
并明确未能确认的历史设置。论文旧图使用 10 次总耗时，应对应 `total_ms`，
不能直接换成 `mean_ms`。当前示例不是旧图的逐点复现。

论文初始 eta=1 对应当前边界下的 m=0，应同时指定 `--eta 1 --tags 0`。
eta、密文标签数 m、穿刺次数 p 不能混用；Fig.8 历史横轴含义仍需结合原实验核对。
公开说明已记录这一点，没有在本轮擅自修改图或论文。

可用 `scripts/run_sweep.py` 显式指定扫描参数及取值；它保存命令、配置、校验值、
退出状态及日志。示例见对应说明。批量示例是新验证实验，不冒充原论文实验。

## 发布内容与许可

英文 `README.md`、`INSTALL.md`、`docs/IMPLEMENTATION.md` 是主要复用文档。
`IMPLEMENTATION_NOTES.md` 保留详细中文修正记录；第三方许可见 `THIRD_PARTY.md`。
MIT 允许修改、再分发和商业使用；引用论文是学术建议，不是额外许可限制。

不将 IDE 缓存、编译产物、依赖库、原始实验数据或旧源码备份打包到发布压缩包。
如后续生成结果，`.gitignore` 会排除 `results/`，但打包仍应按文件清单执行。
公开仓库地址和归档 DOI 应在实际创建后填写，不能使用占位地址冒充已公开。
