# FuanSync

> 不安 Syncing.

用 Rust 写的 Git Credential Helper，通过 GitHub App 私钥实时签发 installation token，供 Git 走 HTTPS 访问仓库使用。

支持直接传参运行（CLI 模式），也支持把凭据直接打包到二进制文件（Embed 模式），丢进目标环境即可无依赖运行。

## 快速开始

确保你的 GitHub App 已安装到目标账号，并开了 `Contents` 读写权限。

### 1. 嵌入模式（推荐）

直接将凭据打包并安装到当前 Git 仓库：

```bash
cd /path/to/repo
fuansync --embed --app <APP_ID> --installation <INSTALLATION_ID> --pem <PEM_PATH>
```

这会生成一个包含凭据的 `.git/.fuansync-credential-helper`（权限 `0700`），并自动追加到当前仓库的 `credential.helper` 配置中（带锁与失败回滚，不影响已有配置；覆盖已有文件需加 `-f`）。

如果只想导出打包后的单文件二进制，加上 `-o`：

```bash
fuansync --embed --app <APP_ID> --installation <INSTALLATION_ID> --pem <PEM_PATH> -o ./fuansync-helper
```

打包后的二进制会剥离配置参数，仅响应标准的 Git 凭据协议指令（`get` / `store` / `erase`）。

### 2. CLI 模式

不打包凭据，直接由 Git 调用或手动测试（默认动作是 `get`）：

```bash
fuansync --app <APP_ID> --installation <INSTALLATION_ID> --pem <PEM_PATH> [get|store|erase]
```

## 技术细节与限制

* **私钥要求**：支持 PKCS#1 / PKCS#8 格式的 RSA 私钥，体积上限 64 KiB。
* **作用范围**：仅响应 `protocol=https` 且 `host=github.com` 的请求。
* **二进制嵌入机制**：
* **Linux (ELF)**：写入非加载的 `.fuansync` section。
* **Windows (PE)**：写入只读、可丢弃的 `.fsync` section。
* **macOS (Mach-O)**：暂不支持二进制嵌入，仅可用 CLI 模式。
* **数据结构**：固定 1 MiB 空间，包含 Magic、版本号、Flags、App/Installation ID、PEM 原文、CRC32C 校验及零填充。不会原地修改输入文件，且默认拒绝处理已签名的二进制。


* **安全性**：嵌入二进制只是为了分发方便，**不是加密**。私钥依然可以从 section 中提取，请严格限制 GitHub App 的权限范围。

## 构建

依赖 Rust stable 和 `just`。

```bash
just build
just test
```

交叉编译（支持 Linux x86_64/aarch64、Windows x86_64、macOS x86_64）需安装 Zig，macOS 目标还需配置 `SDKROOT` 或 `FUANSYNC_MACOS_LIBDIR`：

```bash
just cross-build
```

## License

本项目使用 [MIT-0](https://opensource.org/licenses/MIT-0) 许可证授权。
