# Clash Node Aggregator

定时抓取公开订阅源，清洗、去重并生成一个可供 Clash Verge 订阅的 `dist/clash.yaml`。

> 重要：公开免费节点来源不受控，可能随时失效，也可能记录流量。不要通过它们登录网银、企业账号或其他敏感服务。生产使用应改为自建服务器或可信付费订阅。

## GitHub 自动更新

仓库中的 `.github/workflows/update.yml` 每 6 小时运行一次，也可以手动触发：

1. 打开 `Actions`
2. 选择 `Update Clash subscription`
3. 点击 `Run workflow`
4. 等待任务完成，检查 `dist/clash.yaml`

如需修改来源，编辑根目录的 `sources.txt`，每行一个公开订阅地址。

## Clash Verge 配置

生成后的订阅地址：

```text
https://github.com/lyy00702/clash-node-aggregator/raw/main/dist/clash.yaml
```

如果该地址访问不稳定，可尝试：

```text
https://raw.githubusercontent.com/lyy00702/clash-node-aggregator/main/dist/clash.yaml
```

在 Clash Verge 中：

1. 打开 `订阅 / Profiles`
2. 点击新建或导入
3. 类型选择 `Remote`
4. 名称填写 `GitHub Auto Nodes`
5. URL 粘贴上面的订阅地址
6. 点击导入，然后点击该订阅启用
7. 在设置页开启系统代理或 TUN
8. 在代理页选择 `AUTO` 测速，或手动选择节点

Clash Verge 会按订阅设置自动更新；也可以在订阅卡片上点击刷新按钮手动更新。

## 本地运行

```powershell
python -m pip install -r requirements.txt
python aggregate.py --sources sources.txt --output dist/clash.yaml --limit 200
```

脚本会跳过内网、回环、保留地址，按协议、服务器、端口和凭据去重，并限制节点总数。

## 文件说明

- `aggregate.py`：抓取、解析、去重和生成配置
- `sources.txt`：公开订阅来源
- `dist/clash.yaml`：GitHub Actions 生成的 Clash 配置
- `.github/workflows/update.yml`：自动更新任务

## 安全建议

- 不要把真实 API Key、账号 Cookie 或私人订阅地址提交到公开仓库
- 如果不想公开来源地址，可将 `sources.txt` 改为私有方案，或在 Action 中使用 Secrets 动态生成文件
- 使用前检查 `dist/clash.yaml` 中的 `proxies`，确认没有你不信任的来源
