# watchvuln-rs

## 介绍

程序还在持续完善功能

当前抓取了这几个站点的数据:

| 名称                 | 地址                                    | 推送策略                                 |
| -------------------- | --------------------------------------- | ---------------------------------------- |
| 阿里云漏洞库         | <https://avd.aliyun.com/high-risk/list> | 等级为高危或严重                         |
| OSCS开源安全情报预警 | <https://www.oscs1024.com/cm>           | 等级为高危或严重**并且**包含 `预警` 标签 |
| 知道创宇Seebug漏洞库 | <https://www.seebug.org/>               | 等级为高危或严重                         |

目前程序支持telegram群消息推送

## 开发

已经配置了vscode devcontainer

初始化数据库表：

```bash
sea-orm-cli migrate up
```

![app](./assets/app.jpg)

参考GO版本的：<https://github.com/zema1/watchvuln>
