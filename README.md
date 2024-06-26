# watchvuln-rs

## 介绍

当前抓取了这几个站点的数据:

| 名称                         | 地址                                                           | 推送策略                                                                     |
| ---------------------------- | -------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| 阿里云漏洞库                 | <https://avd.aliyun.com/high-risk/list>                        | 等级为高危或严重                                                             |
| OSCS开源安全情报预警         | <https://www.oscs1024.com/cm>                                  | 等级为高危或严重**并且**包含 `预警` 标签                                     |
| 知道创宇Seebug漏洞库         | <https://www.seebug.org/>                                      | 等级为高危或严重                                                             |
| CISA KEV                     | <https://www.cisa.gov/known-exploited-vulnerabilities-catalog> | 全部推送                                                                     |
| 奇安信威胁情报中心           | <https://ti.qianxin.com/>                                      | 等级为高危严重**并且**包含 `奇安信CERT验证` `POC公开` `技术细节公布`标签之一 |
| 微步在线研究响应中心(公众号) | <https://x.threatbook.com/v5/vulIntelligence>                  | 等级为高危或严重                                                             |
| 安天威胁情报中心             | <https://www.antiycloud.com/#/antiy/safenotice>                | 全部推送                                                                     |

## 开发

已经配置了vscode devcontainer

初始化数据库表：

```bash
sea-orm-cli migrate up
```

本地测试：

```bash
RUST_LOG=info TG_CHAT_ID=xxx TG_TOKEN=xxx cargo run
```

## 部署

项目已经配置了docker-compose,可以通过deployment目录下的文件一键部署

deployment/env 关键配置

```env
DATABASE_URL=postgres://watchvuln:watchvuln@db:5432/watchvuln
DING_ACCESS_TOKEN=
DING_SECRET_TOKEN=
TG_CHAT_ID=0
TG_TOKEN=
```

根据自己的使用添加钉钉或者telegram机器人的配置

## 支持推送方式

- 钉钉机器人
- Telegram机器人
- 飞书机器人

## 推送效果

![app](./assets/app.jpg)

参考GO版本的：<https://github.com/zema1/watchvuln>
