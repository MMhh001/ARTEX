---
name: web-vuln-playbook
description: Web 漏洞验证与利用阶段调用的经验库。包含 SQLi/XSS/SSRF/IDOR/文件上传/鉴权绕过/SSTI/反序列化/业务逻辑 的判定方法、payload 选择顺序、WAF 绕过思路与误报排除清单。任务进入漏洞验证阶段时优先加载。
---

# Web 漏洞挖掘经验库（Playbook）

本 skill 是验证阶段的"老兵经验"，不是扫描器替代品。核心原则：**先证明可控，再证明危害，全程留证据**。

## 通用判定流程（每类洞都按这个走）

1. **定位注入面**：参数名、参数位置（query/body/header/cookie/path/JSON 深层键）、数据流向（回显/盲注/异步回调）。
2. **基线采样**：先发 3 个正常请求，记录状态码、长度、耗时、关键响应串，作为 diff 基线。
3. **探针递增**：从无害特征串开始（`'"、${{7*7}}、sleep(0)`），每升级一档都要能解释"为什么这档能区分有无漏洞"。
4. **证据固化**：每个确认点保存完整请求/响应对到 evidence，标注复现步骤。
5. **误报排除**：见末尾清单，过一遍再上报。

## SQL 注入

### 判定顺序
1. 报错探针：`'`、`"`、`\`、`')` —— 出现数据库报错串（MySQL/PostgreSQL/MSSQL/Oracle 语法指纹）即高置信。
2. 布尔盲注：`AND 1=1` vs `AND 1=2`（注意 URL 编码与 JSON 内的转义），响应长度/关键串稳定差异 ≥3 次复现才算。
3. 时间盲注：`AND SLEEP(5)`（MySQL）/ `pg_sleep(5)` / `WAITFOR DELAY`（MSSQL），实际延迟 ≥4.5s 且正常请求 <1s，复测 2 次。
4. 确认后上 sqlmap：`sqlmap -u '<url>' --data='<body>' --cookie='<c>' -p <参数> --batch --level=3 --risk=2 --flush-session`，dump 前先 `--dbs` 证明深度。

### 绕过要点
- 空格被滤：`/**/`、`%a0`、括号嵌套 `AND(1)=(1)`。
- 关键字被滤：大小写混合 `SeLeCt`、双写 `SELSELECTECT`、等价函数 `substr→mid→substring`。
- 引号被转义：宽字节 `%df'`（GBK 站点）、数字型注入本就不需要引号。

## XSS

1. 回显点先打探针 `<svg onload=prompt(1)>`，被滤就降级枚举可用标签：`<img src=x onerror=...>`、`<details open ontoggle=...>`。
2. 属性内回显：闭合法 `" onfocus=alert(1) autofocus "`；事件属性内则直接 `');alert(1);//`。
3. JS 字符串内回显：`</script><script>alert(1)</script>` 或 `-alert(1)-`。
4. 确认弹窗才算高危；只回显不执行时检查 CSP 与编码（HTML 实体/URL 双重编码场景降为中危存储候选）。
5. 盲打（后台 XSSHunter 类）：payload 带回连域名，记录触发 URL 与 cookie。

## SSRF

1. 找参数特征：`url=`、`uri=`、`callback=`、`webhook=`、`image=`、`proxy=`、`fetch=`。
2. 探测顺序：先打 `http://127.0.0.1:<服务端口>` 看回显差异 → `http://169.254.169.254/latest/meta-data/`（云元数据，AWS/阿里/腾讯各自路径）→ 内网段 `http://192.168.x.x`。
3. 协议升级：`gopher://`（打 Redis/MySQL/内网 HTTP）、`dict://`、`file:///etc/passwd`。
4. 绕过：十进制/八进制 IP（`2130706433`）、`0x7f000001`、`[::ffff:127.0.0.1]`、DNS rebinding、短链跳转、URL 解析差异（`http://evil.com@127.0.0.1`、`http://127.0.0.1#@evil.com`）。

## IDOR / 越权

1. 抓两个不同权限账号（A/B），A 的 token 访问 B 的资源 ID：改 `id`、`uid`、`order_no`、`file_id`。
2. 注意隐藏参数：body 里带 `role`、`isAdmin`、`tenant_id`，尝试直接改。
3. 接口枚举越权：`/api/user/1` 这类 RESTful 路径逐个递增，看是否返回他人数据。
4. 判定标准：返回非本人敏感字段（手机号/身份证/余额/订单）= 实锤；返回 403/空 = 安全。

## 文件上传

1. 先传正常图，记录存储路径与访问 URL（是否同域、是否解析）。
2. 绕过矩阵：双扩展名 `.php.jpg`、大小写 `.PhP`、点空格点 `.php. .`、`.phtml/.php5/.pht`、`.htaccess`+图片马、MIME 改 `image/jpeg`、文件头 `GIF89a` 伪装、条件竞争（传了立刻访问）。
3. 解析漏洞：IIS `xx.asp;.jpg`、Nginx `xx.jpg/.php`、Apache 多后缀。
4. 确认 RCE 后再升级 webshell；只回显路径不解析 = 存储 XSS/钓鱼面，降级。

## 鉴权与会话

1. JWT：先看 alg，`none`、HS256 弱密钥（jwt_tool/hashcat 字典跑）、RS256→HS256 混淆；`kid` 注入与 `jku` 伪造。
2. 改包测垂直越权：普通用户 cookie 直接请求 admin 接口。
3. OAuth：`redirect_uri` 白名单绕过（`@`、`#`、子域、URL 编码）、state 缺失 → CSRF 绑号。
4. 验证码：复用不刷新、响应包带答案、万能码 `0000/1234`、频率缺失 → 爆破面。

## SSTI / 模板注入

1. 探针 `${7*7}`、`{{7*7}}`、`<%=7*7%>`、`#{7*7}`，回显 49 即确认引擎存在。
2. 指纹：Smarty `{* comment *}`、Twig `{{_self}}`、Jinja2 `{{config}}`、Freemarker `<#assign>`。
3. Jinja2 升级链：`{{''.__class__.__mro__[1].__subclasses__()}}` 找 `subprocess.Popen` 或 `os._wrap_close`。

## 业务逻辑（扫描器盲区，重点）

- 金额/数量：改负数、改小数精度（0.001）、并发下单（条件竞争超发优惠券/超提）。
- 流程跳过：直接调最后一步接口（跳过支付/审核）。
- 状态回滚：退款接口重复调、已用券再次使用。
- 短信/邮件炸弹：无频控 + 无图形验证 = 可直接上报。

## 误报排除清单（上报前必过）

- [ ] 差异是否稳定复现 ≥3 次（排除 WAF 随机页、CDN 缓存抖动）
- [ ] 时间盲注是否排除网络抖动（对照组 <1s，实验组 ≥4.5s，两轮）
- [ ] "敏感信息泄露"是否为公开数据（robots、js map、测试账号）
- [ ] 报错堆栈是否含真实路径/SQL（只露框架版本算低危或不算）
- [ ] 漏洞 URL 是否在授权范围内（旁站、CDN 边缘节点不算）

## 输出要求

每个确认漏洞产出：漏洞名 / 等级（CVSS 3.1 向量）/ 复现步骤（含完整请求）/ 证据文件路径 / 修复建议。存疑的进"待复核"而不是混入报告。
