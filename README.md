# cybertagger
高性能WEB指纹识别打标工具

这个工具可以给httpx工具的NDJSON输出打上WEB指纹与IP地理位置标签  以便于后续的数据分析

测试指纹来源 hakuQAQ/Holmes (Goby指纹库)

```json
{
    product: "产品名",
    rule: "规则名",
    rule_id: "规则id",
    level: "等级",
    category: "分类",
    parent_category: "上级分类",
    softhard: "是否软硬件",
    company: "公司",
    from: "来源"
}
```
```
规则函数
banner_contain  banner 包含  非WEB指纹 未实现
banner_equal  banner 完全匹配  非WEB指纹 未实现
body_contain  body 包含
body_equal  body 完全匹配
cert_contain  tls 包含
header_contain header 包含
server_contain header server 包含
server_equal header server 完全匹配
protocol_contain 协议 完全匹配 非WEB指纹 未实现
title_contain  标题 包含
title_equal 标题 完全匹配
port_contain 端口 完全匹配

语法
! || && ()
```
示例规则
```
body_contain("{\"timestamp\":\"") && body_contain("\",\"status\":") && body_contain(",\"message\":") && body_contain(",\"path\":")
```

输入
```
{...
"tls":{...},
"webserver":"Boa/0.94.14rc21",
"body":"...",
"title":"...",
"host":"11.45.1.4",
"path":"/",
"raw_header":"...."
}


```


输出

```
{ ... 
"country":"中国",
"province":"台湾",
"city":"桃园市",
"finger":["Boa-Web-Server"] //指纹产品名 数组
}

```
