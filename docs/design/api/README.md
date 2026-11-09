# 契约范围

`openapi.yaml` 是 HTTP/终端 Upgrade 接口草案；逐帧协议由 `docs/05-protocols.md` 与三个 JSON Schema 定义。

`control.schema.json`：控制 WSS text 信封；`stream.schema.json`：smux 每条流开头的 open/ack JSON（外部 4 字节 BE 长度前缀不在 JSON Schema 内）；`terminal.schema.json`：浏览器终端 text 控制。

`examples/` 对应这些定义。Agent 数据 WSS binary 不是 JSON API，进入 smux 后不能插入控制 JSON；stream ack 后则是原始 SSH。

这不是完整后台 CRUD/权限管理 API。IdP 登录回调、注册授权、管理员 grant CRUD、部署认证、分页等需在实际仓库补齐。所有 sample ticket 都是明确无效占位值。
