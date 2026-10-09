# ORM 基础

## 一句话

**ORM = Object-Relational Mapping（对象关系映射）：用对象/API 操作关系型数据库。**

```text
程序对象 ↔ ORM ↔ 数据库表
```

## 四个审计入口

| 概念 | 极简理解 | 审计重点 |
|---|---|---|
| Query Builder | 用 API 构造查询 | 动态结构是否受用户控制 |
| Raw SQL | ORM 中直接写 SQL | SQL 注入 |
| Lazy Loading | 访问属性时自动查询 | 隐式查询、N+1、权限边界 |
| Mass Assignment | 批量把输入写入模型 | 敏感字段越权修改 |

## 数据流

```text
用户输入 → ORM API → SQL / Model 字段 → 数据库
```

审计时不要只看“有没有 ORM”，而要追踪每个不可信输入最终进入了哪里。
