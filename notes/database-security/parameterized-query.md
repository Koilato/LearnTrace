# 参数化查询

## 一句话

**参数化 = SQL AST 结构固定，只给 Value 参数节点绑定运行时数据。**

## 原理

```sql
SELECT * FROM users WHERE age > ?
```

`?` 是 Value Parameter，不是“万能 SQL 空位”。

```text
SQL → Parse(AST) → 语义分析/优化 → 绑定参数值 → Execute
```

绑定 `? = 18` 只是给 Parameter 节点赋值，不会把它变成列名、表名或关键字。

## 静态 / 动态

- **静态 SQL**：AST 结构不变，只是参数值变化。
- **动态 SQL**：运行时输入会改变 AST 结构。

```sql
WHERE age > ?          -- 静态结构 + 动态值
ORDER BY age           -- age 是结构
```

## 能绑定 / 不能绑定

| 类型 | 参数绑定 |
|---|---|
| 字符串、数字、日期等 Value | ✅ |
| 表名、列名 | ❌ |
| 运算符、ASC/DESC、SQL 关键字 | ❌ |

结构位置需要动态变化时，用**白名单映射**生成 SQL。

## 安全审计

判断“用了参数化”是否安全：

```text
所有不可信输入
→ Value：参数绑定
→ SQL结构：严格白名单
```

重点找：`f-string`、字符串拼接、`format`、Raw SQL。

**部分参数化 ≠ 整条 SQL 安全。**

例如：

```python
sql = f"SELECT * FROM users WHERE id = ? ORDER BY {sort}"
execute(sql, id)
```

`id` 已参数化；`sort` 在 Parse 前进入 SQL 源码，仍是注入面。
