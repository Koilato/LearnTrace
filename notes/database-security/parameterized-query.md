# 参数化查询

## 一句话

**参数化 = SQL AST 结构固定，只给 Value 参数节点绑定运行时数据。**

## 掌握范围

```math
\text{参数化查询}
\xrightarrow{\text{掌握}}
\begin{cases}
\text{Prepared Statement 原理}\\
\text{参数能绑定什么}\\
\text{参数不能绑定什么}\\
\text{动态 SQL 的安全构造}\\
\text{识别“假参数化”}
\end{cases}
```

## 原理

```sql
SELECT * FROM users WHERE age > ?
```

`?` 是 Value Parameter，不是“万能 SQL 空位”。

```text
SQL → Parse(AST) → 语义分析/优化 → 绑定参数值 → Execute
```

绑定 `? = 18` 只是给 Parameter 节点赋值，不会把它变成列名、表名或关键字。

## SQL 关键字作用对象

| 关键字 | 主要作用对象 | 作用 |
|---|---|---|
| `SELECT` | **列** | 选择结果中输出的列/表达式 |
| `FROM` | **表/数据源** | 指定从哪里读取数据 |
| `WHERE` | **行** | 过滤行 |
| `JOIN` | **表 + 行** | 连接多个表的相关行 |
| `ON` | **行之间的关系** | 指定 JOIN 的匹配条件 |
| `GROUP BY` | **行 → 组** | 把行按列/表达式分组 |
| `HAVING` | **组** | 过滤分组后的组 |
| `ORDER BY` | **结果行** | 对结果行排序 |
| `DISTINCT` | **结果行** | 去除重复结果 |
| `LIMIT/OFFSET` | **结果行范围** | 限制返回行数/跳过若干行 |
| `INSERT INTO` | **表/列** | 指定新增数据的目标 |
| `VALUES` | **新行中的值** | 提供插入值 |
| `UPDATE` | **表/行** | 指定要修改的数据 |
| `SET` | **列 + 值** | 指定列的新值 |
| `DELETE FROM` | **表/行** | 删除目标行 |

理解模型：

```text
FROM/JOIN 选数据源 → WHERE 选行 → GROUP BY/HAVING 处理组
→ SELECT 选列 → DISTINCT/ORDER BY/LIMIT 处理结果
```

> 这是逻辑理解模型，不等同于所有 DBMS 的物理执行顺序。

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

## 动态 SQL 的安全构造

动态 Value → 参数绑定：

```python
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

动态结构 → 白名单：

```python
allowed = {"age": "age", "name": "name"}
column = allowed[user_sort]
sql = f"SELECT * FROM users ORDER BY {column}"
```

## 识别“假参数化”

```python
sql = f"SELECT * FROM users WHERE id = ? ORDER BY {sort}"
execute(sql, id)
```

- `id`：真正参数化。
- `sort`：在 Parse 前进入 SQL 源码，仍是动态 SQL。

## 安全审计

```text
所有不可信输入
→ Value：参数绑定
→ SQL结构：严格白名单
```

重点找：`f-string`、字符串拼接、`format`、Raw SQL。

**部分参数化 ≠ 整条 SQL 安全。**
