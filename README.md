密钥按季度轮换之后，上季度加密的少量数据再也解不开了，旧的还能继续用：加密只写版本号不写密钥标识，轮换后无法定位密钥；选择密钥总是取当前版本，旧数据用新密钥解密失败；退役时立刻删除密钥，重叠期形同虚设；重叠期用固定三十天，忽略策略配置；版本号用创建时间戳，同一秒两次轮换版本冲突；解密不校验密钥是否已退役，退役密钥仍可长期使用；环校验不检查版本重复，同名版本互相覆盖；环校验不检查缺失创建时间，无法判断重叠期；批量处理复用当前密钥，第二个操作命中第一个操作的密钥；加解密不带用途标识，同一把密钥被跨用途复用。engine/ring/rotation.py 是核心，tests/ring/test_rotation.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

仓库布局

sec-key-rotation/
  README.md
  conftest.py
  engine/__init__.py
  engine/ring/__init__.py
  engine/ring/rotation.py
  tests/ring/test_rotation.py

运行方式

在仓库根目录执行：pytest tests -q
当前预期结果：15 failed，0 error。

字段表

分类：安全
方向：漏洞检测与攻防
类型：Bugfix
技术栈：Python 3, pytest
依赖：无外部依赖

布局说明

本仓库采用 engine 嵌套布局：engine 是顶层包，包内再分 ring 子包，核心实现位于 engine/ring/rotation.py，测试位于 tests/ring/test_rotation.py。根目录的 conftest.py 把仓库根目录加入 sys.path，因此测试可以直接导入 engine。tests 目录不可修改，只允许修改 engine/ring/rotation.py 中的实现。

补充说明

engine/ring/rotation.py 中恰好有 8 个桩函数，当前全部 raise NotImplementedError；tests 中恰好有 15 个测试，当前全部为红。实现时只使用标准库和 pytest，不联网、不使用随机数，时间与密钥材料全部显式传入。修复目标是让 15 个测试全部通过。
## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

