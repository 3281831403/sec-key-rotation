"""按季度轮换的对称密钥环。

环对象是普通 dict，测试与调用方直接读写。结构固定如下，所有时间都是
datetime.datetime，全部时间比较的容差为 0 秒：

    {
        "purpose": "payload",          # 用途标识，一个环只服务一个用途
        "keys": {
            "payload-v1": {            # 以 key_id 为键
                "key_id": "payload-v1",
                "version": 1,          # 从 1 开始的整数，严格递增，永不复用
                "material": b"...",    # 密钥材料，bytes
                "purpose": "payload",  # 必须与环的 purpose 相同
                "created_at": datetime,
                "retired_at": None,    # 未退役为 None，退役后为 datetime
            },
        },
        "current": "payload-v1",       # 最近一次加入或轮换的 key_id
        "next_version": 2,             # 下一个可用版本号，整数计数器
        "policy": {"overlap_days": 7}, # 重叠期长度，单位天
    }

版本号只能来自 next_version 计数器，禁止使用创建时间戳；同一秒内连续
轮换也必须得到不同且递增的版本。重叠期只由环的 policy.overlap_days 决
定，禁止写死。重叠期是左闭右开区间 [retired_at, retired_at + 重叠期)，
容差为 0：now 恰好等于右端点时即视为过期。

加密必须确定性，不使用随机数，只依赖 hashlib、hmac、datetime、json 与
Python 标准库的其他模块。解密时必须按信封中的 key_id 定位密钥，并校验
用途与退役状态。
"""


def add_key(ring, key_id, material, created_at) -> dict:
    """加入新密钥并设为当前。

    契约：
    - 版本号取 ring["next_version"]（整数），写入后该计数器加一；连续调用
      即使 created_at 相同也不会产生重复版本。
    - 新条目的 purpose 取 ring["purpose"]，retired_at 为 None。
    - 写入 ring["keys"][key_id]，并把 ring["current"] 设为 key_id。
    - created_at 是 datetime 且不能为 None。

    返回新加入的密钥条目 dict（即 ring["keys"][key_id]）。
    """
    raise NotImplementedError


def select_key(ring, purpose, now) -> dict:
    """按用途与时间选择当时可用的密钥。

    - purpose 必须等于 ring["purpose"]，否则抛 ValueError。
    - 候选密钥需同时满足：purpose 匹配、created_at 小于等于 now、尚未退
      役（retired_at 为 None）。
    - 在候选中返回 version 最大的条目，因此把 now 设为较早的历史时刻会
      选到旧版本，而不是无条件返回 ring["current"]。
    - 没有候选时抛 ValueError。

    返回密钥条目 dict（环内对象，调用方不得修改）。
    """
    raise NotImplementedError


def encrypt(ring, plaintext, now) -> dict:
    """加密明文并返回信封。

    使用 select_key(ring, ring["purpose"], now) 选密钥。信封至少包含：
    key_id、version、purpose、ciphertext、tag。必须写入 key_id，不能只写
    version，否则轮换后无法定位旧密钥。purpose 必须写进信封，解密时据此
    拒绝跨用途复用。加密必须确定性：同一环状态、同一明文、同一 now 必须
    得到完全相同的信封，禁止使用随机数。

    plaintext 为 bytes，返回 dict。
    """
    raise NotImplementedError


def decrypt(ring, envelope, now) -> bytes:
    """按信封里的 key_id 找密钥解密，返回原文字节。

    - envelope 缺少 key_id 或环里没有该 key_id 时抛 KeyError。
    - 校验 envelope["purpose"] 与密钥的 purpose、环的 purpose 一致，否
      则抛 ValueError；同一把密钥不得跨用途复用。
    - 校验退役状态：密钥已退役且 now 大于等于 retired_at 加
      overlap_days 时抛 ValueError，容差为 0；重叠期内仍可解密。
    - 校验 tag，失败抛 ValueError。

    返回 bytes。
    """
    raise NotImplementedError


def retire(ring, key_id, now) -> dict:
    """标记密钥退役，重叠期内仍可解密。

    - 只把 retired_at 设为 now，绝不从 ring["keys"] 删除条目；删除会让
      重叠期形同虚设。
    - 重叠期长度从 ring["policy"]["overlap_days"] 读取，禁止写死 30 天。
    - key_id 不存在时抛 KeyError。

    返回被退役的密钥条目 dict。
    """
    raise NotImplementedError


def rotate(ring, material, now) -> dict:
    """生成新版本并保留旧版本。

    - 新版本号来自 ring["next_version"] 计数器，严格加一，禁止使用创建
      时间戳；旧版本条目原样保留，不删除、不覆盖。
    - key_id 按用途与版本生成：purpose + "-v" + str(version)。
    - 新条目加入 ring["keys"] 并设为 ring["current"]。
    - created_at 取 now。

    返回新密钥条目 dict。
    """
    raise NotImplementedError


def validate_ring(ring, policy) -> list[str]:
    """返回环的问题列表，空列表表示通过。

    policy 形如 {"max_overlap_days": 30}。至少检查以下三项：
    1. 版本重复：ring["keys"] 中两个条目的 version 相同，会互相覆盖；问
       题文本必须包含关键词 版本重复。
    2. 重叠期过长：ring["policy"]["overlap_days"] 大于
       policy["max_overlap_days"]；问题文本必须包含关键词 重叠期过长。
    3. 缺失创建时间：任一条目的 created_at 为 None 或缺失；问题文本必须
       包含关键词 缺失创建时间。

    返回 list[str]，每个问题一个字符串，顺序不限。
    """
    raise NotImplementedError


def rotation_batch(operations, policy) -> dict:
    """批量处理操作，各操作彼此独立。

    operations 是 list[dict]，每个元素：
        {
            "ring": 初始环 dict,
            "action": "add_key" 或 "rotate" 或 "retire",
            "now": datetime,
            "key_id": str,      # add_key 或 retire 需要
            "material": bytes,  # add_key 或 rotate 需要
        }

    - 每个操作先深拷贝自己的 ring，再调用对应函数，最后用
      validate_ring(拷贝后的环, policy) 收集问题；操作之间不得共享当前密
      钥、版本计数器或任何可变状态，第二个操作不得命中第一个操作创建的
      密钥。
    - 返回 {"results": list, "problems": dict[int, list[str]]}：
      results 与 operations 等长，按顺序放各操作的返回值；操作抛异常时
      对应位置为 None，并把它的问题记入 problems[下标]。
    - 输入 operations 中的环不得被原地修改。

    add_key 操作使用 key_id 与 material；rotate 使用 material；retire 使
    用 key_id。
    """
    raise NotImplementedError
