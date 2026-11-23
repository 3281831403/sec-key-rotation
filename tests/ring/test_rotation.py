"""密钥轮换的验收测试，共 15 个，当前应全部为红。"""

from datetime import datetime, timedelta

import pytest

from engine.ring.rotation import (
    add_key,
    decrypt,
    encrypt,
    retire,
    rotate,
    rotation_batch,
    select_key,
    validate_ring,
)

T0 = datetime(2026, 1, 1, 0, 0, 0)
POLICY = {"max_overlap_days": 30}


def new_ring(purpose="payload", overlap_days=7):
    """按契约构造空环。"""
    return {
        "purpose": purpose,
        "keys": {},
        "current": None,
        "next_version": 1,
        "policy": {"overlap_days": overlap_days},
    }


def seed_ring(purpose="payload", overlap_days=7, material=b"material-1", key_id=None):
    """构造只含一个密钥的环。"""
    ring = new_ring(purpose, overlap_days)
    add_key(ring, key_id or purpose + "-v1", material, T0)
    return ring


def make_key(key_id, version, purpose="payload", created_at=T0, material=b"material-1"):
    """构造单个密钥条目，用于制造环校验所需的异常环。"""
    return {
        "key_id": key_id,
        "version": version,
        "material": material,
        "purpose": purpose,
        "created_at": created_at,
        "retired_at": None,
    }


def test_envelope_carries_key_id():
    """缺陷 1：信封必须写入 key_id，不能只写版本号。"""
    ring = seed_ring()
    envelope = encrypt(ring, b"quarterly report", T0)
    assert envelope["key_id"] == "payload-v1"
    assert envelope["version"] == 1


def test_select_key_uses_historical_time():
    """缺陷 2：选择密钥不能永远返回当前版本。"""
    ring = new_ring()
    add_key(ring, "payload-v1", b"material-1", T0)
    add_key(ring, "payload-v2", b"material-2", T0 + timedelta(days=1))
    assert select_key(ring, "payload", T0)["version"] == 1
    assert select_key(ring, "payload", T0 + timedelta(days=1))["version"] == 2


def test_retire_keeps_key_in_overlap():
    """缺陷 3：退役只打标记，重叠期内仍可解密。"""
    ring = seed_ring(overlap_days=5)
    envelope = encrypt(ring, b"old data", T0)
    retire(ring, "payload-v1", T0 + timedelta(days=1))
    assert "payload-v1" in ring["keys"]
    assert decrypt(ring, envelope, T0 + timedelta(days=2)) == b"old data"


def test_overlap_uses_policy_value():
    """缺陷 4：重叠期长度取自策略配置，不是固定三十天。"""
    ring = seed_ring(overlap_days=3)
    envelope = encrypt(ring, b"old data", T0)
    retire(ring, "payload-v1", T0 + timedelta(days=1))
    assert decrypt(ring, envelope, T0 + timedelta(days=3)) == b"old data"
    with pytest.raises(ValueError):
        decrypt(ring, envelope, T0 + timedelta(days=5))


def test_rotate_versions_increase_within_same_second():
    """缺陷 5：同一秒两次轮换也必须得到不同且递增的版本号。"""
    ring = seed_ring()
    same = T0 + timedelta(days=1)
    first = rotate(ring, b"material-2", same)
    second = rotate(ring, b"material-3", same)
    assert first["version"] == 2
    assert second["version"] == 3


def test_decrypt_rejects_expired_retired_key():
    """缺陷 6：解密必须校验退役状态，过期后拒绝。"""
    ring = seed_ring(overlap_days=2)
    envelope = encrypt(ring, b"secret", T0)
    retire(ring, "payload-v1", T0 + timedelta(days=1))
    with pytest.raises(ValueError):
        decrypt(ring, envelope, T0 + timedelta(days=10))


def test_validate_reports_duplicate_versions():
    """缺陷 7：环校验必须报告版本重复。"""
    ring = new_ring()
    ring["keys"]["payload-v1"] = make_key("payload-v1", 1)
    ring["keys"]["payload-v1-copy"] = make_key("payload-v1-copy", 1, material=b"material-2")
    ring["current"] = "payload-v1"
    ring["next_version"] = 2
    problems = validate_ring(ring, POLICY)
    assert any("版本重复" in problem for problem in problems)


def test_validate_reports_missing_created_at():
    """缺陷 8：环校验必须报告缺失创建时间。"""
    ring = new_ring()
    ring["keys"]["payload-v1"] = make_key("payload-v1", 1, created_at=None)
    ring["current"] = "payload-v1"
    ring["next_version"] = 2
    problems = validate_ring(ring, POLICY)
    assert any("缺失创建时间" in problem for problem in problems)


def test_batch_operations_are_isolated():
    """缺陷 9：批量处理各操作独立，不能复用上一个操作的当前密钥。"""
    base = seed_ring()
    operations = [
        {
            "ring": base,
            "action": "rotate",
            "material": b"material-2",
            "now": T0 + timedelta(days=1),
        },
        {
            "ring": base,
            "action": "rotate",
            "material": b"material-3",
            "now": T0 + timedelta(days=1),
        },
    ]
    outcome = rotation_batch(operations, POLICY)
    first, second = outcome["results"]
    assert first["version"] == 2
    assert second["version"] == 2
    assert first["key_id"] == second["key_id"]
    assert base["next_version"] == 2
    assert list(base["keys"]) == ["payload-v1"]


def test_envelope_carries_purpose():
    """缺陷 10：加解密必须带用途标识，禁止跨用途复用同一把密钥。"""
    ring = seed_ring(purpose="payload")
    envelope = encrypt(ring, b"alpha", T0)
    assert envelope["purpose"] == "payload"
    other = seed_ring(purpose="token", key_id="payload-v1")
    with pytest.raises(ValueError):
        decrypt(other, envelope, T0)


def test_same_version_roundtrip():
    """同一版本加密再解密得到原文。"""
    ring = seed_ring()
    envelope = encrypt(ring, b"hello ring", T0)
    assert envelope["ciphertext"] != b"hello ring"
    assert decrypt(ring, envelope, T0) == b"hello ring"


def test_old_envelope_survives_rotation():
    """轮换后旧信封仍可解密。"""
    ring = seed_ring(overlap_days=7)
    envelope = encrypt(ring, b"last quarter", T0)
    rotate(ring, b"material-2", T0 + timedelta(days=1))
    assert decrypt(ring, envelope, T0 + timedelta(days=2)) == b"last quarter"


def test_overlap_boundary_expires_exactly():
    """重叠期右端点容差为 0，到期即拒绝。"""
    ring = seed_ring(overlap_days=5)
    envelope = encrypt(ring, b"old", T0)
    retired_at = T0 + timedelta(days=1)
    retire(ring, "payload-v1", retired_at)
    before = retired_at + timedelta(days=5) - timedelta(seconds=1)
    assert decrypt(ring, envelope, before) == b"old"
    with pytest.raises(ValueError):
        decrypt(ring, envelope, retired_at + timedelta(days=5))


def test_versions_strictly_increasing():
    """版本号严格递增。"""
    ring = seed_ring()
    rotate(ring, b"material-2", T0 + timedelta(seconds=1))
    rotate(ring, b"material-3", T0 + timedelta(seconds=2))
    rotate(ring, b"material-4", T0 + timedelta(seconds=3))
    versions = [entry["version"] for entry in ring["keys"].values()]
    assert versions == sorted(versions)
    assert versions == [1, 2, 3, 4]


def test_batch_matches_separate_processing():
    """两批独立处理的结果与分别单独处理相同。"""
    ring_a = seed_ring(purpose="payload")
    ring_b = seed_ring(purpose="token")
    ops_a = [
        {
            "ring": ring_a,
            "action": "rotate",
            "material": b"material-a",
            "now": T0 + timedelta(days=1),
        }
    ]
    ops_b = [
        {
            "ring": ring_b,
            "action": "rotate",
            "material": b"material-b",
            "now": T0 + timedelta(days=1),
        }
    ]
    combined = rotation_batch(ops_a + ops_b, POLICY)
    separate_a = rotation_batch(ops_a, POLICY)
    separate_b = rotation_batch(ops_b, POLICY)
    assert combined["results"] == separate_a["results"] + separate_b["results"]
    assert combined["problems"] == {}
    assert separate_a["problems"] == {}
    assert separate_b["problems"] == {}
