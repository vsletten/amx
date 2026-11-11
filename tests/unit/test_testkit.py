from __future__ import annotations

from amx.testkit import drop_zone_record, set_zone_record


def test_zone_record_helpers_remove_restore_and_increment_serial(tmp_path) -> None:
    zone = tmp_path / "agents.test.zone"
    record = 'scheduler._domainkey IN TXT "v=DKIM1; p=abc"'
    zone.write_text(
        "$ORIGIN agents.test.\n"
        "@ IN SOA mail.test. hostmaster.test. (100 30 30 300 30)\n"
        f"{record}\n"
        'intake._domainkey IN TXT "v=DKIM1; p=def"\n',
        encoding="utf-8",
    )

    removed = drop_zone_record(zone, "scheduler._domainkey")

    assert removed == record
    revoked = zone.read_text(encoding="utf-8")
    assert "(101 " in revoked
    assert "scheduler._domainkey" not in revoked
    assert "intake._domainkey" in revoked

    set_zone_record(zone, removed)

    restored = zone.read_text(encoding="utf-8")
    assert "(102 " in restored
    assert restored.count(record) == 1
