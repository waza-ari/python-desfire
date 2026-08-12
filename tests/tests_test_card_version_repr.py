from desfire.schemas.card_version import CardVersion


def test_card_version_repr_hardware_major_minor():
    # Prepare data for real MIFARE DESFire EV1 card with 4K from 2013
    data = [
        0x04,  # first block, hardware vendor id
        0x01,
        0x01,
        0x01,
        0x00,
        0x18,
        0x05,
        0x04,  # second block, software vendor id
        0x01,
        0x01,
        0x01,
        0x04,
        0x18,
        0x05,
        0x04,  # third block, starts with UID
        0x4D,
        0x70,
        0xBA,
        0x5F,
        0x35,
        0x80,
        0xBA,
        0x44,
        0x97,
        0xD6,
        0x70,
        0x28,
        0x13,
    ]
    cv = CardVersion(data)
    s = repr(cv)
    assert "Hardware Version: 1.0" in s
    assert "Software Version: 1.4" in s
    print(s)


"""
output with current code was:
--- Desfire Card Details ---
Hardware Version: 0.0
Software Version: 1.4
EEPROM size:      8388608 bytes
Production:       week 28, year 2013
UID no:           04 4D 70 BA 5F 35 80
Batch no:         BA 44 97 D6

new code produces following output:
--- Desfire Card Details ---
Hardware Version: 1.0
Software Version: 1.4
EEPROM size:      4096 bytes
Production:       week 28, year 2013
UID no:           04 4D 70 BA 5F 35 80
Batch no:         BA 44 97 D6
"""
