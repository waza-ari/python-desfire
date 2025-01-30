from smartcard.util import toHexString

from desfire import diversify_key
from desfire.util import get_list


def test_diversify_nxp_application_note():
    """
    Tests the diversification of a key based on the NXP application note AN10922.

    Test data coming from section 2.2.1 from https://www.nxp.com/docs/en/application-note/AN10922.pdf
    """

    MK = "00112233445566778899AABBCCDDEEFF"
    UID = "04782E21801D80"
    APPID = "3042F5"
    SYSID = "4E585020416275"
    EXPECTED_RESULT = "A8DD63A3B89D54B37CA802473FDA9175"

    diversify_data = [0x01] + get_list(UID) + get_list(APPID) + get_list(SYSID)
    key = get_list(MK)

    div_key = diversify_key(key, diversify_data, pad_to_32=True)
    print("Diversified key: ", toHexString(div_key))

    assert get_list(EXPECTED_RESULT) == div_key


def test_diversify_no_32_padding():
    """
    Tests the diversification of a key based on the NXP application note AN10922.
    This particular example covers the case where the diversification data is not padded to 32 bytes
    but to the next multiple of 16 bytes, which typically is just 16.
    """

    MK = "83 A6 6C F4 36 05 11 18 02 A2 61 6F A0 C5 E2 FF"
    UID = "04 4D 07 02 19 5E 80"
    APPID = "DA DA DA"
    SYSID = "71 55 17"
    EXPECTED_RESULT = "DAE9B8D3136B2DAE35D58678F378B0B1"

    diversify_data = [0x01] + get_list(UID) + get_list(APPID) + get_list(SYSID)
    key = get_list(MK)

    div_key = diversify_key(key, diversify_data, pad_to_32=False)
    print("Diversified key: ", toHexString(div_key))

    assert get_list(EXPECTED_RESULT) == div_key
