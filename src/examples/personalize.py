"""
This is a more involved example that performs initial configuration (often called personalization) of a DESFire card.

It performs the following steps:
1. Authenticate with the default DES key
3. Change the default key
2. Create an application
4. Change the application master key
6. Create a read and write key (diversified)
7. Create an encrypted file
8. Write the UID to the encrypted file

"""

import logging

from smartcard.CardRequest import CardRequest
from smartcard.CardType import AnyCardType
from smartcard.Exceptions import CardRequestTimeoutException
from smartcard.util import toHexString

from desfire import DESFire, DESFireKey, PCSCDevice, diversify_key
from desfire.enums import DESFireCommunicationMode, DESFireFileType, DESFireKeySettings, DESFireKeyType
from desfire.schemas import FilePermissions, FileSettings, KeySettings
from desfire.util import get_list

# Please make sure to yet your own keys here before running this script
MIFARE_APP_MASTER_KEY = ""  # 16 bytes AES key
MIFARE_ACL_READ_BASE_KEY = ""  # 16 bytes AES key
MIFARE_ACL_WRITE_BASE_KEY = ""  # 16 bytes AES key

# Constants
MIFARE_APP_ID = "DEAFFE"  # 7 bytes
MIFARE_ACL_READ_BASE_KEY_ID = 0x1
MIFARE_ACL_WRITE_BASE_KEY_ID = 0x2
MIFARE_SYS_ID = "FF0000"  # 3 bytes, can essentially be anything
MIFARE_ENCRYPTED_FILE_ID = 0x1

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

cardtype = AnyCardType()
cardrequest = CardRequest(timeout=30, cardType=cardtype)
print("Please present DESfire tag...")

try:
    cardservice = cardrequest.waitforcard()
except CardRequestTimeoutException:
    print("No tag detected within the timeout.")
    raise

cardservice.connection.connect()

# Create Desfire object
desfire = DESFire(PCSCDevice(cardservice.connection.component))

# Create Key objects
AES_NULL_KEY_DATA = "00" * 16
aes_keysettings = KeySettings(
    key_type=DESFireKeyType.DF_KEY_AES,
)
aes_null_key = DESFireKey(aes_keysettings, AES_NULL_KEY_DATA)

# Authenticate with default DES key
print("Authenticating with default DES key...")
key_settings = desfire.get_key_setting()
mk = DESFireKey(key_settings, "00" * 8)
desfire.authenticate(0x0, mk)

# Get real UID
print("Getting real UID...")
uid = desfire.get_real_uid()
print("  - UID: ", toHexString(uid))

# Set default key
print("Setting default key...")
desfire.change_default_key(aes_null_key, 0x0)

# Create application
print("Creating application...")
app_settings = KeySettings(
    settings=[
        DESFireKeySettings.KS_ALLOW_CHANGE_MK,
        DESFireKeySettings.KS_LISTING_WITHOUT_MK,
        DESFireKeySettings.KS_CREATE_DELETE_WITHOUT_MK,
        DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE,
    ],
    key_type=DESFireKeyType.DF_KEY_AES,
)
desfire.create_application(MIFARE_APP_ID, app_settings, 4)

# Verify application creation
applications = desfire.get_application_ids()
assert len(applications) == 1
assert applications[0] == get_list(MIFARE_APP_ID)
print("  - Application created successfully.")

# Select application
print("Selecting application...")
desfire.select_application(MIFARE_APP_ID)

# Authenticate with AES key, as this has been set as the default key
print("Authenticating with AES key...")
# Create a new one as key data would be overriden by session data
aes_null_auth_key = DESFireKey(aes_keysettings, AES_NULL_KEY_DATA)
desfire.authenticate(0x0, aes_null_auth_key)

# Change Application master key
print("Changing application master key (AMK)...")
aes_app_mk = DESFireKey(aes_keysettings, MIFARE_APP_MASTER_KEY)
desfire.change_key(0x0, aes_null_key, aes_app_mk, 0x1)

# Re-Authenticate with new AES key
print("Re-authenticating with new AES key...")
desfire.authenticate(0x0, aes_app_mk)

# Change file read and write keys (diversified)
diversification_data = [0x01] + uid + get_list(MIFARE_APP_ID) + get_list(MIFARE_SYS_ID)
read_div_key_bytes = diversify_key(get_list(MIFARE_ACL_READ_BASE_KEY), diversification_data, pad_to_32=False)
write_div_key_bytes = diversify_key(get_list(MIFARE_ACL_WRITE_BASE_KEY), diversification_data, pad_to_32=False)

print("Changing file read key...")
aes_file_read_key = DESFireKey(aes_keysettings, read_div_key_bytes)
desfire.change_key(MIFARE_ACL_READ_BASE_KEY_ID, aes_null_key, aes_file_read_key, 0x1)

print("Changing file write key...")
aes_file_write_key = DESFireKey(aes_keysettings, write_div_key_bytes)
desfire.change_key(MIFARE_ACL_WRITE_BASE_KEY_ID, aes_null_key, aes_file_write_key, 0x1)

print("Create encrypted file containing UID...")
file_settings = FileSettings(
    file_size=8,
    encryption=DESFireCommunicationMode.ENCRYPTED,
    permissions=FilePermissions(
        read_key=MIFARE_ACL_READ_BASE_KEY_ID,
        write_key=MIFARE_ACL_WRITE_BASE_KEY_ID,
    ),
    file_type=DESFireFileType.MDFT_STANDARD_DATA_FILE,
)
desfire.create_standard_file(MIFARE_ENCRYPTED_FILE_ID, file_settings)

print("Read and verify file settings again...")
file_data = desfire.get_file_settings(MIFARE_ENCRYPTED_FILE_ID)
assert file_data.file_size == 8
assert file_data.encryption == DESFireCommunicationMode.ENCRYPTED
assert file_data.permissions.read_access == MIFARE_ACL_READ_BASE_KEY_ID
assert file_data.permissions.write_access == MIFARE_ACL_WRITE_BASE_KEY_ID
assert file_data.file_type == DESFireFileType.MDFT_STANDARD_DATA_FILE
print("  - File created successfully.")

print("Writing UID to encrypted file...")
data = [0x0] + uid
assert len(data) == 8
desfire.write_file_data(MIFARE_ENCRYPTED_FILE_ID, 0x0, file_data.encryption, get_list(data))

print("Reading from encrypted file...")
rdata = desfire.read_file_data(MIFARE_ENCRYPTED_FILE_ID, file_data)
assert rdata == data
print("  - Data written successfully.")

print("Personalization finished.")
