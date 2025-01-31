from smartcard.CardRequest import CardRequest
from smartcard.CardType import AnyCardType
from smartcard.Exceptions import CardRequestTimeoutException
from smartcard.util import toHexString

from desfire import DESFire, DESFireKey, PCSCDevice

cardtype = AnyCardType()
cardrequest = CardRequest(timeout=30, cardType=cardtype)
print("Please present DESfire tag...")

try:
    cardservice = cardrequest.waitforcard()
except CardRequestTimeoutException:
    print("No tag detected within the timeout.")
    raise

cardservice.connection.connect()

# Create Desfire object, which allows further communication with then card
desfire = DESFire(PCSCDevice(cardservice.connection.component))

# Authenticate with default DES key by retrieving the key settings from the card,
# providing the default key and then authenticate against the master key 0x0
key_settings = desfire.get_key_setting()
mk = DESFireKey(key_settings, "00" * 8)
desfire.authenticate(0x0, mk)

# Get real UID
uid = desfire.get_real_uid()
print(toHexString(uid))
