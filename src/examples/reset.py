import logging

from smartcard.CardRequest import CardRequest
from smartcard.CardType import AnyCardType
from smartcard.Exceptions import CardRequestTimeoutException

from desfire import DESFire, DESFireKey, PCSCDevice

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

# Authenticate with default DES key
print("Authenticating with default DES key...")
key_settings = desfire.get_key_setting()
mk = DESFireKey(key_settings, "00" * 8)
desfire.authenticate(0x0, mk)

# Format card. WARNING: This will delete all applications and files on the card!
print("Formatting card...")
desfire.format_card()

print("Done.")
