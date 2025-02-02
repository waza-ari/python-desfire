## Connecting to the card

This package makes use of `pyscard` to handle the low level communication with the card, it is therefore strongly
recommended to review [their documentation](https://pyscard.sourceforge.io), in particular the
[high-level examples](https://pyscard.sourceforge.io/pyscard-framework.html#framework-samples).

Essentially, there are two different modes to connect to the card, a **direct** and a **passive** mode.

### Direct Mode

In **direct** mode, we explicitely request a card to be presented and configure a timeout. If a card is not presented within the given time,
a `smartcard.Exceptions.CardRequestTimeoutException` exception that must be handled within your code. This is the simplest way to
connect:

```python
from smartcard.CardRequest import CardRequest
from smartcard.CardType import AnyCardType
from smartcard.Exceptions import CardRequestTimeoutException

from desfire import DESFire, PCSCDevice

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
```

### Passive Mode

In passive mode, we're waiting forever for a card to be presented and execute same commands against every card that gets presented.
There is no timeout, the program continues until cancelled.

```python
import sys
import time

from desfire import DESFire, PCSCDevice
from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.System import readers


class MyObserver(CardObserver):
    """Observe when a card is inserted. Then try to run DESFire application listing against it."""

    def update(self, observable, actions):
        (addedcards, removedcards) = actions

        for card in addedcards:
            connection = card.createConnection()
            connection.connect()

            # This will log raw card traffic to console
            connection.addObserver(ConsoleCardConnectionObserver())

            # Connection object itself is CardConnectionDecorator wrapper
            # and we need to address the underlying connection objectdirectly
            desfire = DESFire(PCSCDevice(connection.component))
            print(desfire.get_key_version())


def main():
    available_reader = readers()
    if not available_reader:
        sys.exit("No smartcard readers detected")

    cardmonitor = CardMonitor()
    cardobserver = MyObserver()
    cardmonitor.addObserver(cardobserver)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
```

## Performing Operations

All operations are exposed as commands of the resulting `DESFire` object.
The available commands are listed in the [supported commands](supported-commands.md) section,
details on each command can be found in the [API reference](api/desfire.md).

Some commands require authentication before being executed, this is highlighted in the documentation of each command.
If encryption / CMAC validation / CRC validation is required, this is handled transparently by the package.
Some commands require may or may not require authentication, depending on card or application settings.
It is your responsibility as a user handle authentication prior to this command, otherwise an exception will be thrown.

## Authenticating

Authentication is required for certain commands and requires a cryptographic key depending on the card settings.
This package supports DES, 2K3DES, 3K3DES and AES-128 cryptography, however only DES and AES-128 is currently actively
used and therefore actively tested.

The easiest way to authenticate is to first read the key settings from the card and then supply the actual cryptographic key.
You may also specify the key settings yourself if you're concerned about speed.

!!! tip "Key settings on application level"

    Please note that key settings on application level are set for the master key
    and then apply to all keys that are used within the application. Therefore you
    do not need to specify a key id when getting key settings, key `0x00` is always
    used.

```python
# Connect to your application
self.desfire.select_application("DEAFFE")

# Authenticate with the card
key_settings = self.desfire.get_key_setting()
key = DESFireKey(key_settings, get_list("01 AB CD EF 01 AB CD EF 01 AB CD EF 01 AB CD EF"))

# 0x01 is the key ID you want to authenticate against
self.desfire.authenticate(0x01, key)
```

Note that some operations (such as selecting an application or changing the key you're authenticated with)
immediately destroy the authentication context and you need to re-authenticate.

## About Data Types

The PICC typically works with binary data. Python offers several options to work with data, such as `bytes`, `bytearray` or a `list[int]`.
This library uses `list[int]` consistently to represent data and keys. The list approach is chosen because it is a mutable data type
(in contract to `bytes`, which is immutable). `bytearray` is not used as indexing a `bytearray` yields the `ord()` value of the letter:

```python
a = bytearray(b'abc')
a[0]
> 97
```

As mentioned before, data is passed and returned as `list[int]`, where each value of the list must not be negative and must not exceed the value 255.
In most cases, you can also pass `bytes` or `bytearray` data, they get converted accordingly. Refer to the type annotations of the methods.

To simplify working with whatever data format you prefer, the package exports a `get_list()` method which can convert various data formats
(including plain HEX strings) in data the other methods understand:

```python
from desfire import get_list


# Pass a regular string
get_list("0123456789ABCDEF")
> [1, 35, 69, 103, 137, 171, 205, 239]

# Whitespaces are ignored
>>> get_list("01 23 456789ABCDEF")
> [1, 35, 69, 103, 137, 171, 205, 239]

# When passing an integer, you have to specify byte size and byte order:
get_list(400, byte_size=3, byteorder="little")
> [144, 1, 0]
get_list(400, byte_size=3, byteorder="big")
> [0, 1, 144]
```

Refer to the [API documentation of get_list](api/utility.md#desfire.util.get_list) for more details.
