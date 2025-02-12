# Introduction

The MIFARE DESFire product provides high security RFID key tokens than can be used for contactless identity, access control or payment applications.

This package provides a simple interface of interacting with DESFire chips using pure Python.
It currently supports managing keys, applications and file operations, which should cover the majority of use cases.
AES-128 is fully supported both, DES/3DES currently only receives limited testing up to the extend that is needed to change the default key and create applications.

Both PC/SC readers as well as the popular PN532 reader (only UART, no SPI or I2C as of today) is supported.
Please make sure to install the correct extra dependencies.

**Core features**:

- Compatible with all PC/SC readers supported by `pyscard` or PN532 reader using UART (using `pyserial` as only additional dependency)
- Support for **AES and ISO authentication (DES, 2K3DES and 3K3DES)**. No support for legacy authentication.
- Full crypto support including **CMAC and CRC validation** on all commands that require it
- **Key management** change and create keys on PICC and application leven
- **Application management** create and delete applications
- **File management** support for standard data files is implemented, other file types are currently not available

Currently, the library has been used and tested with EV1 cards and CSL USB Reader, but other PC/SC compatible readers should work the same.
It is also tested using PN532 readers, although I recommend using the Adafruit reader for better compatibility.

!!! warning "NDA and Accuracy"
    Note that NXP does not release the DESFire documentation to the public, NDA signature is required to obtain this information.
    **The author of this package has not signed this NDA, nor does he have access to the documentation**.
    This package has been created based on other open source work, see the Credits section below for details.

    This also means that there is very limited ability to guarantee a correct implementation of all commands.
    The package has mainly been tested using DES and AES-128 keys. If you encounter any issues, please
    feel free to raise a ticket and/or submit an MR.

## Installation

The package itself can be installed using poetry. Depending on the card reader you want to use, you need to select
which extras to install.

```bash
# For PC/SC USB readers:
poetry add "python-desfire[pcsc]"

# For PN532 Reader
poetry add "python-desfire[pn532]"
```

When communicating with the PC/SC smartcard reader, this package relies on `pyscard` which has some requirements.
Refer to the [installation guide](https://github.com/LudovicRousseau/pyscard/blob/master/INSTALL.md) for details.
Just for reference, to install on Debian, the requirements would be:

```bash
sudo apt install swig libpcsclite-dev python3-dev pcscd pcsc-tools
```

## Basic Usage

### PC/SC

There are two basic ways (coming from the `pyscard` dependency) on how to use the package, being either in direct
mode or in observer mode. The following example connects to a card, authenticates using the default key and reads
the card UID.

The most basic pattern looks like this. For more details and examples, please refer to the [usage section](usage.md)
of this documentation.

```python
from smartcard.CardRequest import CardRequest
from smartcard.CardType import AnyCardType
from smartcard.Exceptions import CardRequestTimeoutException
from smartcard.util import toHexString

from desfire import DESFire, DESFireKey, PCSCDevice

# Use pyscard to obtain a handle to the PICC
cardtype = AnyCardType()
cardrequest = CardRequest(timeout=30, cardType=cardtype)
print("Please present DESfire tag...")

try:
    cardservice = cardrequest.waitforcard()
except CardRequestTimeoutException:
    print("No tag detected within the timeout.")
    raise

cardservice.connection.connect()

# Create Desfire object, which allows further communication with the card
desfire = DESFire(PCSCDevice(cardservice.connection.component))

# Authenticate with default DES key by retrieving the key settings from the card,
# providing the default key and then authenticate against the master key 0x0
key_settings = desfire.get_key_setting()
mk = DESFireKey(key_settings, "00" * 8)
desfire.authenticate(0x0, mk)

# Get real UID
uid = desfire.get_real_uid()
print(toHexString(uid))
```

This basic example shows two core concepts already, key management using the `KeySettings` schema and data
representation using integer lists. More details on that can be found in the ... section.

### PN532

The PN532 reader must be connected to UART, either using a USB / UART driver or - if you're using a Raspberry PI - it is also possible using
one of the built-in UARTs.

```python
import logging
import sys

from desfire import DESFire, PN532UARTDevice

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create physical device which can be used to detect a card
device = PN532UARTDevice("/dev/ttyAMA2", baudrate=115200, timeout=0.1)

# Wait for a card
uid = None
i = 0

while not uid and i < 10:
    logger.info(f"Connecting to card (attempt {i + 1})...")
    uid = device.wait_for_card(timeout=1)
    i += 1

if not uid:
    logger.error("No card detected!")
    sys.exit(1)

logger.info("Card detected.")

# Create DESFire object, which allows further communication with the card
desfire = DESFire(device)
print(desfire.get_card_version())
```

## Supported Commands

As outlined in the introduction, not all features and commands are currently supported.
Please refer to the [supported commands](supported-commands.md) section for more details.

## Tests

Test coverage is currently rather limited, and will be extended in the future.
Tests are making use of `pytest`, so you can simply run them by calling it. No dedicated environment varaibles are needed.

```bash
pytest
```

## Contributing

The client is written in pure Python, using `mkdocs` with `mkdocstrings` for documentation. Any changes or
pull requests are more than welcome, but please adhere to the code style:

- Use `ruff` based code linting, formatting and styling
- Use `mypy` for static type checking

A pre-commit hook configuration is supplied as part of the project. You can run them prior to your commit using:

```bash
pre-commit

# Or run them for the entire project
pre-commit run --all-files
```

Please make sure that any additions are properly tested. PRs won't get accepted if they don't have test cases to
cover them.

## Documentation

To work on the documentation, you need to install the `dev` dependencies:

```bash
poetry install --with dev
```

From there, you can simply run

```bash
mkdocs serve
```

Documentation will then be available at http://127.0.0.1:8000/ and automatically monitors the `src` and `docs` directories.
