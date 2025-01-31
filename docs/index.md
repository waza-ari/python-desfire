# Introduction

The MIFARE DESFire product provides high security RFID key tokens than can be used for contactless identity, access control or payment applications.

This package provides a simple interface of interacting with DESFire chips using standard PC/SC smcartcard readers, using pure Python.
It currently supports managing keys, applications and file operations, which should cover the majority of use cases.
AES-128 is fully supported both, DES/3DES currently only receives limited testing up to the extend that is needed to change the default key and create applications.

!!! warning "NDA and Accuracy"
    Note that NXP does not release the DESFire documentation to the public, an NDA is required to obtain this information.
    I do not have an NDA, nor do I have access to the documentation. This package as been created based on other open source
    work, see the Credits section below for the sources that have been used.

    This also means that I have limited ability to guarantee a correct implementation of all commands, especially when
    it comes to different encryption and MAC functions. I have mainly tested AES-128 keys, if you encounter any issues,
    pleae feel free to raise a ticket and/or submit a MR.

Currently, the library has been used and tested with EV1 cards and CSL USB Reader, but other PC/SC compatible readers should work the same.

## Installation

The package itself can be installed using poetry.

```bash
poetry add python-easyverein
```

To communicate with the PC/SC smartcard reader, this package relies on `pyscard` which has some requirements.
Refer to the [installation guide](https://github.com/LudovicRousseau/pyscard/blob/master/INSTALL.md) for details.
Just for reference, to install on Debian, the requirements would be:

```bash
sudo apt install swig libpcsclite-dev python3-dev pcscd pcsc-tools
```

## Basic Usage

There are two basic ways (coming from the `pyscard` dependency) on how to use the package, being either in direct
mode or in observer mode. The following example connects to a card, authenticates using the default key and reads
the card UID.

```python
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

```

This basic example shows two core concepts already, key management using the `KeySettings` schema and data
representation using integer lists. More details on that can be found in the ... section.

## Supported Commands

This section gives an overview on the commands that are available on the card and whether they're supported by this package.

### Card Level Commands

| Code | Supported          | Command               | Note                                               |
| ---- | ------------------ | --------------------- | -------------------------------------------------- |
| 0x0A | :x:                | Authenticate (Legacy) | Legacy DES authentication, 8-byte key length       |
| 0x1A | :white_check_mark: | Authenticate (ISO)    | 3DES (2 keys, 16 byte) or 3K3DES (3 keys, 24 byte) |
| 0xAA | :white_check_mark: | Authenticate (AES)    | AES-128 (16 byte key length)                       |


## Tests

Test coverage is currently rather limited, and will be extended in the future.
Tests are making use of `pytest`, so you can simply run them by calling it. No dedicated environment varaibles are needed.

```bash
pytest
```

All features of this client are automatically tested against the actual API using pytest. If you want to run the tests
yourself, it is advisable to create a separate demo account for that. Then, set the following environment variable to
your API token and simply run `pytest`:

```
EV_API_KEY=<your-api-key>
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