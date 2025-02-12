[![Documentation Status](https://readthedocs.org/projects/python-desfire/badge/?version=latest)](https://python-desfire.readthedocs.io/en/latest/?badge=latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)
![GitHub issues](https://img.shields.io/github/issues/waza-ari/python-desfire)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/waza-ari/python-desfire)
![GitHub top language](https://img.shields.io/github/languages/top/waza-ari/python-desfire)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/waza-ari/python-desfire/main.svg)](https://results.pre-commit.ci/latest/github/waza-ari/python-desfire/main)

# Python DESFire

[Full documentation is available at read the docs.](https://python-desfire.readthedocs.io/en/latest/)

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

> [!IMPORTANT]  
> Note that NXP does not release the DESFire documentation to the public, NDA signature is required to obtain this information.
> **The author of this package has not signed this NDA, nor does he have access to the documentation**.
> This package has been created based on other open source work, see the Credits section below for details.
> 
> This also means that there is very limited ability to guarantee a correct implementation of all commands.
> The package has mainly been tested using DES and AES-128 keys. If you encounter any issues, please
> feel free to raise a ticket and/or submit an MR.

# Documentation Sources and Credits

This library would not be possible without other amazing open source contributions that served as source of information
when creating this package. Credits go to the creators and maintainers of the following repositories, in no particular order:

- Desfire Python: https://github.com/patsys/desfire-python
- EasyPay: https://github.com/nceruchalu/easypay/blob/master/mifare/mifare_crypto.c
- Libfreefare: https://github.com/nfc-tools/libfreefare/blob/c2b0cfa4b9fb0e4be88604f00b7a2405618d5abc/libfreefare/mifare_desfire.c
- ESUP NFC Tag: https://github.com/EsupPortail/esup-nfc-tag-server/blob/master/src/main/java/org/esupportail/nfctag/service/desfire/DESFireEV1Service.java#L1523
- DESfire PDF on Github: https://raw.githubusercontent.com/revk/DESFireAES/master/DESFire.pdf
- DESFire Examples: https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
