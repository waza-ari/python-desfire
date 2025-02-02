

This section gives an overview on the commands that are available on the card and whether they're supported by this package.
The list is based on public information on EV1 cards, and will likely not represent a full list of available commands.
Additional EV2 and EV3 features are not part of this list (yet).

## Card Level Commands

Both supported authentication schemes are encapsulated in the `authenticate()` method.

| Code | Supported          | Command                   | Note                                                                        |
| ---- | ------------------ | ------------------------- | --------------------------------------------------------------------------- |
| 0x0A | :x:                | Authenticate (Legacy)     | Legacy DES authentication, 8-byte key length                                |
| 0x1A | :white_check_mark: | Authenticate (ISO)        | 3DES (2 keys, 16 byte) or 3K3DES (3 keys, 24 byte)                          |
| 0xAA | :white_check_mark: | Authenticate (AES)        | AES-128 (16 byte key length)                                                |
| 0x51 | :white_check_mark: | Get Real UID              | Retrieves real UID in case random UID is enabled during collision detection |
| 0x5C | :warning:          | Change PICC Configuration | Partially supported, see below for details                                  |
| 0x60 | :white_check_mark: | Get card version          | Retrieves card details such as HW and SW version and production date        |
| 0x6E | :x:                | Get free memory           |                                                                             |
| 0xFC | :white_check_mark: | Format PICC               | Completely wipes the card                                                   |

## Key Commands

These commands are for managing crypto keys on the PICC.

| Code | Supported          | Description                                                                  | Method                |
| ---- | ------------------ | ---------------------------------------------------------------------------- | --------------------- |
| 0x64 | :white_check_mark: | Get Key Version Byte                                                         | `get_key_version`     |
| 0x45 | :white_check_mark: | Get key settings of the master key of the currently selected application.    | `get_key_setting`     |
| 0x54 | :white_check_mark: | Change key settings of the master key of the currently selected application. | `change_key_settings` |
| 0xC4 | :white_check_mark: | Change key data and potentially type.                                        | `change_key_settings` |

## Application Level Commands

asdasd

## File Level Commands

asdasd