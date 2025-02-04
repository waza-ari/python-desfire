

This section gives an overview on the commands that are available on the card and whether they're supported by this package.
The list is based on public information on EV1 cards, and will likely not represent a full list of available commands.
Additional EV2 and EV3 features are not part of this list (yet).

## Authentication

Both supported authentication schemes are encapsulated in the `authenticate()` method.

| Code | Supported          | Command                      | Note                                               |
| ---- | ------------------ | ---------------------------- | -------------------------------------------------- |
| 0x0A | :x:                | Authenticate (Legacy)        | Legacy DES authentication, 8-byte key length       |
| 0x1A | :white_check_mark: | Authenticate (ISO)           | 3DES (2 keys, 16 byte) or 3K3DES (3 keys, 24 byte) |
| 0xAA | :white_check_mark: | Authenticate (AES)           | AES-128 (16 byte key length)                       |
| 0x71 | :x:                | Authenticate (EV2 First)     | EV2 + EV3 only                                     |
| 0x72 | :x:                | Authenticate (EV2 Non First) | EV2 + EV3 only                                     |

## Card Level Commands

These commands are not application or key specific.

| Code | Supported          | Description               | Method               |
| ---- | ------------------ | ------------------------- | -------------------- |
| 0x51 | :white_check_mark: | Get Real UID              | `get_real_uid`       |
| 0x5C | :warning:          | Change PICC Configuration | `change_default_key` |
| 0x60 | :white_check_mark: | Get card version          | `get_card_version`   |
| 0x6E | :x:                | Get free memory           |                      |
| 0xFC | :white_check_mark: | Format PICC               | `format_card`        |

Command `0x5C` supports multiple sub-commands. Currently, only `0x5C01` is implemented, which is used to change
the default key that is used as master key when creating new applications.

## Key Commands

These commands are for managing crypto keys on the PICC.

| Code | Supported          | Description                                                                  | Method                |
| ---- | ------------------ | ---------------------------------------------------------------------------- | --------------------- |
| 0xC4 | :white_check_mark: | Change key data and potentially type.                                        | `change_key_`         |
| 0xC6 | :x:                | Change Key (EV2 only)                                                        | N/A                   |
| 0x55 | :x:                | Roll Key Set (EV2 only)                                                      | N/A                   |
| 0x56 | :x:                | Initialize Key Set (EV2 only)                                                | N/A                   |
| 0x57 | :x:                | Finalize Key Set (EV2 only)                                                  | N/A                   |
| 0x45 | :white_check_mark: | Get key settings of the master key of the currently selected application.    | `get_key_setting`     |
| 0x54 | :white_check_mark: | Change key settings of the master key of the currently selected application. | `change_key_settings` |
| 0x64 | :white_check_mark: | Get Key Version Byte                                                         | `get_key_version`     |

## Application Level Commands

These commands are used to manage applications on the card.

| Code | Supported          | Description                  | Method                |
| ---- | ------------------ | ---------------------------- | --------------------- |
| 0xCA | :white_check_mark: | Creates a new application    | `create_application`  |
| 0xDA | :white_check_mark: | Delete application           | `delete_application`  |
| 0xC9 | :x:                | Create delegated application | N/A                   |
| 0x5A | :white_check_mark: | Select application           | `select_application`  |
| 0x6A | :white_check_mark: | Get application ids          | `get_application_ids` |

## File Level Commands

Commands to create and update files within applications. There are multiple file types:

- Standard Data File (supported)
- Backup Data File (not supported)
- Value File (not supported)
- Linear Record File (not supported)
- Cyclic Record File (not supported)
- Transaction MAC File (EV2 only, not supported)


| Code | Supported          | Description                     | Method                 |
| ---- | ------------------ | ------------------------------- | ---------------------- |
| 0xCD | :white_check_mark: | Creates a standard data file    | `create_standard_file` |
| 0xCB | :x:                | Creates a backup data file      | N/A                    |
| 0xCC | :x:                | Creates a value file            | N/A                    |
| 0xC1 | :x:                | Creates a linear record file    | N/A                    |
| 0xC0 | :x:                | Creates a cyclic record file    | N/A                    |
| 0xCE | :x:                | Creates a transaction MAC file  | N/A                    |
| 0xDF | :white_check_mark: | Deletes a file                  | `delete_file`          |
| 0x6F | :white_check_mark: | Get file IDs within application | `get_file_ids`         |
| 0x61 | :x:                | Get ISO file ids                | N/A                    |
| 0xF5 | :white_check_mark: | Get file settings               | `get_file_settings`    |
| 0xF6 | :x:                | Get file counters               | N/A                    |
| 0x5F | :x:                | Change file settings            | N/A                    |
| 0xBD | :white_check_mark: | Read file data                  | `read_file_data`       |
| 0x3D | :white_check_mark: | Write file data                 | `write_file_data`      |
| 0x6C | :x:                | Get value                       | N/A                    |
| 0x0C | :x:                | Credit                          | N/A                    |
| 0xDC | :x:                | Debit                           | N/A                    |
| 0x1C | :x:                | Limited Credit                  | N/A                    |
| 0xBB | :x:                | Read Records                    | N/A                    |
| 0x3B | :x:                | Write Records                   | N/A                    |
| 0xDB | :x:                | Update Records                  | N/A                    |
| 0xEB | :x:                | Clear Record File               | N/A                    |
| 0xC7 | :x:                | Commit Transaction              | N/A                    |
| 0xA7 | :x:                | Abort Transaction               | N/A                    |
| 0xC8 | :x:                | Commit Reader ID                | N/A                    |
