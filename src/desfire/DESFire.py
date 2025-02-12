import logging

from Crypto.Random import get_random_bytes

from .devices.base import Device
from .enums import DESFireCommand, DESFireCommunicationMode, DESFireKeySettings, DESFireKeyType, DESFireStatus
from .exceptions import DESFireAuthException, DESFireCommunicationError, DESFireException
from .key import DESFireKey
from .schemas import CardVersion, FileSettings, KeySettings
from .util import CRC32, get_int, get_list, to_hex_string, xor_lists

logger = logging.getLogger(__name__)


class DESFire:
    """
    This is the main class of this library, facilitating communication with the DESFire card.
    """

    is_authenticated: bool = False
    session_key: DESFireKey | None = None
    max_frame_size: int = 60
    last_selected_application: list[int] | None = None
    last_auth_key_id: int | None = None

    def __init__(self, device: Device):
        """
        Initializes a new DESfire object which can be used to interact with the card.
        Requires an initialized PCSC device object, refer to the examples for details and uage examples.

        Args:
            device (Device): Initialized PCSC device object
        """
        self.device = device
        logger.info("DESFire object initialized")

    #
    # Internal Methods
    #

    def _communicate(self, apdu_cmd: list[int], native: bool = True, af_passthrough: bool = False) -> list[int]:
        """
        Communicate with a NFC tag. Send in outgoing request and wait for a card reply.

        Args:
            apdu_cmd (list[int]): Outgoing APDU command as list of bytes in integer format
            native (bool, optional): True indicates that DESfire native commands are used,
                otherwise ISO 7816 APDUs are used
            af_passthrough (bool, optional): If true, a 0xAF response (indicating more incoming data) is instantly
                returned to the callee instead of trying to handle it internally

        Raises:
            DESFireCommunicationError: Used to indicate a communication error with the card

        Returns:
            list[int]: List of bytes received from the card
        """

        result: list[int] = []
        additional_data: bool = True
        # current_command: bytearray = apdu_cmd

        # Loop until all data is received
        while additional_data:
            # Send the APDU command to the card
            logger.debug("Running APDU command, sending: %s", to_hex_string(apdu_cmd))
            resp = self.device.transceive(apdu_cmd)
            logger.debug("Received APDU response: %s", to_hex_string(resp))

            # DESfire native commands are used
            if native:
                status = resp[0]
                # Check for known error interpretation
                if status == 0xAF:
                    if af_passthrough:
                        logger.debug("More data present (indicated by 0xAF), returning response to callee")
                        additional_data = False
                    else:
                        # Need to loop more cycles to fill in receive buffer
                        logger.debug("More data present (indicated by 0xAF), sending continue command")
                        additional_data = True
                        apdu_cmd = self._command(0xAF)  # Continue
                elif status != 0x00:
                    try:
                        error_description = DESFireStatus(status).name
                    except ValueError:
                        error_description = f"Unknown error, status {status}"
                    logger.error("Received error from card: %s", error_description)
                    raise DESFireCommunicationError(error_description, status)
                else:
                    additional_data = False
            else:  # If commands are wrapped in ISO 7816-4 APDU Frames, SW1 must be 0x91
                if resp[-2] != 0x91:
                    raise DESFireCommunicationError(
                        "Received invalid response for command using native communication", resp[-2:]
                    )
                # Possible status words:
                # https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesfireStatusWord.java
                status = resp[-1]
                unframed = list(resp[0:-2])

            # This will un-memoryview this object as there seems to be some pyjnius
            # bug getting this corrupted down along the line
            unframed = list(resp[1:])
            result += unframed

        return result

    @classmethod
    def _add_padding(cls, data: list[int], blocksize: int = 16) -> list[int]:
        """
        Adds padding to the data to make it a multiple of the cipher block size

        Padding is 0x80 once followed by 0x00 bytes until the block size is reached.

        @See https://stackoverflow.com/a/23704425/1627106
        Moreover, be careful about the way you have to do the padding.
        The DESFire EV1 datasheet is ambiguous on that. While the section
        on AES encryption suggests that CMAC padding should always be used
        together with AES, the section on padding states that commands with
        known data length should be padded with all zeros, while commands with
        unknown data length should be padded with 0x80 followed by zeros.
        Finally the documentation on the write command explicitly states
        that the write command should be padded with all zeros for encryption
        (and that's what you are supposed to do).
        """
        if len(data) % blocksize == 0:
            return data
        padding = blocksize - (len(data) % blocksize)
        logger.debug(f"Adding padding of {padding} bytes to the data.")
        logger.debug(f"Original Data: {to_hex_string(data)}")
        padded_data = data + [0x80] + [0x00] * (padding - 1)
        logger.debug(f"Padded Data: {to_hex_string(padded_data)}")
        return padded_data

    @classmethod
    def _command(cls, command: int, parameters: list[int] | None = None) -> list[int]:
        """
        Concatenate the command and parameters into a single list that can be sent to the card.
        """
        r_val = [command]

        if parameters:
            r_val += parameters

        return r_val

    def _preprocess(
        self,
        apdu_cmd: list[int],
        tx_mode: DESFireCommunicationMode,
        disable_crc: bool = False,
        encryption_offset: int = 1,
    ) -> list[int]:
        """
        Preprocess the command before sending it to the card. This includes adding the padding and the CRC if needed.
        """

        logger.debug(f"Preprocessing command {to_hex_string(apdu_cmd)}")

        # If not authenticated, we don't need to do anything
        if not self.is_authenticated:
            logger.debug("Not authenticated, skipping preprocessing")
            return apdu_cmd

        assert self.session_key is not None

        # Preprocess the command
        if tx_mode == DESFireCommunicationMode.PLAIN:
            # We don't do anything with the CMAC, but it does update the IV for future crypto operations
            logger.debug("Calculating CMAC for data simply to update IV")
            self.session_key.calculate_cmac(apdu_cmd)
            return apdu_cmd
        elif tx_mode == DESFireCommunicationMode.CMAC:
            # Calculate the CMAC and append it to the command
            logger.debug("Calculating CMAC for data")
            tx_cmac = self.session_key.calculate_cmac(apdu_cmd)
            logger.debug("CMAC has been calculated to be: " + to_hex_string(tx_cmac))
            # Only the last 8 bytes of the CMAC are used
            return apdu_cmd + tx_cmac[-8:]
        elif tx_mode == DESFireCommunicationMode.ENCRYPTED:
            assert self.session_key.cipher_block_size is not None

            logger.debug("Command requires data to be encrypted. Calculating CRC and encrypting message")
            logger.debug("Original data: " + to_hex_string(apdu_cmd))

            # Encrypt the command + data
            resp_data = self.session_key.encrypt_msg(apdu_cmd, disable_crc=disable_crc, offset=encryption_offset)
            logger.debug("Encrypted data: " + to_hex_string(resp_data))

            # Update IV to the last block of the encrypted data
            self.session_key.set_iv(resp_data[-self.session_key.cipher_block_size :])

            # Return encrypted data
            return resp_data
        else:
            logger.error("Invalid communication mode while trying to preprocess command")
            raise Exception("Invalid communication mode")

    def _postprocess(self, response: list[int], rx_mode: DESFireCommunicationMode) -> list[int]:
        """
        Postprocess the response from the card.
        """

        logger.debug(f"Postprocessing PICC response {to_hex_string(response)}")

        # PLAIN response is only possible if we're not authenticated
        if rx_mode == DESFireCommunicationMode.PLAIN:
            logger.debug("Response is plain, returning as is")
            return response
        # CMAC response is only possible if we're authenticated
        elif rx_mode == DESFireCommunicationMode.CMAC:
            """
            The CMAC is calculated over the payload of the response (i.e after the status byte) and then the status byte
            appended to the end. If the response is multiple parts then the payload of these parts are concatenated
            (without the AF status byte) and the final status byte added to the end.
            """
            logger.debug("Response is CMAC protected, we need to verify it")
            assert self.session_key is not None

            # Calculate the CMAC of the last 8 bytes of the response and append status code
            cmac_data = response[:-8] + [0x00]  # Status code of a successful command is always 0x00

            logger.debug("Calculating CMAC for data: " + to_hex_string(cmac_data))
            calculated_cmac = self.session_key.calculate_cmac(cmac_data)[:8]

            logger.debug("RXCMAC      : " + to_hex_string(response[-8:]))
            logger.debug("RXCMAC_CALC : " + to_hex_string(calculated_cmac))

            if bytes(response[-8:]) != bytes(calculated_cmac):
                logger.warning("CMAC verification failed!")
                raise Exception("CMAC verification failed!")

            return response[:-8]
        # ENCRYPTED response is only possible if we're authenticated
        elif rx_mode == DESFireCommunicationMode.ENCRYPTED:
            """
            The response is encrypted using the session key. The response is padded with 0x80 followed by 0x00 bytes
            until the end of the block. The IV is updated with the last block of the encrypted data.
            """
            logger.debug("Response is encrypted, decrypting")
            assert self.session_key is not None
            assert self.session_key.cipher_block_size is not None

            # Decrypt the response
            logger.debug("Encrypted response: " + to_hex_string(response))
            padded_response = self._add_padding(response)
            logger.debug("Padded response: " + to_hex_string(padded_response))
            decrypted_response = self.session_key.decrypt(padded_response)
            logger.debug("Decrypted response: " + to_hex_string(decrypted_response))

            # Update IV to the last block of the encrypted data
            self.session_key.set_iv(response[-self.session_key.cipher_block_size :])

            # Remove all null bytes from the end
            while decrypted_response[-1] == 0x00:
                decrypted_response = decrypted_response[:-1]

            logger.debug("Decrypted response (trimmed): " + to_hex_string(decrypted_response))

            # Check if the CRC is correct - Status byte is appended to the data before CRC calculation
            logger.debug("Verifying CRC checksum")
            crc_bytes = 4  # 2 (CRC16) is only needed for legacy authentication, which we do not support (only ISO+AES)
            received_crc = decrypted_response[-crc_bytes:]
            logger.debug("Received CRC  : " + to_hex_string(received_crc))
            calculated_crc = CRC32(decrypted_response[:-crc_bytes] + [0x00])
            logger.debug("Calculated CRC: " + to_hex_string(calculated_crc))

            if bytes(received_crc) != bytes(calculated_crc):
                logger.warning(
                    f"CRC verification failed! (received: {to_hex_string(received_crc)},"
                    f" calculated: {to_hex_string(calculated_crc)})"
                )
                raise Exception("CRC verification failed!")

            # Remove the CRC from the response
            response = decrypted_response[:-crc_bytes]

        return response

    def _transceive(
        self,
        apdu_cmd: list[int],
        tx_mode: DESFireCommunicationMode,
        rx_mode: DESFireCommunicationMode,
        af_passthrough: bool = False,
        disable_crc: bool = False,
        encryption_offset: int = 1,
    ) -> list[int]:
        """
        Communicate with the card. This is the main function that sends the APDU command and performs
        neccessary pre- and postprocessing of the data. It also handles the CMAC calculation and
        encryption/decryption of the communication if needed.
        """

        # Check for existing of session key if needed
        if tx_mode != DESFireCommunicationMode.PLAIN or rx_mode != DESFireCommunicationMode.PLAIN:
            if not self.is_authenticated:
                logger.error("Cant perform crypto operations without authentication!")
                raise Exception("Cant perform crypto operations without authentication!")

        # Preprocess the command, includes CMAC calculation and encryption
        apdu_cmd = self._preprocess(apdu_cmd, tx_mode, disable_crc, encryption_offset)

        # Send the command to the card, note that this command will raise an exception if the card returns an error
        response = self._communicate(apdu_cmd, af_passthrough=af_passthrough)

        # Postprocess the response
        return self._postprocess(response, rx_mode)

    #
    # Public Methodds
    #

    # Authentication

    def authenticate(
        self, key_id: int, key: DESFireKey, challenge: list[int] | str | bytearray | int | bytes | None = None
    ):
        """
        Authenticate against the currently selected application with key_id.
        If no application has been selected before, the default (master) application is used, which is `0x00`.
        In this case, only key `0x00` can be used for authentication.

        Authentication:
            Not required.

        Args:
            key_id (int): Key ID to authenticate with. Must be `0x00` if no application is selected.
            key (DESFireKey): Instance of the DESFireKey class containing the key data that is used to authenticate.
            challenge (list[int] | str | bytearray | int | bytes | None, optional): During the handshake process,
                the card will respond with a randomly generated challenge and then expects this device to answer with a
                random challenge as well. This challenge can be provided, it is not recommended though.
                Data passed will be parsed using the `get_list` function.

        Raises:
            DESFireException: if an invalid configuration is provided
            DESFireAuthException: If authentication fails
        """

        assert key.cipher_block_size is not None
        logger.debug("Authenticating against PICC")
        self.is_authenticated = False

        # Determine the authentication command based on the key type
        if key.key_type == DESFireKeyType.DF_KEY_AES:
            logger.debug(f"Authenticating using AES authentication scheme and key_id {key_id}")
            cmd = DESFireCommand.AUTHENTICATE_AES.value
            params = [key_id]
        elif key.key_type == DESFireKeyType.DF_KEY_2K3DES or key.key_type == DESFireKeyType.DF_KEY_3K3DES:
            logger.debug(f"Authenticating using ISO authentication scheme and key_id {key_id}")
            cmd = DESFireCommand.AUTHENTICATE_ISO.value
            params = [key_id]
        else:
            logger.error("Invalid key type has been provided.")
            raise DESFireException("Invalid key type has been provided.")

        # First part of three way handshake - Initial authentication and retrieve RND_B from card
        # AF_Passthrough is required as the card will respond with 0xAF as challenge response
        RndB_enc = self._transceive(
            self._command(cmd, params),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.PLAIN,
            af_passthrough=True,
        )
        logger.debug("Encrypion: Random B (enc):" + to_hex_string(RndB_enc))

        # Check if the key type is correct
        if (key.key_type == DESFireKeyType.DF_KEY_3K3DES or key.key_type == DESFireKeyType.DF_KEY_AES) and len(
            RndB_enc
        ) != 16:
            logger.warning(
                "Encrypion:  Card expects a different key type. "
                "(enc B size is less than the blocksize of the key you specified)"
            )
            raise DESFireException(
                "Card expects a different key type. (enc B size is less than the blocksize of the key you specified)"
            )

        # Reinitalize the cipher object of the key
        key.cipher_init()

        # Decrypt the RndB using the provided master key
        RndB = key.decrypt(RndB_enc)
        logger.debug("Encrypion: Random B (dec): " + to_hex_string(RndB))

        # Rotate RndB to the left by one byte
        RndB_rot = RndB[1:] + [RndB[0]]
        logger.debug("Encrypion: Random B (dec, rot): " + to_hex_string(RndB_rot))

        # Challenge can be either provided externally, or generated randomly
        if challenge is not None:
            RndA = get_list(challenge)
        else:
            RndA = get_list(get_random_bytes(len(RndB)))
        logger.debug("Encrypion: Random A: " + to_hex_string(RndA))

        # Concatenate RndA and RndB_rot and encrypt it with the master key
        RndAB = list(RndA) + RndB_rot
        logger.debug("Encrypion: Random AB: " + to_hex_string(RndAB))
        key.set_iv(RndB_enc)
        RndAB_enc = key.encrypt(RndAB)
        logger.debug("Encrypion: Random AB (enc): " + to_hex_string(RndAB_enc))

        # Send the encrypted RndAB to the card, it should reply with a positive result
        params = RndAB_enc
        cmd = DESFireCommand.ADDITIONAL_FRAME.value
        RndA_enc = self._transceive(
            self._command(cmd, params), DESFireCommunicationMode.PLAIN, DESFireCommunicationMode.PLAIN
        )

        # Verify that the response matches our original challenge
        logger.debug("Encrypion: Random A (enc): " + to_hex_string(RndA_enc))
        key.set_iv(RndAB_enc[-key.cipher_block_size :])
        RndA_dec = key.decrypt(RndA_enc)
        logger.debug("Encrypion: Random A (dec): " + to_hex_string(RndA_dec))
        RndA_dec_rot = RndA_dec[-1:] + RndA_dec[0:-1]
        logger.debug("Encrypion: Random A (dec, rot): " + to_hex_string(RndA_dec_rot))

        if bytes(RndA) != bytes(RndA_dec_rot):
            raise DESFireAuthException("Authentication FAILED!")

        logger.info("Authentication successful")
        self.is_authenticated = True
        self.last_auth_key_id = key_id

        logger.debug("Encrypion: Calculating Session key")
        session_key_bytes = RndA[:4]
        session_key_bytes += RndB[:4]
        if key.key_size > 8:
            if key.key_type == DESFireKeyType.DF_KEY_2K3DES:
                session_key_bytes += RndA[4:8]
                session_key_bytes += RndB[4:8]
            elif key.key_type == DESFireKeyType.DF_KEY_3K3DES:
                session_key_bytes += RndA[6:10]
                session_key_bytes += RndB[6:10]
                session_key_bytes += RndA[12:16]
                session_key_bytes += RndB[12:16]
            elif key.key_type == DESFireKeyType.DF_KEY_AES:
                session_key_bytes += RndA[12:16]
                session_key_bytes += RndB[12:16]

        if key.key_type == DESFireKeyType.DF_KEY_2K3DES or key.key_type == DESFireKeyType.DF_KEY_3K3DES:
            session_key_bytes = [(a & 0b11111110) for a in session_key_bytes]

        ## now we have the session key, so we reinitialize the crypto part of the key
        key.set_key(bytes(session_key_bytes))
        key.generate_cmac()
        key.clear_iv()

        # Store the session key
        self.session_key = key

    #
    ## Card related
    #

    def get_real_uid(self) -> list[int]:
        """
        Depending on the card configuration, the UID returned using `get_card_version` can be random.
        This command returns the real UID of the card.

        Authentication:
            Required

        Raises:
            DESFireException: if an invalid configuration is provided

        Returns:
            list[int]: 7 byte UID of the card
        """
        logger.info(f"Executing command: get_real_uid (0x{DESFireCommand.GET_CARD_UID.value:02x})")

        if not self.is_authenticated:
            logger.warning("Tried to get real UID without authentication")
            raise DESFireException("Not authenticated!")

        cmd = DESFireCommand.GET_CARD_UID.value
        return self._transceive(self._command(cmd), DESFireCommunicationMode.PLAIN, DESFireCommunicationMode.ENCRYPTED)

    def get_card_version(self) -> CardVersion:
        """
        Gets the card version data, which contains information about the card such as the UID, batch number, etc.

        Authentication:
            Not required.

        !!! warning
            DESFire cards have a security feature called "Random UID" which can be activated.
            If active, the PICC will will return a random UID each time you call this function.

        Returns:
            CardVersion: An instance of the CardVersion schema containing the card version information

        Raises:
            DESFireException: if an invalid configuration is provided
        """
        logger.info(f"Executing command: get_card_version (0x{DESFireCommand.GET_VERSION.value:02x})")

        raw_data = self._transceive(
            self._command(DESFireCommand.GET_VERSION.value),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )
        return CardVersion(raw_data)

    def format_card(self):
        """
        Formats the card, deleting all keys, applications and files on the card.

        Authentication:
            Authentication using the application `0x00` master key (key id `0x00`) is required

        !!! warning
            THIS COMPLETELY WIPES THE CARD AND RESETS IT TO A BLANK CARD!!

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.is_authenticated:
            logger.warning("Tried to format card without authentication")
            raise DESFireException("Not authenticated!")

        logger.info(f"Executing command: format_card (0x{DESFireCommand.FORMAT_PICC.value:02x})")
        cmd = DESFireCommand.FORMAT_PICC.value
        self._transceive(self._command(cmd), DESFireCommunicationMode.PLAIN, DESFireCommunicationMode.PLAIN)

    #
    ## Key Related
    #

    def get_key_setting(self) -> KeySettings:
        """
        Gets the key settings for the master key of the application currently selected.

        It returns two bytes, where the first byte contains the key settings for the current application
        as described in the change_key_settings method. The second byte is structured as follows:

        ```
        KKKK|DDDD
        7       0
        ```

        - K: Determines the key type as defined in the DESFireKeyType enum
        - D: Maximum number of keys that are allowed by the application. Always 1 for the main appliction (0x0).

        Authentication:
            Not required.

        Returns:
            KeySettings: An instance of the KeySettings schema containing the key settings. Can be
                used to authenticate using this key or another key of the same application.
        """

        logger.info(f"Executing command: get_key_setting (0x{DESFireCommand.GET_KEY_SETTINGS.value:02x})")

        resp = self._transceive(
            self._command(DESFireCommand.GET_KEY_SETTINGS.value),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )
        res = KeySettings(
            application_id=self.last_selected_application or [0x0],
            key_type=DESFireKeyType(resp[1] & 0xF0),  # Only interested in first 4 bits of the second byte
            max_keys=resp[1] & 0x0F,  # Only interested in last 4 bits of the second byte
            settings=[],
        )
        res.parse_settings(resp[0])
        return res

    def get_key_version(self, key_number: int) -> int:
        """
        Returns the version of the key, which is a one byte that can be set when the key is created.
        It is typically used to distinguish between different versions of the same key in use.

        Authentication:
            Required.

        Args:
            key_number (int): Number of the key to get the version from. Must be between 0x00 and 0x0D.

        Returns:
            int: Single byte containing the custom version information.
        """

        logger.info(
            f"Executing command: get_key_version (0x{DESFireCommand.GET_KEY_VERSION.value:02x}) for key {key_number:x}"
        )

        params = get_list(key_number, 1, "big")
        cmd = DESFireCommand.GET_KEY_VERSION.value
        raw_data = self._transceive(
            self._command(cmd, params),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )
        assert len(raw_data) == 1
        return raw_data[0]

    def change_key_settings(self, new_settings: list[DESFireKeySettings]):
        """
        Changes key settings for the application currently selected.

        Authentication:
            Required.

        !!! note "Key settings details"
            Note that the key settings depend on the application that is currently selected.
            Settings are represented as one byte, which is structures as follows:

            ```
            FFFF | AAAA
            0         7
            ```

            The first four bits are flags which control certain settings, such as whether creating and deleting
            applications requires authentication or not. Refer to DESFireKeySettings for more information.

            !!! warning
                Bit 3 (frozen settings) cannot be cleared once it is set.

            The last four bits are only relevant for applications and determine how keys can be changed. Values below
            are represented in hex:

            - 0x0 - 0xD: This specific key can change any key
            - 0xE: Only the key that was used for authentication can be changed
            - 0xF: All keys are locked (except master key, this is controlled by a flag as documented above)

        Example:

        You can use the provided enum (DESFireKeySettings) to set the key settings. For example, to allow
        a change of keys with the app master key, you can use the following code:

        ```python
        change_key_settings([DESFireKeySettings.KS_CHANGE_KEY_WITH_MK])
        ```

        Args:
            new_settings (list[DESFireKeySettings]): List of key settings to apply to the application.
                Refer to the DESFireKeySettings enum for possible values.

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.is_authenticated:
            logger.warning("Tried to change key settings without authentication")
            raise DESFireException("Not authenticated.")

        logger.info(f"Executing command: change_key_settings (0x{DESFireCommand.CHANGE_KEY_SETTINGS.value:02x})")

        key_settings = KeySettings(settings=new_settings)

        # logger.debug('Changing key settings to %s' %('|'.join(a.name for a in newKeySettings),))
        self._transceive(
            self._command(DESFireCommand.CHANGE_KEY_SETTINGS.value, [key_settings.get_settings()]),
            DESFireCommunicationMode.ENCRYPTED,
            DESFireCommunicationMode.CMAC,
        )

    def change_key(self, key_id: int, current_key: DESFireKey, new_key: DESFireKey, new_key_version: int | None = None):
        """
        Changes a key from a current value to a new value. If the key is the one currently used for authentication,
        the authentication session is invalidated.

        Authentication:
            Required.

        Args:
            key_id (int): ID of the key to change. Can also be the key that is currently used for authentication.
            current_key (DESFireKey): Key that is currently in use.
            new_key (DESFireKey): New key to set.
            new_key_version (int | None, optional): Optionally you can set a version for the new key. It is
                for information purposes only and can be used to distinguish between different versions of a key.

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.is_authenticated:
            logger.warning("Tried to change key without authentication")
            raise DESFireException("Not authenticated!")

        logger.info(f"Executing command: change_key (0x{DESFireCommand.CHANGE_KEY.value:02x}) for key {key_id:x}")

        # If we're changing the key we're authenticated with, the message format
        # is different than if we're changing a different key.
        is_same_key = key_id == self.last_auth_key_id
        if is_same_key:
            logger.debug("Changing the key we're authenticated with, need to re-authenticate after")
        else:
            logger.debug("Changing a different key, no need to re-authenticate")

        # Calculate the key number parameter
        # The key_no parameter has 4 bits (MSB, key type) + 4 bits (LSB, key number).
        # The type of key can only be changed for the PICC master key
        # Applications must define their key type in create_application()
        key_number = key_id & 0x0F
        if self.last_selected_application == [0x00]:
            key_number = key_number | current_key.key_type.value
            logger.debug(f"Key number parameter calculated: {to_hex_string([key_number])}")

        # Data to transmit depends on whether we're changing the PICC master key or an application key
        # and whether we're changing the key we're authenticated with or a different one
        data = self._command(DESFireCommand.CHANGE_KEY.value, [key_number])

        # The following can only apply to application keys, as the PICC has only one key (0x00).
        if not is_same_key:
            # If we're changing a different key, new key data is the new key XORed with the old key
            # If we're changing the key type at the same time, we need to XOR the new key with the old key twice
            if len(new_key.get_key()) > len(current_key.get_key()):
                logger.debug("New key is longer than the current key, XORing current key twice")
                data += xor_lists(list(new_key.get_key()), list(current_key.get_key()) * 2)
            else:
                logger.debug("New key is shorter than the current key, XORing current key")
                data += xor_lists(list(new_key.get_key()), list(current_key.get_key()))
        else:
            # If we're changing the key we're authenticated with, new key data is the new key
            data += list(new_key.get_key())

        # If the new key is AES, we need to append the key version
        if new_key.key_type == DESFireKeyType.DF_KEY_AES:
            assert new_key_version is not None
            data += [new_key_version]

        # Regular CRC32 of the data is always appended
        data += CRC32(data)

        # If we're changing a different key, CRC32 of the new key is appended as well
        if not is_same_key:
            logger.debug("Changing a different key, appending CRC32 of new key as well")
            data += CRC32(list(new_key.get_key()))

        # Send the command - auth session is invalidated if we chnge the key we're authenticated with
        self._transceive(
            data,
            tx_mode=DESFireCommunicationMode.ENCRYPTED,
            rx_mode=DESFireCommunicationMode.PLAIN if is_same_key else DESFireCommunicationMode.CMAC,
            disable_crc=True,
            encryption_offset=2,
        )

        # If we changed the currently active key, then re-auth is needed!
        if is_same_key:
            logger.info("Key of authentication change successful, re-authentication is needed")
            self.is_authenticated = False
            self.session_key = None

    def change_default_key(self, new_key: DESFireKey, key_version: int = 0):
        """
        Allows changing the default key that is used as application master key when creating new applications.

        Authentication:
            Required.

        Args:
            new_key (DESFireKey): New key to set as the default key.
            key_version (int, optional): Key version to set when using this key.

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.is_authenticated:
            logger.warning("Tried to change default key without authentication")
            raise DESFireException("Not authenticated!")

        logger.info(f"Executing command: change_default_key (0x{DESFireCommand.SET_CONFIGURATION.value:02x}01)")

        # 0x5C is related to the card configuration, 0x01 is the dedault key
        data = self._command(DESFireCommand.SET_CONFIGURATION.value, [0x01])

        # Append key data and pad it to 24 bytes key length
        data += list(new_key.get_key())
        data += [0x00] * (24 - len(new_key.get_key()))

        # Append key version
        data += [key_version]

        # Send the command, CRC is appended automatically but we need to exclude the first two bytes from encryption
        self._transceive(
            data,
            tx_mode=DESFireCommunicationMode.ENCRYPTED,
            rx_mode=DESFireCommunicationMode.CMAC,
            encryption_offset=2,
        )

    #
    ## Application related
    #

    def get_application_ids(self) -> list[list[int]]:
        """
        Lists all application currently configured on the card.

        Authentication:
            Not required.

        Returns:
            list[list[int]]: List of application IDs, in a 4 byte hex form
        """
        logger.info(f"Executing command: get_application_ids (0x{DESFireCommand.GET_APPLICATION_IDS.value:02x})")

        raw_data = self._transceive(
            self._command(DESFireCommand.GET_APPLICATION_IDS.value),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )
        logger.debug(f"Raw data: {to_hex_string(raw_data)}")

        # Parse App data, each of them is 3 bytes long
        apps = []
        for i in range(0, len(raw_data), 3):
            appid = [raw_data[i + 2]] + [raw_data[i + 1]] + [raw_data[i]]
            logger.debug(f"Found application with AppID {to_hex_string(appid)}")
            apps.append(appid)

        logger.debug(f"Found {len(apps)} applications")
        return apps

    def select_application(self, appid: list[int] | str | bytearray | int | bytes):
        """
        Choose application on a card on which all the following commands will apply.

        Authentication:
            MAY be required depending on the application settings.

        Args:
            appid (list[int] | str | bytearray | int | bytes): ID of the application.
                Will be converted using the `get_list` function.
        """

        parsed_appid = get_list(appid, 3, "big")
        logger.info(f"Selecting application with ID {to_hex_string(parsed_appid)}")

        # TODO: Check why this is reversed after parsing the list big endian above
        parameters = [parsed_appid[2], parsed_appid[1], parsed_appid[0]]

        #  As application selection invalidates auth, there's no need to use CMAC
        self._transceive(
            self._command(DESFireCommand.SELECT_APPLICATION.value, parameters),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.PLAIN,
        )

        # if new application is selected, authentication needs to be carried out again
        logger.debug("Application selected, new authentication is needed")
        self.is_authenticated = False
        self.last_auth_key_id = None
        self.last_selected_application = parsed_appid

    def create_application(
        self, appid: list[int] | str | bytearray | int | bytes, keysettings: KeySettings, keycount: int
    ):
        """
        Creates a new application on the card with the specified settings. The key settings provided are
        applied to the master key of the application.

        Authentication:
            Required.

        Args:
            appid (list[int] | str | bytearray | int | bytes): 3 byte application ID.
                Will be converted using `get_list`.
            keysettings (KeySettings): Key settings to apply to the application.
            keycount (int): Number of keys that can be stored in the application.

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.is_authenticated:
            logger.error("Tried to create application without authentication")
            raise DESFireException("Not authenticated!")

        if not keysettings.settings or not keysettings.key_type:
            logger.error("Key type and key settings must be set in the KeySettings object.")
            raise DESFireException("The key type and key settings must be set in the KeySettings object.")

        if not 0 <= keycount <= 14:
            logger.error("Key count must be between 0 and 14.")
            raise DESFireException("Key count must be between 0 and 14.")

        appid = get_list(appid, 3, "big")
        logger.info(f"Creating application with ID: {to_hex_string(appid)}, ")

        # Structure of the APDU:
        # 0xCA + AppID (3 bytes) + key settings (1 byte) + app settings (4 MSB = key type, 4 LSB = key count)
        params = appid + [keysettings.get_settings()] + [keycount | keysettings.key_type.value]
        cmd = DESFireCommand.CREATE_APPLICATION.value
        self._transceive(
            self._command(cmd, params),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC,
        )
        logger.debug("Application created successfully")

    def delete_application(self, appid: list[int] | str | bytearray | int | bytes):
        """
        Deletes the application specified by appid

        Authentication:
            Required.

        Args:
            appid (list[int] | str | bytearray | int | bytes): 3 byte application ID. Will be converted using `get_list`

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.is_authenticated:
            logger.error("Tried to delete application without authentication")
            raise DESFireException("Not authenticated!")

        appid = get_list(appid, 3, "big")
        logger.info("Deleting application for ID %s", to_hex_string(appid))

        appid.reverse()

        self._transceive(
            self._command(DESFireCommand.DELETE_APPLICATION.value, appid),
            DESFireCommunicationMode.CMAC,
            DESFireCommunicationMode.CMAC,
        )

    #
    ## File related
    #

    def get_file_ids(self) -> list[int]:
        """
        Lists all files belonging to the application currently selected. `select_application` needs to be called first

        Authentication:
            MAY be required depending on the application settings.

        Returns:
            List of file IDs in the application

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.last_selected_application:
            logger.error("Tried to get file IDs without selecting an application")
            raise DESFireException("No application selected, call select_application first")

        logger.info(f"Executing command: get_file_ids (0x{DESFireCommand.GET_FILE_IDS.value:02x})")
        file_ids = []

        raw_data = self._transceive(
            self._command(DESFireCommand.GET_FILE_IDS.value),
            tx_mode=DESFireCommunicationMode.PLAIN,
            rx_mode=DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )

        # Parse the raw data
        if len(raw_data) == 0:
            logger.debug("No files found")
        else:
            for byte in raw_data:
                file_ids.append(byte)
            logger.debug(f"File ids: {''.join([to_hex_string([id]) for id in file_ids])}")

        return file_ids

    def get_file_settings(self, file_id: int) -> FileSettings:
        """
        Gets file settings for the file identified by file_id. `select_application` must be called first.
        Authentication is NOT ALWAYS needed to call this function. Depends on the application/card settings.

        Args:
            file_id (int): ID of the file to get the settings for.

        Authentication:
            MAY be required depending on the application settings.

        Returns:
            Instance of the FileSettings schema containing the parsed file settings

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.last_selected_application:
            raise DESFireException("No application selected, call select_application first")

        file_id_bytes = get_list(file_id, 1, "big")
        logger.info(
            f"Executing command: get_file_settings (0x{DESFireCommand.GET_FILE_SETTINGS.value:02x})"
            f" for file {to_hex_string(file_id_bytes)}"
        )

        # Get the file settings
        raw_data = raw_data = self._transceive(
            self._command(DESFireCommand.GET_FILE_SETTINGS.value, file_id_bytes),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )
        logger.debug(f"Raw data: {to_hex_string(raw_data)}")

        # Parse the raw data
        file_settings = FileSettings()
        file_settings.parse(raw_data)
        logger.debug(f"File settings: {repr(file_settings)}")

        return file_settings

    def read_file_data(self, file_id: int, file_settings: FileSettings) -> list[int]:
        """
        Read file data for file_id. SelectApplication needs to be called first
        Authentication is NOT ALWAYS needed to call this function. Depends on the application/card settings.

        Args:
            file_id (int): ID of the file to get the settings for.
            file_settings (FileSettings): Instance of the FileSettings schema containing the file settings.
                Can be obtained using the `get_file_settings` method.

        Authentication:
            MAY be required depending on the application settings.

        Raises:
            DESFireException: if an invalid configuration is provided

        Returns:
            list[int]: Raw data read from the file
        """

        if not self.last_selected_application:
            logger.error("Tried to read file data without selecting an application")
            raise DESFireException("No application selected, call select_application first")

        assert file_settings.encryption is not None
        logger.info(f"Executing command: read_file_data (0x{DESFireCommand.READ_DATA.value:02x}) for file {file_id:x}")

        file_id_bytes = get_list(file_id, 1)
        length = get_int(file_settings.file_size, "big")
        ioffset = 0
        ret = []

        while length > 0:
            count = min(length, 48)
            logger.debug(f"Reading {count} bytes from offset {ioffset}")
            params = file_id_bytes + get_list(ioffset, 3, "little") + get_list(count, 3, "little")
            ret += self._transceive(
                self._command(DESFireCommand.READ_DATA.value, params),
                DESFireCommunicationMode.PLAIN,
                file_settings.encryption,
            )
            logger.debug(f"Read raw data: {to_hex_string(ret)}")
            ioffset += count
            length -= count

        logger.debug(f"Total data that has been read: {to_hex_string(ret)}")
        return ret

    def create_standard_file(self, file_id: int, file_settings: FileSettings):
        """
        Creates a standard data file in the application currently selected. `select_application` must be called first.

        Authentication:
            MAY be required depending on the application settings.

        Args:
            file_id (int): ID of the file to get the settings for.
            file_settings (FileSettings): Instance of the FileSettings schema containing the file settings that
                should be applied to the file.

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.last_selected_application:
            logger.error("Tried to create file without selecting an application")
            raise DESFireException("No application selected, call select_application first")

        if not 0 <= file_settings.file_size <= 0xFF:
            logger.error("File size must be between 0 and 255 (single byte)")
            raise DESFireException("File size must be between 0 and 255 (single byte)")

        logger.info(
            "Executing command: create_standard_file"
            " (0x{DESFireCommand.CREATE_STD_DATA_FILE.value:02x}) on file {file_id:x}"
        )

        assert file_settings.encryption is not None
        assert file_settings.permissions is not None

        data: list[int] = get_list(file_id, 1, "big")
        data += [file_settings.encryption.value]
        data += file_settings.permissions.get_permissions()

        # File size is stored in little endian
        data += get_list(file_settings.file_size, 3, "little")

        self._transceive(
            self._command(DESFireCommand.CREATE_STD_DATA_FILE.value, data),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )

    def write_file_data(self, file_id: int, offset: int, communication_mode: DESFireCommunicationMode, data: list[int]):
        """
        Writes data to the file specified by file_id

        Authentication:
            MAY be required depending on the application settings.

        Args:
            file_id (int): ID of the file to get the settings for.
            offset (int): Offset in the file to write the data to.
            communication_mode (DESFireCommunicationMode): Communication mode to use for the data transfer.
                Depends on the file settings that were applied when creating the file.
            data (list[int]): Data to write to the file.

        !!! warning
            The data length must not exceed the maximum frame size of 60 bytes.
            It is possible to write longer data, but this is currently not implemented in this library.

        Raises:
            DESFireException: if an invalid configuration is provided
        """
        if not self.last_selected_application:
            logger.error("Tried to write file data without selecting an application")
            raise DESFireException("No application selected, call select_application first")

        logger.info(
            f"Executing command: write_file_data (0x{DESFireCommand.WRITE_DATA.value:02x}) for file {file_id:x}"
        )

        max_length = self.max_frame_size - 1 - 7  # 60 - CMD - CMD Header
        length = len(data)
        if length > max_length:
            logger.error(f"Data length exceeds maximum frame size of {max_length}, not supported yet.")
            raise DESFireException(f"Data length exceeds maximum frame size of {max_length}, not supported yet.")

        file_id_bytes = [file_id]
        offset_bytes = get_list(offset, 3, "little")  # Left aligned
        length_bytes = get_list(length, 3, "little")  # Left aligned

        params = file_id_bytes + offset_bytes + length_bytes + data
        self._transceive(
            self._command(DESFireCommand.WRITE_DATA.value, params),
            communication_mode,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
            # Command (1 byte) + header file number (1 byte), data length (3 bytes) and offset (3 bytes)
            encryption_offset=8,
        )

    def delete_file(self, file_id: int):
        """
        Deletes the file specified by file_id

        Authentication:
            MAY be required depending on the application settings.

        Args:
            file_id (int): ID of the file to get the settings for.

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.last_selected_application:
            logger.error("Tried to delete file without selecting an application")
            raise DESFireException("No application selected, call select_application first")

        logger.info(f"Executing command: delete_file (0x{DESFireCommand.DELETE_FILE.value:02x}) for file {file_id:x}")

        self._transceive(
            self._command(DESFireCommand.DELETE_FILE.value, get_list(file_id, 1, "little")),
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.PLAIN,
        )
