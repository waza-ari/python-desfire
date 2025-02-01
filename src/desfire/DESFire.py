import logging

from Crypto.Random import get_random_bytes
from smartcard.util import toHexString

from .enums import DESFireCommand, DESFireCommunicationMode, DESFireKeySettings, DESFireKeyType, DESFireStatus
from .exceptions import DESFireAuthException, DESFireCommunicationError, DESFireException
from .key import DESFireKey
from .pcsc import Device
from .schemas import FileSettings, KeySettings
from .schemas.card_version import DESFireCardVersion
from .util import CRC32, get_int, get_list, xor_lists


class DESFire:
    """
    This is the main class of this library, facilitating communication with the DESFire card.
    """

    is_authenticated: bool = False
    session_key: DESFireKey | None = None
    max_frame_size: int = 60
    last_selected_application: list[int] | None = None
    last_auth_key_id: int | None = None

    def __init__(self, device: Device, logger: logging.Logger | None = None):
        """
        Initializes a new DESfire object which can be used to interact with the card.
        Requires an initialized PCSC device object, refer to the examples for details and uage examples.
        """
        self.device = device

        # Set up logging if not externally provided
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger(__name__)

    #
    # Internal Methods
    #

    def _communicate(self, apdu_cmd: list[int], native: bool = True, af_passthrough: bool = False):
        """
        Communicate with a NFC tag. Send in outgoing request and wait for a card reply.

        :param apdu_cmd: Outgoing APDU command as array of bytes
        :type apdu_cmd: bytearray
        :param native: True indicates that DESfire native commands are used, otherwise ISO 7816 APDUs are used
        :type native: bool
        :param af_passthrough: If true, a 0xAF response (indicating more incoming data) is instantly
            returned to the callee instead of trying to handle it internally
        :type af_passthrough: bool
        """

        result: list[int] = []
        additional_data: bool = True
        # current_command: bytearray = apdu_cmd

        # Loop until all data is received
        while additional_data:
            # Send the APDU command to the card
            self.logger.debug("Running APDU command, sending: %s", toHexString(apdu_cmd))
            resp = self.device.transceive(apdu_cmd)
            self.logger.debug("Received APDU response: %s", toHexString(resp))

            # DESfire native commands are used
            if native:
                status = resp[0]
                # Check for known error interpretation
                if status == 0xAF:
                    if af_passthrough:
                        additional_data = False
                    else:
                        # Need to loop more cycles to fill in receive buffer
                        additional_data = True
                        apdu_cmd = self._command(0xAF)  # Continue
                elif status != 0x00:
                    try:
                        error_description = DESFireStatus(status).name
                    except ValueError:
                        error_description = "Unknown error"
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
        return data + [0x80] + [0x00] * (padding - 1)

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
        encryption_offset: int = 0,
    ) -> list[int]:
        """
        Preprocess the command before sending it to the card.
        This includes adding the padding and the CRC if needed.
        """

        # If not authenticated, we don't need to do anything
        if not self.is_authenticated:
            return apdu_cmd

        assert self.session_key is not None

        # Preprocess the command
        if tx_mode == DESFireCommunicationMode.PLAIN:
            # We don't do anything with the CMAC, but it does update the IV for future crypto operations
            self.session_key.calculate_cmac(apdu_cmd)
            return apdu_cmd
        elif tx_mode == DESFireCommunicationMode.CMAC:
            # Calculate the CMAC and append it to the command
            tx_cmac = self.session_key.calculate_cmac(apdu_cmd)
            # Only the last 8 bytes of the CMAC are used
            return apdu_cmd + tx_cmac[-8:]
        elif tx_mode == DESFireCommunicationMode.ENCRYPTED:
            assert self.session_key.cipher_block_size is not None

            # Encrypt the command + data
            resp_data = self.session_key.encrypt_msg(apdu_cmd, disable_crc=disable_crc, offset=encryption_offset)

            # Update IV to the last block of the encrypted data
            self.session_key.set_iv(resp_data[-self.session_key.cipher_block_size :])

            # Return encrypted data
            return resp_data
        else:
            raise Exception("Invalid communication mode")

    def _postprocess(self, response: list[int], rx_mode: DESFireCommunicationMode) -> list[int]:
        """
        Postprocess the response from the card.
        """

        # PLAIN response is only possible if we're not authenticated
        if rx_mode == DESFireCommunicationMode.PLAIN:
            return response
        # CMAC response is only possible if we're authenticated
        elif rx_mode == DESFireCommunicationMode.CMAC:
            """
            The CMAC is calculated over the payload of the response (i.e after the status byte) and then the status byte
            appended to the end. If the response is multiple parts then the payload of these parts are concatenated
            (without the AF status byte) and the final status byte added to the end.
            """
            # Check if the CMAC is correct
            assert self.session_key is not None
            # Calculate the CMAC of the data
            cmac_data = response[:-8] + [0x00]
            self.logger.debug("Calculating CMAC for data: " + toHexString(cmac_data))
            calculated_cmac = self.session_key.calculate_cmac(cmac_data)[:8]
            self.logger.debug("RXCMAC      : " + toHexString(response[-8:]))
            self.logger.debug("RXCMAC_CALC : " + toHexString(calculated_cmac))
            if bytes(response[-8:]) != bytes(calculated_cmac):
                raise Exception("CMAC verification failed!")
            return response[:-8]
        # ENCRYPTED response is only possible if we're authenticated
        elif rx_mode == DESFireCommunicationMode.ENCRYPTED:
            """
            The response is encrypted using the session key. The response is padded with 0x80 followed by 0x00 bytes
            until the end of the block. The IV is updated with the last block of the encrypted data.
            """
            assert self.session_key is not None
            assert self.session_key.cipher_block_size is not None

            # Decrypt the response
            padded_response = self._add_padding(response)
            self.logger.debug("Padded response: " + toHexString(padded_response))
            decrypted_response = self.session_key.decrypt(padded_response)
            self.logger.debug("Decrypted response: " + toHexString(decrypted_response))

            # Update IV to the last block of the encrypted data
            self.session_key.set_iv(response[-self.session_key.cipher_block_size :])

            # Remove all null bytes from the end
            while decrypted_response[-1] == 0x00:
                decrypted_response = decrypted_response[:-1]

            # Check if the CRC is correct - Status byte is appended to the data before CRC calculation
            crc_bytes = 4  # 2 (CRC16) is only needed for legacy authentication, which we do not support (only ISO+AES)
            received_crc = decrypted_response[-crc_bytes:]
            self.logger.debug("Received CRC  : " + toHexString(received_crc))
            calculated_crc = CRC32(decrypted_response[:-crc_bytes] + [0x00])
            self.logger.debug("Calculated CRC: " + toHexString(calculated_crc))

            if bytes(received_crc) != bytes(calculated_crc):
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
        encryption_offset: int = 0,
    ) -> list[int]:
        """
        Communicate with the card. This is the main function that sends the APDU command and performs
        neccessary pre- and postprocessing of the data. It also handles the CMAC calculation and
        encryption/decryption of the communication if needed.
        """

        # Check for existing of session key if needed
        if tx_mode != DESFireCommunicationMode.PLAIN or rx_mode != DESFireCommunicationMode.PLAIN:
            if not self.is_authenticated:
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

    @classmethod
    def wrap_command(cls, command: int, parameters: list[int] | None = None) -> list[int]:
        """
        Wrap a command to native DES framing.

        :param command: Command byte
        :param parameters: Command parameters as list of bytes
        """
        if parameters:
            return [0x90, command, 0x00, 0x00, len(parameters)] + parameters + [0x00]
        else:
            return [0x90, command, 0x00, 0x00, 0x00]

    # Authentication

    def authenticate(self, key_id: int, key: DESFireKey, challenge: str | bytearray | int | bytes | None = None):
        """
        Authenticate against the currently selected application with key_id.
        Authentication is NEVER needed to call this function.

        :param key_id: Key ID to authenticate with
        :type key_id: int
        :param key: The DESFireKey instance used for authentication
        :type key: DESFireKey
        :param challenge: The challenge supplied by the reader to the card on the challenge-response authentication.
            It will determine half of the session Key bytes (optional)
        :type challenge: str | None
        """
        assert key.cipher_block_size is not None
        self.logger.debug("Authenticating")
        self.is_authenticated = False

        # Determine the authentication command based on the key type
        if key.key_type == DESFireKeyType.DF_KEY_AES:
            self.logger.debug("Authenticating with AES key")
            cmd = DESFireCommand.DFEV1_INS_AUTHENTICATE_AES.value
            params = [key_id]
        elif key.key_type == DESFireKeyType.DF_KEY_2K3DES or key.key_type == DESFireKeyType.DF_KEY_3K3DES:
            self.logger.debug("Authenticating with DES/3DES key")
            cmd = DESFireCommand.DFEV1_INS_AUTHENTICATE_ISO.value
            params = [key_id]
        else:
            raise Exception("Invalid key type!")

        # First part of three way handshake - Initial authentication and retrieve RND_B from card
        # AF_Passthrough is required as the card will respond with 0xAF as challenge response
        RndB_enc = self._transceive(
            self._command(cmd, params),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.PLAIN,
            af_passthrough=True,
        )
        self.logger.debug("Random B (enc):" + toHexString(RndB_enc))

        # Check if the key type is correct
        if (key.key_type == DESFireKeyType.DF_KEY_3K3DES or key.key_type == DESFireKeyType.DF_KEY_AES) and len(
            RndB_enc
        ) != 16:
            raise DESFireAuthException(
                "Card expects a different key type. (enc B size is less than the blocksize of the key you specified)"
            )

        # Reinitalize the cipher object of the key
        key.cipher_init()

        # Decrypt the RndB using the provided master key
        RndB = key.decrypt(RndB_enc)
        self.logger.debug("Random B (dec): " + toHexString(RndB))

        # Rotate RndB to the left by one byte
        RndB_rot = RndB[1:] + [RndB[0]]
        self.logger.debug("Random B (dec, rot): " + toHexString(RndB_rot))

        # Challenge can be either provided externally, or generated randomly
        if challenge is not None:
            RndA = get_list(challenge)
        else:
            RndA = get_list(get_random_bytes(len(RndB)))
        self.logger.debug("Random A: " + toHexString(RndA))

        # Concatenate RndA and RndB_rot and encrypt it with the master key
        RndAB = list(RndA) + RndB_rot
        self.logger.debug("Random AB: " + toHexString(RndAB))
        key.set_iv(RndB_enc)
        RndAB_enc = key.encrypt(RndAB)
        self.logger.debug("Random AB (enc): " + toHexString(RndAB_enc))

        # Send the encrypted RndAB to the card, it should reply with a positive result
        params = RndAB_enc
        cmd = DESFireCommand.DF_INS_ADDITIONAL_FRAME.value
        RndA_enc = self._transceive(
            self._command(cmd, params), DESFireCommunicationMode.PLAIN, DESFireCommunicationMode.PLAIN
        )

        # Verify that the response matches our original challenge
        self.logger.debug("Random A (enc): " + toHexString(RndA_enc))
        key.set_iv(RndAB_enc[-key.cipher_block_size :])
        RndA_dec = key.decrypt(RndA_enc)
        self.logger.debug("Random A (dec): " + toHexString(RndA_dec))
        RndA_dec_rot = RndA_dec[-1:] + RndA_dec[0:-1]
        self.logger.debug("Random A (dec, rot): " + toHexString(RndA_dec_rot))

        if bytes(RndA) != bytes(RndA_dec_rot):
            raise Exception("Authentication FAILED!")

        self.logger.debug("Authentication success!")
        self.is_authenticated = True
        self.last_auth_key_id = key_id

        self.logger.debug("Calculating Session key")
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
        Gets the real UID of the card. This function requires authentication, any key can be used.
        """
        self.logger.debug("Getting real card UID")

        if not self.is_authenticated:
            raise Exception("Not authenticated!")

        cmd = DESFireCommand.DFEV1_INS_GET_CARD_UID.value
        return self._transceive(self._command(cmd), DESFireCommunicationMode.PLAIN, DESFireCommunicationMode.ENCRYPTED)

    def get_card_version(self) -> DESFireCardVersion:
        """
        Gets card version info blob
        Version info contains the UID, Batch number, production week, production year, .... of the card
        Authentication is NOT needed to call this function
        BEWARE: DESFire card has a security feature called "Random UID" which means that without authentication it will
            give you a random UID each time you call this function!
        """
        self.logger.debug("Getting card version info")
        raw_data = self._transceive(
            self._command(DESFireCommand.DF_INS_GET_VERSION.value),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )
        return DESFireCardVersion(raw_data)

    def format_card(self):
        """
        Formats the card
        WARNING! THIS COMPLETELY WIPES THE CARD AND RESETS IF TO A BLANK CARD!!
        Authentication using the App 0 master key is needed to call this function
        """
        self.logger.debug("Formatting card")
        cmd = DESFireCommand.DF_INS_FORMAT_PICC.value
        self._transceive(self._command(cmd), DESFireCommunicationMode.PLAIN, DESFireCommunicationMode.PLAIN)

    #
    ## Key Related
    #

    def get_key_setting(self) -> KeySettings:
        """
        Gets the key settings for the master key of the application currently selected.

        It returns two bytes, where the first byte contains the key settings for the current application
        as described in the change_key_settings method. The second byte is structured as follows:

        KKKK|DDDD
        7       0

        K: Determines the key type as defined in the DESFireKeyType enum
        D: Maximum number of keys that are allowed by the application

        D seems to be always 1 for the main appliction (0x0).

        CMAC is used for communication if authenticated, otherwise plain communication is used.
        """
        resp = self._transceive(
            self._command(DESFireCommand.DF_INS_GET_KEY_SETTINGS.value),
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
        Returns the version of the key, which is a one byte identifier that can be set when the key is created.
        It is typically used to distinguish between different versions of the same key in use.

        Authentication is ALWAYS needed to call this function.

        Returns a single byte containing the custom version information.
        """
        self.logger.debug(f"Getting key version for keyid {key_number:x}")

        params = get_list(key_number, 1, "big")
        cmd = DESFireCommand.DF_INS_GET_KEY_VERSION.value
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
        Authentication is ALWAYS needed to call this function.

        Note that the key settings depend on the application that is currently selected.
        Settings are represented as one byte, which is structures as follows:

        FFFF|AAAA
        0       7

        The first four bits are flags which control certain settings, such as whether creating and deleting
        applications requires authentication or not. Refer to DESFireKeySettings for more information.

        WARNING: Bit 3 (frozen settings) cannot be cleared once it is set.

        The last four bits are only relevant for applications and determine how keys can be changed. Values below
        are represented in hex:

        - 0x0 - 0xD: This specific key can change any key
        - 0xE: Only the key that was used for authentication can be changed
        - 0xF: All keys are locked (except master key, this is controlled by a flag as documented above)
        """

        if not self.is_authenticated:
            raise DESFireException("Not authenticated.")

        key_settings = KeySettings(
            settings=new_settings,
        )

        # self.logger.debug('Changing key settings to %s' %('|'.join(a.name for a in newKeySettings),))
        self._transceive(
            self._command(DESFireCommand.DF_INS_CHANGE_KEY_SETTINGS.value, [key_settings.get_settings()]),
            DESFireCommunicationMode.ENCRYPTED,
            DESFireCommunicationMode.CMAC,
        )

    def change_key(self, key_id: int, current_key: DESFireKey, new_key: DESFireKey, new_key_version: int | None = None):
        """
        Changes current key (curKey) to a new one (newKey) in specified keyslot (keyno)
        Authentication is ALWAYS needed to call this function.
        """

        self.logger.debug(f" -- Changing key {key_id} --")

        if not self.is_authenticated:
            raise DESFireException("Not authenticated!")

        self.logger.debug("curKey : " + toHexString(list(current_key.get_key())))
        self.logger.debug("newKey : " + toHexString(list(new_key.get_key())))

        # If we're changing the key we're authenticated with, the message format
        # is different than if we're changing a different key.
        is_same_key = key_id == self.last_auth_key_id
        self.logger.info(f"Are we changing the key we're authenticated with: {is_same_key}")

        # Calculate the key number parameter
        # The key_no parameter has 4 bits (MSB, key type) + 4 bits (LSB, key number).
        # The type of key can only be changed for the PICC master key
        # Applications must define their key type in create_application()
        key_number = key_id & 0x0F
        if self.last_selected_application == [0x00]:
            key_number = key_number | current_key.key_type.value

        # Data to transmit depends on whether we're changing the PICC master key or an application key
        # and whether we're changing the key we're authenticated with or a different one
        data = self._command(DESFireCommand.DF_INS_CHANGE_KEY.value, [key_number])

        # The following can only apply to application keys, as the PICC has only one key (0x00).
        if not is_same_key:
            # If we're changing a different key, new key data is the new key XORed with the old key
            # If we're changing the key type at the same time, we need to XOR the new key with the old key twice
            if len(new_key.get_key()) > len(current_key.get_key()):
                data += xor_lists(list(new_key.get_key()), list(current_key.get_key()) * 2)
            else:
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
            self.is_authenticated = False
            self.session_key = None

        return

    def change_default_key(self, new_key: DESFireKey, key_version: int = 0):
        """
        The default key is used as application master key when creating new applications

        Uses command 0x5C01
        """

        if not self.is_authenticated:
            raise DESFireException("Not authenticated!")

        # 0x5C is related to the card configuration, 0x01 is the dedault key
        data = self._command(DESFireCommand.DFEV1_INS_SET_CONFIGURATION.value, [0x01])

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

        return

    #
    ## Application related
    #

    def get_application_ids(self) -> list[list[int]]:
        """
        Lists all application on the card. Authentication is NOT needed to call this function
        Returns a list of application IDs, in a 4 byte hex form
        """
        self.logger.debug("Fetching application IDs")

        raw_data = self._transceive(
            self._command(DESFireCommand.DF_INS_GET_APPLICATION_IDS.value),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )

        pointer = 0
        apps = []
        while pointer < len(raw_data):
            appid = [raw_data[pointer + 2]] + [raw_data[pointer + 1]] + [raw_data[pointer]]
            self.logger.debug("Reading %s", toHexString(appid))
            apps.append(appid)
            pointer += 3

        return apps

    def select_application(self, appid: str | bytearray | bytes | int):
        """
        Choose application on a card on which all the following commands will apply.
        Authentication is NOT ALWAYS needed to call this function. Depends on the application settings.
        """
        parsed_appid = get_list(appid, 3, "big")
        self.logger.debug(f"Selecting application with AppID {toHexString(parsed_appid)}")

        # TODO: Check why this is reversed after parsing the list big endian above
        parameters = [parsed_appid[2], parsed_appid[1], parsed_appid[0]]

        #  As application selection invalidates auth, there's no need to use CMAC
        self._transceive(
            self._command(DESFireCommand.DF_INS_SELECT_APPLICATION.value, parameters),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.PLAIN,
        )

        # if new application is selected, authentication needs to be carried out again
        self.is_authenticated = False
        self.last_auth_key_id = None
        self.last_selected_application = parsed_appid

    def create_application(self, appid: list[int] | str, keysettings: KeySettings, keycount: int):
        """
        Creates application on the card with the specified settings
        Authentication is ALWAYS needed before calling this function.
        """

        if not self.is_authenticated:
            raise Exception("Not authenticated!")

        if not keysettings.settings or not keysettings.key_type:
            raise Exception("The key type and key settings must be set in the KeySettings object.")

        if not 0 <= keycount <= 14:
            raise Exception("Key count must be between 0 and 14.")

        if isinstance(appid, str):
            appid = get_list(appid, 2, "big")

        self.logger.debug(f"Creating application with appid: {toHexString(appid)}, ")

        # Structure of the APDU:
        # 0xCA + AppID (3 bytes) + key settings (1 byte) + app settings (4 MSB = key type, 4 LSB = key count)
        params = appid + [keysettings.get_settings()] + [keycount | keysettings.key_type.value]
        cmd = DESFireCommand.DF_INS_CREATE_APPLICATION.value
        self._transceive(
            self._command(cmd, params),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC,
        )

    def deleteApplication(self, appid: list[int] | str):
        """
        Deletes the application specified by appid
        Authentication is ALWAYS needed to call this function.
        """

        if not self.is_authenticated:
            raise Exception("Not authenticated!")

        if isinstance(appid, str):
            appid = get_list(appid, 2, "big")

        self.logger.debug("Deleting application for AppID %s", toHexString(appid))

        appid.reverse()

        self._transceive(
            self._command(DESFireCommand.DF_INS_DELETE_APPLICATION.value, appid),
            DESFireCommunicationMode.CMAC,
            DESFireCommunicationMode.CMAC,
        )

    #
    ## File related
    #

    def get_file_ids(self):
        """
        Lists all files belonging to the application currently selected.
        SelectApplication needs to be called first
        Authentication is NOT ALWAYS needed to call this function. Depends on the application/card settings.
        """

        if not self.last_selected_application:
            raise DESFireException("No application selected, call select_application first")

        self.logger.debug("Enumerating all files for the selected application")
        file_ids = []

        raw_data = self._transceive(
            self._command(DESFireCommand.DF_INS_GET_FILE_IDS.value),
            tx_mode=DESFireCommunicationMode.PLAIN,
            rx_mode=DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )

        # Parse the raw data
        if len(raw_data) == 0:
            self.logger.debug("No files found")
        else:
            for byte in raw_data:
                file_ids.append(byte)
            self.logger.debug(f"File ids: {''.join([toHexString([id]) for id in file_ids])}")

        return file_ids

    def get_file_settings(self, file_id: int) -> FileSettings:
        """
        Gets file settings for the File identified by file_id.
        SelectApplication needs to be called first.
        Authentication is NOT ALWAYS needed to call this function. Depends on the application/card settings.
        """

        if not self.last_selected_application:
            raise DESFireException("No application selected, call select_application first")

        file_id_bytes = get_list(file_id, 1, "big")
        self.logger.debug(f"Getting file settings for file {toHexString(file_id_bytes)}")

        # Get the file settings
        raw_data = raw_data = self._transceive(
            self._command(DESFireCommand.DF_INS_GET_FILE_SETTINGS.value, file_id_bytes),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )

        # Parse the raw data
        file_settings = FileSettings()
        file_settings.parse(raw_data)
        return file_settings

    def read_file_data(self, file_id: int, file_settings: FileSettings):
        """
        Read file data for file_id. SelectApplication needs to be called first
        Authentication is NOT ALWAYS needed to call this function. Depends on the application/card settings.
        """

        if not self.last_selected_application:
            raise DESFireException("No application selected, call select_application first")

        assert file_settings.encryption is not None

        file_id_bytes = get_list(file_id, 1)
        length = get_int(file_settings.file_size, "big")
        ioffset = 0
        ret = []

        while length > 0:
            count = min(length, 48)
            params = file_id_bytes + get_list(ioffset, 3, "little") + get_list(count, 3, "little")
            ret += self._transceive(
                self._command(DESFireCommand.DF_INS_READ_DATA.value, params),
                DESFireCommunicationMode.PLAIN,
                file_settings.encryption,
            )
            ioffset += count
            length -= count

        return ret

    def delete_file(self, file_id: int):
        """
        Deletes the file specified by file_id
        """

        if not self.last_selected_application:
            raise DESFireException("No application selected, call select_application first")

        return self._transceive(
            self._command(DESFireCommand.DF_INS_DELETE_FILE.value, get_list(file_id, 1, "little")),
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.PLAIN,
        )

    ###################################################################################################################
    ### This Function is not refactored
    ###################################################################################################################

    ###### FILE FUNTCIONS

    def writeFileData(self, fileId, offset, length, data):
        fileId = get_list(fileId, 1)
        offset = get_int(offset, "big")
        length = get_int(length, "big")
        data = get_list(data)
        ioffset = 0

        while length > 0:
            count = min(length, self.max_frame_size - 8)
            cmd = DESFireCommand.DF_INS_WRITE_DATA.value
            params = (
                fileId
                + get_list(offset + ioffset, 3, "little")
                + get_list(count, 3, "little")
                + data[ioffset : (ioffset + count)]
            )
            self.communicate(
                self._command(cmd, params),
                with_tx_cmac=self.is_authenticated,
            )
            ioffset += count
            length -= count

    def createStdDataFile(self, fileId, filePermissions, fileSize):
        params = get_list(fileId, 1, "big")
        params += [0x00]
        params += get_list(filePermissions.pack(), 2, "big")
        params += get_list(get_int(fileSize, "big"), 3, "little")
        apdu_command = self._command(DESFireCommand.DF_INS_CREATE_STD_DATA_FILE.value, params)
        self.communicate(
            apdu_command,
            with_tx_cmac=self.is_authenticated,
        )
        return
