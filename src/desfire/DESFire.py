import logging

from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

from .enums import DESFireCommand, DESFireCommunicationMode, DESFireKeyType, DESFireStatus
from .exceptions import DESFireAuthException, DESFireCommunicationError, DESFireException
from .file.settings import DESFireFileSettings
from .key.card_version import DESFireCardVersion
from .key.key import DESFireKey
from .pcsc import Device
from .util import CRC32, calc_key_settings, get_int, get_list, to_human_readable_hex


class DESFire:
    """
    This is the main class of this library, facilitating communication with the DESFire card.
    """

    is_authenticated: bool = False
    session_key: DESFireKey | None = None
    max_frame_size: int = 60
    last_selected_application: int | None = None

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
            self.logger.debug("Running APDU command, sending: %s", to_human_readable_hex(apdu_cmd))
            resp = self.device.transceive(apdu_cmd)
            self.logger.debug("Received APDU response: %s", to_human_readable_hex(resp))

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

    def _preprocess(self, apdu_cmd: list[int], tx_mode: DESFireCommunicationMode) -> list[int]:
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
            # Encrypt the command
            return self.session_key.encrypt_msg(apdu_cmd, with_crc=True)
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
            self.logger.debug("Calculating CMAC for data: " + to_human_readable_hex(cmac_data))
            calculated_cmac = self.session_key.calculate_cmac(cmac_data)[:8]
            self.logger.debug("RXCMAC      : " + to_human_readable_hex(response[-8:]))
            self.logger.debug("RXCMAC_CALC : " + to_human_readable_hex(calculated_cmac))
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
            self.logger.debug("Padded response: " + to_human_readable_hex(padded_response))
            decrypted_response = self.session_key.decrypt(padded_response)
            self.logger.debug("Decrypted response: " + to_human_readable_hex(response))

            # Update IV to the last block of the encrypted data
            self.session_key.set_iv(response[-self.session_key.cipher_block_size :])

            # Remove all null bytes from the end
            while decrypted_response[-1] == 0x00:
                decrypted_response = decrypted_response[:-1]

            # Check if the CRC is correct - Status byte is appended to the data before CRC calculation
            crc_bytes = (
                4 if self.session_key.key_type in [DESFireKeyType.DF_KEY_AES, DESFireKeyType.DF_KEY_3K3DES] else 2
            )
            received_crc = decrypted_response[-crc_bytes:]
            self.logger.debug("Received CRC  : " + to_human_readable_hex(received_crc))
            calculated_crc = CRC32(decrypted_response[:-crc_bytes] + [0x00])
            self.logger.debug("Calculated CRC: " + to_human_readable_hex(calculated_crc))

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
        apdu_cmd = self._preprocess(apdu_cmd, tx_mode)

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
            self.logger.debug("Authenticating with 3DES key")
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
        self.logger.debug("Random B (enc):" + to_human_readable_hex(RndB_enc))

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
        self.logger.debug("Random B (dec): " + to_human_readable_hex(RndB))

        # Rotate RndB to the left by one byte
        RndB_rot = RndB[1:] + [RndB[0]]
        self.logger.debug("Random B (dec, rot): " + to_human_readable_hex(RndB_rot))

        # Challenge can be either provided externally, or generated randomly
        if challenge is not None:
            RndA = get_list(challenge)
        else:
            RndA = get_list(get_random_bytes(len(RndB)))
        self.logger.debug("Random A: " + to_human_readable_hex(RndA))

        # Concatenate RndA and RndB_rot and encrypt it with the master key
        RndAB = list(RndA) + RndB_rot
        self.logger.debug("Random AB: " + to_human_readable_hex(RndAB))
        key.set_iv(RndB_enc)
        RndAB_enc = key.encrypt(RndAB)
        self.logger.debug("Random AB (enc): " + to_human_readable_hex(RndAB_enc))

        # Send the encrypted RndAB to the card, it should reply with a positive result
        params = RndAB_enc
        cmd = DESFireCommand.DF_INS_ADDITIONAL_FRAME.value
        RndA_enc = self._transceive(
            self._command(cmd, params), DESFireCommunicationMode.PLAIN, DESFireCommunicationMode.PLAIN
        )

        # Verify that the response matches our original challenge
        self.logger.debug("Random A (enc): " + to_human_readable_hex(RndA_enc))
        key.set_iv(RndAB_enc[-key.cipher_block_size :])
        RndA_dec = key.decrypt(RndA_enc)
        self.logger.debug("Random A (dec): " + to_human_readable_hex(RndA_dec))
        RndA_dec_rot = RndA_dec[-1:] + RndA_dec[0:-1]
        self.logger.debug("Random A (dec, rot): " + to_human_readable_hex(RndA_dec_rot))

        if bytes(RndA) != bytes(RndA_dec_rot):
            raise Exception("Authentication FAILED!")

        self.logger.debug("Authentication success!")
        self.is_authenticated = True
        self.lastAuthKeyNo = key_id  # TODO: Verify if this is needed

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

    def get_card_version(self):
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

    #
    ## Key Related
    #

    def get_key_setting(self) -> DESFireKey:
        """
        Gets the key settings for the currently selected application.

        CMAC is used for communication if authenticated, otherwise plain communication is used.
        """
        resp = self._transceive(
            self._command(DESFireCommand.DF_INS_GET_KEY_SETTINGS.value),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )
        ret = DESFireKey()
        ret.set_key_settings(resp[1] & 0x0F, DESFireKeyType(resp[1] & 0xF0), resp[0] & 0x07)
        return ret

    def get_key_version(self, key_number: int) -> list[int]:
        """
        Gets the key version for the key identified by keyno.
        SelectApplication needs to be called first, otherwise it's getting the settings for the Master Key
        Authentication is ALWAYS needed to call this function.
        """
        self.logger.debug(f"Getting key version for keyid {key_number:x}")

        params = get_list(key_number, 1, "big")
        cmd = DESFireCommand.DF_INS_GET_KEY_VERSION.value
        raw_data = self._transceive(
            self._command(cmd, params),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )
        return raw_data

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
            DESFireCommunicationMode.PLAIN,
        )

        pointer = 0
        apps = []
        while pointer < len(raw_data):
            appid = [raw_data[pointer + 2]] + [raw_data[pointer + 1]] + [raw_data[pointer]]
            self.logger.debug("Reading %s", to_human_readable_hex(appid))
            apps.append(appid)
            pointer += 3

        return apps

    def select_application(self, appid: int):
        """
        Choose application on a card on which all the following commands will apply.
        Authentication is NOT ALWAYS needed to call this function. Depends on the application settings.
        """
        parsed_appid = get_list(appid, 3, "big")
        self.logger.debug(f"Selecting application with AppID {to_human_readable_hex(parsed_appid)}")

        # TODO: Check why this is reversed after parsing the list big endian above
        parameters = [parsed_appid[2], parsed_appid[1], parsed_appid[0]]

        # If we are authenticated, we use CMAC for communication, otherwise we use plain communication
        communication_mode = DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN
        self._transceive(
            self._command(DESFireCommand.DF_INS_SELECT_APPLICATION.value, parameters),
            communication_mode,
            communication_mode,
        )

        # if new application is selected, authentication needs to be carried out again
        self.is_authenticated = False
        self.last_selected_application = appid

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
            self.logger.debug(f"File ids: {''.join([to_human_readable_hex(bytearray([id])) for id in file_ids])}")

        return file_ids

    def get_file_settings(self, file_id: int) -> DESFireFileSettings:
        """
        Gets file settings for the File identified by file_id.
        SelectApplication needs to be called first.
        Authentication is NOT ALWAYS needed to call this function. Depends on the application/card settings.
        """

        if not self.last_selected_application:
            raise DESFireException("No application selected, call select_application first")

        file_id_bytes = get_list(file_id, 1, "big")
        self.logger.debug(f"Getting file settings for file {to_human_readable_hex(file_id_bytes)}")

        # Get the file settings
        raw_data = raw_data = self._transceive(
            self._command(DESFireCommand.DF_INS_GET_FILE_SETTINGS.value, file_id_bytes),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )

        # Parse the raw data
        file_settings = DESFireFileSettings()
        file_settings.parse(raw_data)
        return file_settings

    def read_file_data(self, file_id: int, file_settings: DESFireFileSettings):
        """
        Read file data for file_id
        SelectApplication needs to be called first
        Authentication is NOT ALWAYS needed to call this function. Depends on the application/card settings.
        """

        if not self.last_selected_application:
            raise DESFireException("No application selected, call select_application first")

        assert file_settings.encryption is not None

        file_id_bytes = get_list(file_id, 1)
        length = get_int(file_settings.FileSize, "big")
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

    ###################################
    ### TO BE DONE

    def formatCard(self):
        """
        Formats the card
        WARNING! THIS COMPLETELY WIPES THE CARD AND RESETS IF TO A BLANK CARD!!
        Authentication is needed to call this function
        Args:
            None
        Returns:
            None
        """
        self.logger.debug("Formatting card")
        cmd = DESFireCommand.DF_INS_FORMAT_PICC.value
        self.communicate([cmd], with_tx_cmac=self.is_authenticated)

    ###### Application related

    def createApplication(self, appid, keysettings, keycount, type):
        """
        Creates application on the card with the specified settings
        Authentication is ALWAYS needed before calling this function.


        :param appid: The application ID of the app to be created
        :type appid:
        :param keysettings: Key settings to be applied to the application to be created.
            MUST contain entryes derived from the DESFireKeySettings enum
        :type keysettings:
        :param keycount:
        :type keycount:
        :param type: Key type that will specify the encryption used for authenticating to this application and
            communication with it.MUST be coming from the DESFireKeyType enum
        :type type:
        """

        appid = get_list(appid, 3, "big")
        self.logger.debug(f"Creating application with appid: {to_human_readable_hex(appid)}, ")
        appid = [appid[2], appid[1], appid[0]]
        keycount = get_int(keycount, "big")
        params = appid + [calc_key_settings(keysettings)] + [keycount | type.value]
        cmd = DESFireCommand.DF_INS_CREATE_APPLICATION.value
        self.communicate(
            self._command(cmd, params),
            with_tx_cmac=self.is_authenticated,
        )

    def deleteApplication(self, appid):
        """Deletes the application specified by appid
        Authentication is ALWAYS needed to call this function.
        Args:
            appid (int)       : The application ID of the app to be deleted
        Returns:
            None
        """
        appid = get_list(appid, 3, "big")
        self.logger.debug("Deleting application for AppID %s", to_human_readable_hex(appid))

        appid = [appid[2], appid[1], appid[0]]

        params = appid
        cmd = DESFireCommand.DF_INS_DELETE_APPLICATION.value
        self.communicate(
            self._command(cmd, params),
            with_tx_cmac=self.is_authenticated,
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

    def deleteFile(self, fileId):
        return self.communicate(
            self._command(DESFireCommand.DF_INS_DELETE_FILE.value, get_list(fileId, 1, "little")),
            with_tx_cmac=self.is_authenticated,
        )

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

    ###### CRYPTO KEYS RELATED FUNCTIONS

    def changeKeySettings(self, newKeySettings):
        """Changes key settings for the key that was used to authenticate with in the current session.
        Authentication is ALWAYS needed to call this function.
        Args:
            newKeySettings (list) : A list with DESFireKeySettings enum value

        Returns:
            None
        """
        # self.logger.debug('Changing key settings to %s' %('|'.join(a.name for a in newKeySettings),))
        params = [calc_key_settings(newKeySettings)]
        cmd = DESFireCommand.DF_INS_CHANGE_KEY_SETTINGS.value
        raw_data = self.communicate(
            self._command(cmd, params),
            encrypted=True,
            with_crc=True,
        )

    def changeKey(self, keyNo, newKey, curKey):
        """Changes current key (curKey) to a new one (newKey) in specified keyslot (keyno)
        Authentication is ALWAYS needed to call this function.
        Args:
            keyNo  (int) : Key number
            newKey (DESFireKey)    : The new key
            curKey (DESFireKey)    : The current key for that keyslot

        Returns:
            None
        """

        keyNo = get_int(keyNo, "big")
        self.logger.debug(" -- Changing key --")
        # self.logger.debug('Changing key No: %s from %s to %s' % (keyNo, newKey, curKey))
        if not self.is_authenticated:
            raise Exception("Not authenticated!")

        self.logger.debug("curKey : " + to_human_readable_hex(curKey.get_key()))
        self.logger.debug("newKey : " + to_human_readable_hex(newKey.get_key()))

        isSameKey = keyNo == self.lastAuthKeyNo
        # self.logger.debug('isSameKey : ' + str(isSameKey))

        # The type of key can only be changed for the PICC master key.
        # Applications must define their key type in CreateApplication().
        if self.last_selected_application == 0x00:
            keyNo = keyNo | newKey.keyType.value

        cryptogram = self._command(DESFireCommand.DF_INS_CHANGE_KEY.value, [keyNo])
        # The following if() applies only to application keys.
        # For the PICC master key b_SameKey is always true because there is only ONE key (#0) at the PICC level.
        if not isSameKey:
            keyData_xor = []
            if len(newKey.get_key()) > len(curKey.get_key()):
                keyData_xor = bytearray(strxor(bytes(newKey.get_key()), bytes(curKey.get_key() * 2)))
            else:
                keyData_xor = bytearray(strxor(bytes(newKey.get_key()), bytes(curKey.get_key())))
            cryptogram += keyData_xor
        else:
            cryptogram += newKey.get_key()

        if newKey.keyType == DESFireKeyType.DF_KEY_AES:
            cryptogram += [newKey.keyVersion]

        cryptogram += bytearray(CRC32(cryptogram).to_bytes(4, byteorder="little"))
        if not isSameKey:
            cryptogram += bytearray(CRC32(newKey.get_key()).to_bytes(4, byteorder="little"))

        # self.logger.debug( (int2hex(DESFireCommand.DF_INS_CHANGE_KEY.value) + int2hex(keyNo) + cryptogram).encode('hex'))
        raw_data = self.communicate(
            cryptogram,
            encrypted=True,
            with_rxc_mac=not isSameKey,
            with_tx_cmac=False,
            with_crc=False,
            encrypt_begin=2,
        )

        # If we changed the currently active key, then re-auth is needed!
        if isSameKey:
            self.is_authenticated = False
            self.session_key = None

        return

    #######################################################################################################################################
    ### Helper function
    #######################################################################################################################################

    def createKeySetting(self, key, keyNumbers, keyType, keySettings):
        ret = DESFireKey()
        ret.set_key_settings(get_int(keyNumbers, "big"), keyType, calc_key_settings(keySettings))
        ret.set_key(get_list(key))
        return ret
