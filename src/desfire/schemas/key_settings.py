from desfire.enums import DESFireKeySettings, DESFireKeyType


class KeySettings:
    """
    Key settings for a master key on a DESFire application.
    """

    def __init__(
        self,
        application_id: list[int] | None = None,
        key_type: DESFireKeyType | None = None,
        settings: list[DESFireKeySettings] | None = None,
        max_keys: int | None = None,
    ):
        self.application_id = application_id
        self.key_type = key_type
        self.settings = settings
        self.max_keys = max_keys

    """
    The application ID these settings have been retrieved for
    """
    application_id: list[int] | None = None

    """
    Key type (DES, 2K3DES, 3K3DES, AES)
    """
    key_type: DESFireKeyType | None = None

    """
    Array of key settings that are set for this master key
    """
    settings: list[DESFireKeySettings] | None = None

    """
    Maximum number of keys that has been configured for this application
    """
    max_keys: int | None = None

    def parse_settings(self, settings: int):
        """
        Takes the raw settings byte and parses it into a list of key settings.
        """
        self.settings = []
        for keysetting in DESFireKeySettings:
            if settings & keysetting.value:
                self.settings.append(keysetting)

    def get_settings(self) -> int:
        """
        Returns the settings as a single byte.
        """
        res = 0

        if not self.settings:
            return res

        for keysetting in self.settings:
            res += keysetting.value
        return res & 0xFF

    def human_key_settings(self) -> list[str]:
        """
        Returns a human readable string of the key settings.
        """
        if not self.settings:
            return []

        return [keysetting.name for keysetting in self.settings]
