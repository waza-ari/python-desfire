from ..enums.desfire_keysettings import DESFireKeySettings


class DESFireKeySet:
    master = DESFireKeySettings.KS_FACTORY_DEFAULT
    change = DESFireKeySettings.KS_FACTORY_DEFAULT

    def __repr__(self):
        return "master:" + self.master.name + "\nchange:" + self.change.name
