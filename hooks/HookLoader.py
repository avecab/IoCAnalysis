from hooks.Hooks import *
__all__ = ["HookLoader"]


class HookLoader:

    def __init__(self, logger=None):
        logger.info('')

    @staticmethod
    def get_hook(f_hook, logger=None):
        match f_hook:
            case "inet_addr":
                return inetAdressHook()
            case "IsDebuggerPresent":
                return IsDebuggerPresentHook()
            case "__set_app_type":
                return SetAppTypeHook()
            case _:
                return SimpleHook()
