class SWJSQError(RuntimeError):
    pass


class APIError(SWJSQError):
    def __init__(self, command, errno, message):
        self.command = command
        self.errno = errno
        self.message = message


class LoginError(SWJSQError):
    def __init__(self, errno, message):
        self.errno = errno
        self.message = message


class UpgradeError(SWJSQError):
    def __init__(self, message):
        self.message = message
