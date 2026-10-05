class IPList:
    def __init__(self):
        self.blocked: set[str] = set()
        self.always_allowed: set[str] = set()

    def block(self, ip: str):
        self.blocked.add(ip)

    def unblock(self, ip: str):
        self.blocked.discard(ip)

    def allow_always(self, ip: str):
        self.always_allowed.add(ip)

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked

    def is_allowed_override(self, ip: str) -> bool:
        return ip in self.always_allowed
