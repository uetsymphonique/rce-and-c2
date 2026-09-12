from .base import XpMssqlBase
from .staging import StagingMixin
from .exfil import ExfilMixin
from .xpagent import XpAgentMixin


class XpMssql(XpMssqlBase, StagingMixin, ExfilMixin, XpAgentMixin):
    pass


__all__ = ["XpMssql"]
