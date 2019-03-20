name = "sonoff-python"

import sys

if sys.version_info.major >= 3:
    from sonoff.sonoff import Sonoff
else:
    from sonoff import Sonoff