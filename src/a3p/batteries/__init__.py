"""The four MVP batteries."""

from a3p.batteries.injection import injection_scenarios
from a3p.batteries.leakage import leakage_scenarios
from a3p.batteries.permission import permission_scenarios
from a3p.batteries.phantom import phantom_scenarios

BATTERIES = {
    "phantom": phantom_scenarios,
    "injection": injection_scenarios,
    "permission": permission_scenarios,
    "leakage": leakage_scenarios,
}

__all__ = ["BATTERIES", "phantom_scenarios", "injection_scenarios", "permission_scenarios", "leakage_scenarios"]
