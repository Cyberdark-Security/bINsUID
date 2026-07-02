"""ASCII banner (figlet slant style)."""

from __future__ import annotations

# figlet slant font — BINSUID
BANNER_ART = r"""    ____  _____   _______ __  __________ 
   / __ )/  _/ | / / ___// / / /  _/ __ \
  / __  |/ //  |/ /\__ \/ / / // // / / /
 / /_/ // // /|  /___/ / /_/ // // /_/ / 
/_____/___/_/ |_//____/\____/___/_____/  
"""


def banner_footer(version: str, width: int = 55) -> str:
    left = f"v{version}"
    right = "- by cyberdark"
    pad = max(1, width - len(left) - len(right))
    return f"{left}{' ' * pad}{right}"
