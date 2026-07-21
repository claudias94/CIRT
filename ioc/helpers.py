"""
============================================================
Claus Incident Response Toolkit (CIRT)

IOC Helper Functions

Common helper functions used by IOC detection engines.

Author : Claudias Musavini Misiko
============================================================
"""


def normalize_text(data):
    """
    Convert collector output into a text string.

    Supports:
        - str
        - list
        - tuple
        - None
        - any other object

    Returns
    -------
    str
    """

    if data is None:
        return ""

    if isinstance(data, str):
        return data

    if isinstance(data, (list, tuple)):
        return "\n".join(str(item) for item in data)

    return str(data)
