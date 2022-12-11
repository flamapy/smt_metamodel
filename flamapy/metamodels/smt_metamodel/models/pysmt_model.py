from z3 import BoolRef, ArithRef

from flamapy.core.models import VariabilityModel


class PySMTModel(VariabilityModel):

    @staticmethod
    def get_extension() -> str:
        return 'pysmt'

    def __init__(self) -> None:
        self.domains: dict[str, BoolRef] = {}
        self.cvvs: dict[str, ArithRef] = {}