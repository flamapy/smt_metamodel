from z3 import BoolRef, ArithRef

from flamapy.core.models import VariabilityModel


class PySMTModel(VariabilityModel):

    @staticmethod
    def get_extension() -> str:
        return 'pysmt'

    def __init__(self) -> None:
        self.domains: list[BoolRef] = []
        self.vars: list[ArithRef] = []
        self.versions: dict[str, ArithRef] = {}

    def get_var(self, name: str) -> ArithRef | None:
        for var in self.vars:
            if str(var) == name:
                return var
        return None