from z3 import And, Or, Int, Real, Implies

from flamapy.core.models import VariabilityModel


class PySMTModel(VariabilityModel):

    @staticmethod
    def get_extension() -> str:
        return 'pysmt'

    def __init__(self) -> None:
        self.domains: list = []
        self.vars: list = []
        self.versions: dict = {}

    def add_domain(self, domain: And | Or | Implies) -> None:
        self.domains.append(domain)

    def add_var(self, var: Real | Int) -> None:
        self.vars.append(var)

    def add_version(self, name: str, version: dict) -> None:
        if name not in self.versions:
            self.versions[name] = version
        else:
            self.versions[name].update(version)

    def get_domains(self) -> list[And | Or | Implies]:
        return self.domains

    def get_vars(self) -> list[Real | Int]:
        return self.vars

    def get_versions(self) -> dict[str, dict]:
        return self.versions

    def get_var(self, name: str) -> Real | Int | None:
        for var in self.vars:
            if str(var) == name:
                return var
        return None