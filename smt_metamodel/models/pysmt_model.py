from z3 import And, Or, Int, Real, Implies

from typing import Union

from famapy.core.models import VariabilityModel


class PySMTModel(VariabilityModel):

    @staticmethod
    def get_extension() -> str:
        return 'pysmt'

    def __init__(self) -> None:
        self.__domains = list()
        self.__vars = list()
        self.__versions = dict()

    def add_domain(self, domain: Union[And, Or, Implies]) -> None:
        self.__domains.append(domain)

    def add_var(self, var: Union[Real, Int]) -> None:
        self.__vars.append(var)

    def add_version(self, name: str, version: dict) -> None:
        if name not in self.__versions:
            self.__versions[name] = version
        else:
            self.__versions[name].update(version)

    def get_domains(self) -> list[Union[And, Or, Implies]]:
        return self.__domains

    def get_vars(self) -> list[Union[Real, Int]]:
        return self.__vars

    def get_versions(self) -> dict[str, dict]:
        return self.__versions

    def get_var(self, name: str) -> Union[Real, Int]:
        for var in self.__vars:
            if str(var) == name:
                return var