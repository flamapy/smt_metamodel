from z3 import Int, sat, ModelRef, Optimize

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models import PySMTModel
from flamapy.metamodels.smt_metamodel.utils import config_sanitizer


class CompleteConfig(Operation):

    def __init__(
        self,
        file_name: str,
        config: dict[str, int]
    ) -> None:
        self.file_name: str = file_name
        self.config: dict[str, int] = config
        self.result: list[ModelRef] = []

    def get_result(self) -> list[ModelRef]:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        solver = Optimize()
        if model.cvvs:
            cvss_f = model.cvvs[self.file_name]
            solver.minimize(cvss_f)

        formula = model.domains[self.file_name]
        solver.add(formula)
        for package, count in self.config.items():
            solver.add(Int(package) == count)

        while solver.check() == sat:
            config = solver.model()
            sanitized_config = config_sanitizer(config)
            self.result.append(sanitized_config)
            break