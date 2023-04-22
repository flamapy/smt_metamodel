from z3 import Int, sat, Optimize

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models import PySMTModel
from flamapy.metamodels.smt_metamodel.utils import config_sanitizer


class CompleteConfig(Operation):

    def __init__(
        self,
        config: dict[str, int]
    ) -> None:
        self.config: dict[str, int] = config
        self.result: list[dict[str, float | int]] = []

    def get_result(self) -> list[dict[str, float | int]]:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        solver = Optimize()
        if model.func_obj_var is not None:
            cvss_f = model.func_obj_var
            solver.minimize(cvss_f)

        formula = model.domain
        solver.add(formula)
        for package, count in self.config.items():
            solver.add(Int(package) == count)

        while solver.check() == sat:
            config = solver.model()
            sanitized_config = config_sanitizer(config)
            self.result.append(sanitized_config)
            break