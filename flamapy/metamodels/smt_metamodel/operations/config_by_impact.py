from z3 import sat, Optimize, Abs

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models import PySMTModel
from flamapy.metamodels.smt_metamodel.utils import config_sanitizer


class ConfigByImpact(Operation):

    def __init__(
        self,
        impact: float
    ) -> None:
        self.impact: float = impact
        self.result: list[dict[str, float | int]] = []

    def get_result(self) -> list[dict[str, float | int]]:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        solver = Optimize()
        if model.func_obj_var is not None:
            cvss_f = model.func_obj_var
            obj = Abs(cvss_f - self.impact)
            solver.minimize(obj)

        formula = model.domain
        solver.add(formula)
        while solver.check() == sat:
            config = solver.model()
            sanitized_config = config_sanitizer(config)
            self.result.append(sanitized_config)
            break