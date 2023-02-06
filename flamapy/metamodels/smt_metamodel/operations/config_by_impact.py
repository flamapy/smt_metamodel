from z3 import sat, ModelRef, Optimize, Abs

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models import PySMTModel
from flamapy.metamodels.smt_metamodel.utils import config_sanitizer


class ConfigByImpact(Operation):

    def __init__(
        self,
        file_name: str,
        impact: float
    ) -> None:
        self.file_name: str = file_name
        self.impact: float = impact
        self.result: list[ModelRef] = []

    def get_result(self) -> list[ModelRef]:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        solver = Optimize()
        if model.cvvs:
            cvss_f = model.cvvs[self.file_name]
            obj = Abs(cvss_f - self.impact)
            solver.minimize(obj)

        formula = model.domains[self.file_name]
        solver.add(formula)
        while solver.check() == sat:
            config = solver.model()
            sanitized_config = config_sanitizer(config)
            self.result.append(sanitized_config)
            break