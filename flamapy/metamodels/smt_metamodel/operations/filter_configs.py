from z3 import And, Or, Solver, sat

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models import PySMTModel
from flamapy.metamodels.smt_metamodel.utils import config_sanitizer


class FilterConfigs(Operation):

    def __init__(
        self,
        max_threshold: float,
        min_threshold: float,
        limit: int
    ) -> None:
        self.max_threshold: float = max_threshold
        self.min_threshold: float = min_threshold
        self.limit: int = limit
        self.result: list[dict[str, float | int]] = []

    def get_result(self) -> list[dict[str, float | int]]:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        if model.func_obj_var is not None:
            cvss_f = model.func_obj_var
            max_ctc = cvss_f <= self.max_threshold
            min_ctc = cvss_f >= self.min_threshold

        solver = Solver()
        formula = And([model.domain, max_ctc, min_ctc])
        solver.add(formula)
        while len(self.result) < self.limit and solver.check() == sat:
            config = solver.model()
            sanitized_config = config_sanitizer(config)
            self.result.append(sanitized_config)

            block = []
            for var in config:
                if str(var) != '/0':
                    variable = var()
                    if 'CVSS' not in str(variable):
                        block.append(config[var] != variable)

            solver.add(Or(block))