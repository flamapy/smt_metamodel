from z3 import And, Or, Solver, sat, ModelRef

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models import PySMTModel
from flamapy.metamodels.smt_metamodel.utils import config_sanitizer


class FilterConfigs(Operation):

    def __init__(
        self,
        file_name: str,
        max_threshold: float,
        min_threshold: float,
        limit: int
    ) -> None:
        self.file_name: str = file_name
        self.max_threshold: float = max_threshold
        self.min_threshold: float = min_threshold
        self.limit: int = limit
        self.result: list[ModelRef] = []

    def get_result(self) -> list[ModelRef]:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        if model.cvvs:
            cvss_f = model.cvvs[self.file_name]
            max_ctc = cvss_f <= self.max_threshold
            min_ctc = cvss_f >= self.min_threshold

        solver = Solver()
        formula = And([model.domains[self.file_name], max_ctc, min_ctc])
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