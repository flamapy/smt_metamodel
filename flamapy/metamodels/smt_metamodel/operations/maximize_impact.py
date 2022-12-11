from z3 import Or, Optimize, sat, ModelRef

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models import PySMTModel
from flamapy.metamodels.smt_metamodel.utils import config_sanitizer


class MaximizeImpact(Operation):

    def __init__(
        self,
        file_name: str,
        limit: int
    ) -> None:
        self.file_name: str = file_name
        self.limit: int = limit
        self.result: list[ModelRef] = []

    def get_result(self) -> list[ModelRef]:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        solver = Optimize()
        if model.cvvs:
            cvss_f = model.cvvs[self.file_name]
            solver.maximize(cvss_f)

        formula = model.domains[self.file_name]
        solver.add(formula)
        while solver.check() == sat and len(self.result) < self.limit:
            config = solver.model()
            sanitized_config = config_sanitizer(config)
            self.result.append(sanitized_config)

            block = []
            for var in config:
                variable = var()
                block.append(variable != config[var])

            solver.add(Or(block))