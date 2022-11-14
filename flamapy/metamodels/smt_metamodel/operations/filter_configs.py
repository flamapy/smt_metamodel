from z3 import And, Or, Solver, sat, ModelRef

from sys import maxsize

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models import PySMTModel


class FilterConfigs(Operation):

    def __init__(
        self,
        max_threshold: float = 10.,
        min_threshold: float = 0.,
        limit: int = maxsize
        ) -> None:
        self.max_threshold: float = max_threshold
        self.min_threshold: float = min_threshold
        self.limit: int = limit
        self.result: list[ModelRef] = []

    def get_result(self) -> list[ModelRef]:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        _domains = []
        _domains.extend(model.domains)

        if model.vars:
            CVSSt = model.vars[0]
            max_ctc = CVSSt <= self.max_threshold
            min_ctc = CVSSt >= self.min_threshold
            _domains.extend([max_ctc, min_ctc])

        solver = Solver()
        formula = And(_domains)
        solver.add(formula)
        while solver.check() == sat and len(self.result) < self.limit:
            config = solver.model()
            if config:
                self.result.append(config)

            block = []
            for var in config:
                c = var()
                block.append(c != config[var])

            solver.add(Or(block))