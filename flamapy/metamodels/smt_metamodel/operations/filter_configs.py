from z3 import And, Or, Solver, sat

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
        self.result: list = []

    def get_result(self) -> list:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        _domains = []
        _domains.extend(model.get_domains())

        if model.get_vars():
            CVSSt = model.get_vars()[0]
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
            for var in config: # var is a declaration of a smt variable
                c = var() # create a constant from declaration
                block.append(c != config[var])

            solver.add(Or(block))
