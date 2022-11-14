from z3 import And, Or, Optimize, sat, ModelRef

from sys import maxsize

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models import PySMTModel


class MaximizeImpact(Operation):

    def __init__(
        self,
        limit: int = maxsize
        ) -> None:
        self.limit: int = limit
        self.result: list[ModelRef] = []

    def get_result(self) -> list[ModelRef]:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        _domains = []
        _domains.extend(model.domains)

        solver = Optimize()
        if model.vars:
            CVSSt = model.vars[0]
            solver.maximize(CVSSt)

        formula = And(_domains)
        solver.add(formula)
        while solver.check() == sat and len(self.result) < self.limit:
            config = solver.model()
            self.result.append(config)

            block = []
            for var in config:
                c = var()
                block.append(c != config[var])

            solver.add(Or(block))