from z3 import And, Or, Optimize, sat

from sys import maxsize

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models.pysmt_model import PySMTModel


class MaximizeImpact(Operation):

    def __init__(
        self,
        limit: int = maxsize
        ) -> None:
        self.limit: int = limit
        self.result: list = []

    def get_result(self) -> list:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        _domains = []
        _domains.extend(model.get_domains())

        solver = Optimize()
        if model.get_vars():
            CVSSt = model.get_vars()[0]
            solver.maximize(CVSSt)

        formula = And(_domains)
        solver.add(formula)
        while solver.check() == sat and len(self.result) < self.limit:
            config = solver.model()
            self.result.append(config)

            block = []
            for var in config: # var is a declaration of a smt variable
                c = var() # create a constant from declaration
                block.append(c != config[var])

            solver.add(Or(block))