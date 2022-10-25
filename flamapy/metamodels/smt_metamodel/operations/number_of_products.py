from z3 import And, Or, Solver, sat

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models.pysmt_model import PySMTModel


class NumberOfProducts(Operation):

    def __init__(self) -> None:
        self.result: int = 0

    def get_result(self) -> int:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        formula = And(model.domains)
        solver = Solver()
        solver.add(formula)
        while solver.check() == sat:
            config = solver.model()

            block = []
            for var in config:
                c = var()
                block.append(c != config[var])

            solver.add(Or(block))
            self.result += 1