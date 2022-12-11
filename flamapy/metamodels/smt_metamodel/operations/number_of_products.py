from z3 import Or, Solver, sat

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models import PySMTModel


class NumberOfProducts(Operation):

    def __init__(self, file_name: str) -> None:
        self.file_name: str = file_name
        self.result: int = 0

    def get_result(self) -> int:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        formula = model.domains[self.file_name]
        solver = Solver()
        solver.add(formula)
        while solver.check() == sat:
            config = solver.model()

            block = []
            for var in config:
                variable = var()
                block.append(variable != config[var])

            solver.add(Or(block))
            self.result += 1