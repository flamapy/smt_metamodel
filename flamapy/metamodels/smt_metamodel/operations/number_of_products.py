from z3 import Or, Solver, sat

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models import PySMTModel


class NumberOfProducts(Operation):

    def __init__(self) -> None:
        self.result: int = 0

    def get_result(self) -> int:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        formula = model.domain
        solver = Solver()
        solver.add(formula)
        while solver.check() == sat:
            config = solver.model()

            block = []
            for var in config:
                if str(var) != '/0':
                    variable = var()
                    if 'CVSS' not in str(variable):
                        block.append(config[var] != variable)

            solver.add(Or(block))
            self.result += 1