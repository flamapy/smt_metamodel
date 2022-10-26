from z3 import And, Solver, sat

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models import PySMTModel


class ValidModel(Operation):

    def __init__(self) -> None:
        self.result: bool = True

    def get_result(self) -> bool:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        formula = And(model.domains)
        solver = Solver()
        solver.add(formula)
        self.result = solver.check() == sat