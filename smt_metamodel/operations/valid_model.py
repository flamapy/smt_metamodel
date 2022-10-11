from z3 import And, Solver, sat

from smt_metamodel.models.pysmt_model import PySMTModel

from famapy.core.operations import Operation


class ValidModel(Operation):

    def __init__(self) -> None:
        self.__result: bool = True

    def get_result(self) -> bool:
        return self.__result

    def execute(self, smt_model: PySMTModel) -> None:
        formula = And(smt_model.domains)
        solver = Solver()
        solver.add(formula)
        self.__result == solver.check() == sat