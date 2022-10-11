from z3 import And, Or, Solver, sat

from smt_metamodel.models.pysmt_model import PySMTModel

from famapy.core.operations import Operation


class NumberOfProducts(Operation):

    def __init__(self) -> None:
        self.__result: int = 0

    def get_result(self) -> int:
        return self.__result

    def execute(self, smt_model: PySMTModel) -> None:
        formula = And(smt_model.domains)
        solver = Solver()
        solver.add(formula)
        while solver.check() == sat:
            config = solver.model()

            block = list()
            for var in config:
                c = var()
                block.append(c != config[var])

            solver.add(Or(block))
            self.__result += 1