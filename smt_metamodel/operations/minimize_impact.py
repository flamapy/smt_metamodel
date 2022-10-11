from z3 import And, Or, Optimize, sat

from smt_metamodel.models.pysmt_model import PySMTModel
import sys

from famapy.core.operations import Operation


class MinimizeImpact(Operation):

    def __init__(
        self,
        limit: int = sys.maxsize
        ) -> None:
        self.__limit: int = limit
        self.__result: list = list()

    def get_result(self) -> list:
        return self.__result

    def execute(self, smt_model: PySMTModel) -> 'MinimizeImpact':
        _domains = list()
        _domains.extend(smt_model.get_domains())

        solver = Optimize()
        if smt_model.get_vars():
            CVSSt = smt_model.get_vars()[0]
            solver.minimize(CVSSt)

        formula = And(_domains)
        solver.add(formula)
        while solver.check() == sat and len(self.__result) < self.__limit:
            config = solver.model()
            self.__result.append(config)

            block = list()
            for var in config: # var is a declaration of a smt variable
                c = var() # create a constant from declaration
                block.append(c != config[var])

            solver.add(Or(block))