from z3 import And, Or, Solver, sat

from smt_metamodel.models.pysmt_model import PySMTModel

import sys

from famapy.core.operations import Operation


class FilterConfigs(Operation):

    def __init__(
        self,
        max_threshold: float = 10.,
        min_threshold: float = 0.,
        limit: int = sys.maxsize
        ) -> None:
        self.__max_threshold: float = max_threshold
        self.__min_threshold: float = min_threshold
        self.__limit: int = limit
        self.__result: list = list()

    def get_result(self) -> list:
        return self.__result

    def execute(self, smt_model: PySMTModel) -> 'FilterConfigs':
        _domains = list()
        _domains.extend(smt_model.get_domains())

        if smt_model.get_vars():
            CVSSt = smt_model.get_vars()[0]
            max_ctc = CVSSt <= self.__max_threshold
            min_ctc = CVSSt >= self.__min_threshold
            _domains.extend([max_ctc, min_ctc])

        solver = Solver()
        formula = And(_domains)
        solver.add(formula)
        while solver.check() == sat and len(self.__result) < self.__limit:
            config = solver.model()
            if config:
                self.__result.append(config)

            block = list()
            for var in config: # var is a declaration of a smt variable
                c = var() # create a constant from declaration
                block.append(c != config[var])

            solver.add(Or(block))
