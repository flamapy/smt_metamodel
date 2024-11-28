from z3 import Solver, sat, unknown

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models import PySMTModel


class ValidModel(Operation):
    def __init__(self) -> None:
        self.result: bool | str = True

    def get_result(self) -> bool | str:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        solver = Solver()
        solver.set("timeout", 3000)
        solver.add(model.domain)
        self.result = solver.check() == sat
        if solver.check() == unknown:
            self.result = (
                "Execution timed out after 3 seconds. "
                "The complexity of the model is too high, "
                "try lowering the maximum level of the graph."
            )
