from z3 import Int, Solver, sat, unknown

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models import PySMTModel


class ValidConfig(Operation):
    def __init__(self, config: dict[str, int]) -> None:
        self.config: dict[str, int] = config
        self.result: bool | str = True

    def get_result(self) -> bool | str:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        solver = Solver()
        solver.set("timeout", 3000)
        solver.add(model.domain)
        for package, count in self.config.items():
            solver.add(Int(package) == count)
        self.result = solver.check() == sat
        if solver.check() == unknown:
            self.result = (
                "Execution timed out after 3 seconds. "
                "The complexity of the model is too high, "
                "try lowering the maximum level of the graph."
            )
