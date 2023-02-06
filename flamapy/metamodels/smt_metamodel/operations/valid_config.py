from z3 import Int, Solver, sat

from flamapy.core.operations import Operation
from flamapy.metamodels.smt_metamodel.models import PySMTModel


class ValidConfig(Operation):

    def __init__(
        self,
        file_name: str,
        config: dict[str, int]
    ) -> None:
        self.file_name: str = file_name
        self.config: dict[str, int] = config
        self.result: bool = True

    def get_result(self) -> bool:
        return self.result

    def execute(self, model: PySMTModel) -> None:
        formula = model.domains[self.file_name]
        solver = Solver()
        solver.add(formula)
        for package, count in self.config.items():
            solver.add(Int(package) == count)
        self.result = solver.check() == sat