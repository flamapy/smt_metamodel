from advisory.models import Graph, PySMTModel
from advisory.objects import Version, Package

from z3 import And, Or, Int, Real, Implies

from operator import eq

from famapy.core.transformations import ModelToModel

class GraphToSMT(ModelToModel):

    @staticmethod
    def get_source_extension() -> str:
        return 'graph'

    @staticmethod
    def get_destination_extension() -> str:
        return 'smt'

    def __init__(self, source_model: Graph) -> None:
        self.__source_model: Graph = source_model
        self.__destination_model: PySMTModel = PySMTModel()
        self.__counter: int = 0
        self.__CVSSs: dict = dict()

    def transform(self) -> PySMTModel:
        if self.__source_model.get_packages():
            CVSSt = Real('CVSSt')
            self.__destination_model.add_var(CVSSt)

            for package in self.__source_model.get_packages():
                self.add_package(package)

            p_impact = self.division(self.__CVSSs.values())
            self.__destination_model.add_domain(eq(CVSSt, p_impact))

        return self.__destination_model

    def add_package(self, package: Package):
        pkg_name = package.get_pkg_name()
        var = Int(pkg_name)
        self.__destination_model.add_var(var)

        cvss_name = 'CVSS' + pkg_name
        cvss_var = Real(cvss_name)
        self.__CVSSs[cvss_name] = cvss_var
        self.__destination_model.add_var(cvss_var)

        versions = list()
        [versions.extend(package.get_versions()[parent_name]) for parent_name in package.get_versions()]

        self.__counter = 0
        all_p_cves, p_cvss = self.add_versions(versions, var, self.__CVSSs[cvss_name])

        p_domain = self.add_problems(var)

        sub_domain = [And(p_cvss)]
        sub_domain.extend(all_p_cves)
        sub_domain.extend(p_domain)

        self.__destination_model.add_domain(And(sub_domain))

    def add_versions(self, versions: list[Version], var: Int, part_cvss: Real) -> tuple[list, list, list]:
        all_p_cves = list()
        p_cvss = list()

        for version in versions:
            self.__destination_model.add_version(str(var), {self.__counter: version})

            p_cves = self.add_cves(version)
            
            exprs = [p_cve == p_cves[p_cve] for p_cve in p_cves]

            for expr in exprs:
                if expr not in all_p_cves:
                    all_p_cves.append(expr)

            v_impact = self.division(p_cves.keys()) if version.get_cves() else 0.
            ctc = Implies(var == self.__counter, part_cvss == v_impact)
            p_cvss.append(Or(ctc))
            self.__counter += 1

        return (all_p_cves, p_cvss)

    def add_cves(self, version: Version) -> dict[Real, float]:
        p_cves = dict()

        for cve in version.get_cves():

            old_p_cve = self.__destination_model.get_var(cve.id)

            if not old_p_cve:
                p_cve = Real(cve.id)
            else:
                p_cve = old_p_cve

            if cve.cvss.impact_score:
                p_cves[p_cve] = float(cve.cvss.impact_score)

        return p_cves

    @staticmethod
    def division(problem) -> float:
        return sum(problem) / len(problem) if problem else 0.

    ''' Crea las restricciones para el modelo smt '''
    def add_problems(self, var: Int) -> list:
        problems_ = [
            var >= 0,
            var <= self.__counter - 1
        ]

        return problems_