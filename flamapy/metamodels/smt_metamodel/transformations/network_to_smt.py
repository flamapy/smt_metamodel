from z3 import And, ArithRef, BoolRef, Implies, Int, Or, Real, Not

from flamapy.core.transformations import ModelToModel
from flamapy.metamodels.dn_metamodel.models import (
    DependencyNetwork,
    Package,
    Version
)
from flamapy.metamodels.smt_metamodel.models import PySMTModel


class NetworkToSMT(ModelToModel):

    @staticmethod
    def get_source_extension() -> str:
        return 'dn'

    @staticmethod
    def get_destination_extension() -> str:
        return 'smt'

    def __init__(self, source_model: DependencyNetwork, agregator: str | None = None) -> None:
        self.source_model: DependencyNetwork = source_model
        self.agregator: str | None = agregator
        self.destination_model: PySMTModel = PySMTModel()
        self.vars: dict[str, ArithRef] = {}
        self.childs: dict[BoolRef, list[BoolRef]] = {}
        self.parents: dict[ArithRef, list[BoolRef]] = {}
        self.cvss_p: list[ArithRef] = []
        self.domain: list[BoolRef] = []
        self.distributions: list[str] = []
        self.ctcs: list[BoolRef] = []
        self.directs: list[str] = []

    def transform(self) -> None:
        if self.source_model.requirement_files:
            for requirement_file in self.source_model.requirement_files:
                self.transform_direct_packages(requirement_file.packages)
                self.build_indirect_constraints()
                self.domain.extend(self.ctcs)

                cvss_f_name = 'CVSS' + requirement_file.name
                cvss_f_var = Real(cvss_f_name)
                agregator_impact = self.agregate(self.cvss_p) if self.cvss_p else 0.
                self.domain.append(cvss_f_var == agregator_impact)

                func_obj_name = 'func_obj_' + requirement_file.name
                func_obj_var = Real(func_obj_name)
                func_obj_impact = self.obj_func(self.cvss_p) if self.cvss_p else 0.
                self.domain.append(func_obj_var == func_obj_impact)
                self.destination_model.cvvs[requirement_file.name] = func_obj_var

                self.destination_model.domains[requirement_file.name] = And(self.domain)
                self.domain.clear()
                self.cvss_p.clear()

    def transform_direct_packages(self, packages: list[Package]) -> None:
        for package in packages:
            self.directs.append(package.name)
        for package in packages:
            if package.name not in self.vars:
                var = Int(package.name)
                self.vars[package.name] = var

                cvss_p_name = 'CVSS' + package.name
                cvss_p_var = Real(cvss_p_name)
                self.vars[cvss_p_name] = cvss_p_var
                self.cvss_p.append(cvss_p_var)
            else:
                var = self.vars[package.name]
                cvss_p_var = self.vars['CVSS' + package.name]

            self.build_direct_contraint(var, package.versions)

            self.transform_versions(package.versions, var, cvss_p_var)

    def transform_versions(
        self,
        versions: list[Version],
        var: ArithRef,
        cvss_p_var: ArithRef
    ) -> None:
        for version in versions:
            key = str(var) + '-' + str(version.count)
            if key not in self.distributions:
                impacts = self.get_impacts(version)
                v_impact = self.agregate(impacts) if impacts else 0.
                ctc = Implies(var == version.count, cvss_p_var == v_impact)
                self.ctcs.append(ctc)
                self.distributions.append(key)
                self.transform_indirect_packages(version.packages, var, version.count)

    def transform_indirect_packages(
        self,
        packages: list[Package],
        parent: ArithRef,
        version: int
    ) -> None:
        for package in packages:
            if package.name not in self.vars:
                var = Int(package.name)
                self.vars[package.name] = var

                cvss_p_name = 'CVSS' + package.name
                cvss_p_var = Real(cvss_p_name)
                self.vars[cvss_p_name] = cvss_p_var
                self.cvss_p.append(cvss_p_var)

                ctc = Implies(var == -1, cvss_p_var == 0.)
                self.ctcs.append(ctc)
            else:
                var = self.vars[package.name]
                cvss_p_var = self.vars['CVSS' + package.name]

            self.append_indirect_constraint(var, package.versions, parent, version)

            self.transform_versions(package.versions, var, cvss_p_var)

    def get_impacts(self, version: Version) -> list[float]:
        impacts: list[float] = []

        for cve in version.cves:
            for key, value in cve['metrics'].items():
                match key:
                    case 'cvssMetricV31':
                        impacts.append(float(value[0]['impactScore']))
                    case 'cvssMetricV30':
                        impacts.append(float(value[0]['impactScore']))
                    case 'cvssMetricV2':
                        impacts.append(float(value[0]['impactScore']))

        return impacts

    def build_direct_contraint(self, var: ArithRef, versions: list[Version]) -> None:
        constraint = [var == version.count for version in versions]
        if constraint:
            self.domain.append(Or(constraint))

    def append_indirect_constraint(
        self,
        var: ArithRef,
        versions: list[Version],
        parent: ArithRef,
        version: int
    ) -> None:
        _ = versions[0]
        parts = [var == version.count for version in versions]
        if parts:
            versions = Or(parts)

            if versions in self.childs:
                self.childs[versions].append(parent == version)
            else:
                self.childs[versions] = [parent == version]

        if str(var) not in self.directs:
            if var in self.parents:
                self.parents[var].append(parent == version)
            else:
                self.parents[var] = [parent == version]

    def build_indirect_constraints(self) -> None:
        for versions, parents in self.childs.items():
            self.domain.append(Implies(Or(parents), versions))
        for var, parents in self.parents.items():
            self.domain.append(Implies(Not(Or(parents)), var == -1))

    # TODO: Posibilidad de añadir nuevas métricas
    def agregate(
        self,
        impacts: list[ArithRef | float],

    ) -> float:
        match self.agregator:
            case 'mean':
                return self.mean(impacts)
            case 'weighted_mean':
                return self.weighted_mean(impacts)
            case _:
                return self.mean(impacts)

    @staticmethod
    def obj_func(problems: list[ArithRef | float]) -> float:
        return sum(problems)

    @staticmethod
    def mean(problems: list[ArithRef | float]) -> float:
        return sum(problems) / len(problems)

    @staticmethod
    def weighted_mean(problems: list[ArithRef | float]) -> float:
        dividends = 0.
        divisors = 0.

        for var in problems:
            weight = var * 0.1
            dividends += var * weight
            divisors += weight

        return dividends / divisors