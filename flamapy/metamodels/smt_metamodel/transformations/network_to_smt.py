from operator import eq

from typing import Callable

from flamapy.core.transformations import ModelToModel
from flamapy.metamodels.dn_metamodel.models import (DependencyNetwork, Package,
                                                    RequirementFile, Version)
from flamapy.metamodels.smt_metamodel.models import PySMTModel

from z3 import And, Implies, Int, Or, Real, ArithRef, BoolRef

class NetworkToSMT(ModelToModel):

    @staticmethod
    def get_source_extension() -> str:
        return 'dn'

    @staticmethod
    def get_destination_extension() -> str:
        return 'smt'

    def __init__(self, source_model: DependencyNetwork, agregation_type: str) -> None:
        self.source_model: DependencyNetwork = source_model
        self.agregation = self.get_agregation_op(agregation_type)
        self.destination_model: PySMTModel = PySMTModel()
        self.counter: int = 0
        self.CVSSp: dict[str, ArithRef] = {}
        self.CVSSf: dict[str, ArithRef] = {}
        self.CVSSt: ArithRef = Real('CVSSt')
        self.destination_model.vars.append(self.CVSSt)

    def transform(self) -> PySMTModel:
        if self.source_model.requirement_files:
            for requirement_file in self.source_model.requirement_files:
                self.transform_requirement_file(requirement_file)

            f_impacts = self.agregation(list(self.CVSSf.values()))
            self.destination_model.domains.append(eq(self.CVSSt, f_impacts))
            self.CVSSf.clear()

    def transform_requirement_file(self, requirement_file: RequirementFile) -> None:
        for package in requirement_file.packages:
            self.transform_package(package)

        CVSSf_name = 'CVSS' + requirement_file.name
        CVSSf_var = Real(CVSSf_name)
        self.CVSSf[CVSSf_name] = CVSSf_var
        self.destination_model.vars.append(CVSSf_var)
    
        p_impacts = self.agregation(list(self.CVSSp.values())) if self.CVSSp.values() else 0.
        self.destination_model.domains.append(eq(CVSSf_var, p_impacts))
        self.CVSSp.clear()

    def transform_package(self, package: Package) -> None:
        var = Int(package.name)
        self.destination_model.vars.append(var)

        CVSSp_name = 'CVSS' + package.name
        CVSSp_var = Real(CVSSp_name)
        self.CVSSp[CVSSp_name] = CVSSp_var
        self.destination_model.vars.append(CVSSp_var)

        all_p_cves, p_cvss = self.transform_version(package.versions, var, self.CVSSp[CVSSp_name])

        p_domain = self.add_constraint(var, package.versions[-1].count)

        sub_domain = [And(p_cvss)]
        sub_domain.extend(all_p_cves)
        sub_domain.extend(p_domain)

        self.destination_model.domains.append(And(sub_domain))
            
    def transform_version(self, versions: list[Version], var: ArithRef, CVSS_var: ArithRef) -> tuple[list[BoolRef], list[BoolRef]]:
        all_p_cves: list[BoolRef] = []
        p_cvss: list[BoolRef] = []

        for version in versions:
            p_cves = self.transform_cves(version)

            exprs = [p_cve == impact for p_cve, impact in p_cves.items()]

            for expr in exprs:
                if expr not in all_p_cves:
                    all_p_cves.append(expr)

            v_impact = self.agregation(list(p_cves.keys())) if p_cves.keys() else 0.
            ctc = Implies(var == version.count, CVSS_var == v_impact)
            p_cvss.append(Or(ctc))

        return (all_p_cves, p_cvss)

    def transform_cves(self, version: Version) -> dict[ArithRef, float]:
        p_cves: dict[ArithRef, float] = {}

        for cve in version.cves:
            old_p_cve = self.destination_model.get_var(cve['id'])

            if not old_p_cve:
                p_cve = Real(cve['id'])
            else:
                p_cve = old_p_cve

            for key in cve['metrics']:
                match key:
                    case 'cvssMetricV31':
                        p_cves[p_cve] = float(cve['metrics']['cvssMetricV31'][0]['impactScore'])
                    case 'cvssMetricV30':
                        p_cves[p_cve] = float(cve['metrics']['cvssMetricV30'][0]['impactScore'])
                    case 'cvssMetricV2':
                        p_cves[p_cve] = float(cve['metrics']['cvssMetricV2'][0]['impactScore'])

        return p_cves

    def add_constraint(self, var: ArithRef, count: int) -> list[bool]:
        problems_: list[bool] = [
            var >= 0,
            var <= count
        ]

        return problems_

    def get_agregation_op(self, agregation_type: str) -> Callable[[list[ArithRef]], float]:
        match agregation_type:
            case 'mean':
                return self.mean
            case 'median':
                pass
            case 'mode':
                pass
        return self.mean

    @staticmethod
    def mean(problem: list[ArithRef]) -> float:
        return sum(problem) / len(problem)