from typing import Any

from z3 import And, ArithRef, BoolRef, Implies, Int, Or, Real, Not, If

from univers.versions import Version, PypiVersion, SemverVersion, MavenVersion, InvalidVersion
from univers.version_range import (
    VersionRange,
    PypiVersionRange,
    NpmVersionRange,
    MavenVersionRange,
    InvalidVersionRange
)

from flamapy.core.transformations import Transformation
from flamapy.metamodels.smt_metamodel.models.pysmt_model import PySMTModel


class GraphToSMT(Transformation):

    @staticmethod
    def get_source_extension() -> str:
        return 'neo4j'

    @staticmethod
    def get_destination_extension() -> str:
        return 'smt'

    def __init__(
        self,
        source_data: dict[str, Any],
        file_name: str,
        package_manager: str,
        agregator: str
    ) -> None:
        self.source_data: dict[str, list[dict[str, Any]]] = source_data
        self.file_name: str = file_name
        self.agregator: str = agregator
        self.destination_model: PySMTModel = PySMTModel()
        self.dependency_versions: dict[str, list[dict[str, Any]]] = (
            self.match_dependency_versions()
        )
        self.version_type, self.range_type = self.get_version_range_type(package_manager)
        self.vars: dict[str, ArithRef] = {}
        self.childs: dict[ArithRef, dict[ArithRef, list[int]]] = {}
        self.parents: dict[ArithRef, dict[ArithRef, list[int]]] = {}
        self.directs: list[str] = []
        self.domain: list[BoolRef] = []
        # self.distributions: list[str] = []
        self.ctcs: dict[ArithRef, dict[float, list[int]]] = {}

    def match_dependency_versions(self) -> dict[str, Any]:
        dependency_versions: dict[str, list[dict[str, Any]]] = {}
        for rel_have in self.source_data['have']:
            dependency = rel_have.pop('dependency')
            dependency_versions.setdefault(dependency, []).append(rel_have)
        return dependency_versions

    def transform(self) -> None:
        impacts: list[ArithRef] = []
        for rel_requires in self.source_data['requires']:
            if rel_requires['parent_type'] == 'RequirementFile':
                impacts.extend(self.transform_direct_package(rel_requires))
            else:
                impacts.extend(self.transform_indirect_package(rel_requires))
        self.build_indirect_constraints()
        self.build_impact_constraints()
        self.domain.append(Real('CVSS' + self.file_name) == self.agregate(impacts))
        func_obj_var = Real('func_obj_' + self.file_name)
        self.domain.append(func_obj_var == self.mean(impacts))
        self.destination_model.domain = And(self.domain)
        self.destination_model.func_obj_var = func_obj_var

    def transform_direct_package(self, rel_requires: dict[str, Any]) -> list[ArithRef]:
        impacts: list[ArithRef] = []
        self.directs.append(rel_requires['dependency'])
        if rel_requires['dependency'] not in self.vars:
            var = Int(rel_requires['dependency'])
            self.vars[rel_requires['dependency']] = var
            cvss_p_name = 'CVSS' + rel_requires['dependency']
            cvss_p_var = Real(cvss_p_name)
            self.vars[cvss_p_name] = cvss_p_var
            impacts.append(cvss_p_var)
        else:
            var = self.vars[rel_requires['dependency']]
            cvss_p_var = self.vars['CVSS' + rel_requires['dependency']]
        filtered_versions = self.filter_versions(
            rel_requires['dependency'],
            rel_requires['constraints']
        )
        self.build_direct_contraint(var, filtered_versions)
        self.transform_versions(filtered_versions, var, cvss_p_var)
        return impacts

    def transform_indirect_package(
        self,
        rel_requires: dict[str, Any]
    ) -> list[ArithRef]:
        impacts: list[ArithRef] = []
        if rel_requires['dependency'] not in self.vars:
            var = Int(rel_requires['dependency'])
            self.vars[rel_requires['dependency']] = var
            cvss_p_name = 'CVSS' + rel_requires['dependency']
            cvss_p_var = Real(cvss_p_name)
            self.vars[cvss_p_name] = cvss_p_var
            impacts.append(cvss_p_var)
            self.ctcs.setdefault((var, cvss_p_var), {}).setdefault(0., []).append(-1)
        else:
            var = self.vars[rel_requires['dependency']]
            cvss_p_var = self.vars['CVSS' + rel_requires['dependency']]
        filtered_versions = self.filter_versions(
            rel_requires['dependency'],
            rel_requires['constraints']
        )
        self.append_indirect_constraint(
            var,
            filtered_versions,
            self.vars[self.get_parent_name(rel_requires['parent_id'])],
            rel_requires['parent_count']
        )
        self.transform_versions(filtered_versions, var, cvss_p_var)
        return impacts

    def transform_versions(
        self,
        versions: list[dict[str, Any]],
        var: ArithRef,
        cvss_p_var: ArithRef
    ) -> None:
        for version in versions:
            # key = str(var) + '-' + str(version['count'])
            # if key not in self.distributions:
            self.ctcs.setdefault((var, cvss_p_var), {}).setdefault(
                version[self.agregator],
                []
            ).append(version['count'])
            # self.distributions.append(key)

    def get_parent_name(self, version_id: str) -> str:
        for dependency, versions in self.dependency_versions.items():
            for version in versions:
                if version['id'] == version_id:
                    return dependency
        return ''

    def filter_versions(self, dependency: str, constraints: str) -> list[dict[str, Any]]:
        filtered_versions = []
        if constraints != 'any':
            for version in self.dependency_versions[dependency]:
                try:
                    univers_version = self.version_type(version['release'])
                except InvalidVersion:
                    continue
                check = True
                try:
                    versions_range = self.range_type.from_native(constraints)
                    print(univers_version)
                    print(versions_range)
                    check = check and univers_version in versions_range
                except InvalidVersionRange:
                    continue
                if check:
                    filtered_versions.append(version)
            return filtered_versions
        return self.dependency_versions[dependency]

    def append_indirect_constraint(
        self,
        child: ArithRef,
        versions: list[dict[str, Any]],
        parent: ArithRef,
        version: int
    ) -> None:
        if versions:
            version_constraints = self.group_versions(
                child,
                [version['count'] for version in versions]
            )
            self.childs.setdefault(version_constraints, {}).setdefault(parent, []).append(version)
            if str(child) not in self.directs:
                self.parents.setdefault(child, {}).setdefault(parent, []).append(version)

    def build_direct_contraint(self, var: ArithRef, versions: list[dict[str, Any]]) -> None:
        if versions:
            version_constraints = self.group_versions(
                var,
                [version['count'] for version in versions]
            )
            self.domain.append(version_constraints)
        else:
            self.domain.append(False)

    def build_indirect_constraints(self) -> None:
        for versions, _ in self.childs.items():
            for parent, parent_versions in _.items():
                self.domain.append(Implies(self.group_versions(parent, parent_versions), versions))
        for child, _ in self.parents.items():
            for parent, parent_versions in _.items():
                self.domain.append(
                    Implies(Not(self.group_versions(parent, parent_versions)), child == -1)
                )

    def build_impact_constraints(self) -> None:
        for vars_, _ in self.ctcs.items():
            for impact, versions in _.items():
                self.domain.append(
                    Implies(self.group_versions(vars_[0], versions), vars_[1] == impact)
                )

    # TODO: Possibility to add new metrics
    def agregate(
        self,
        impacts: list[ArithRef],
    ) -> ArithRef:
        match self.agregator:
            case 'mean':
                return self.mean(impacts)
            case 'weighted_mean':
                return self.weighted_mean(impacts)

    @staticmethod
    def get_version_range_type(package_manager: str) -> tuple[Version, VersionRange]:
        match package_manager:
            case 'PIP':
                return PypiVersion, PypiVersionRange
            case 'NPM':
                return SemverVersion, NpmVersionRange
            case 'MVN':
                return MavenVersion, MavenVersionRange
        return PypiVersion, PypiVersionRange

    @staticmethod
    def group_versions(var: ArithRef, versions: list[int]) -> BoolRef:
        min_ = min(versions)
        max_ = max(versions)
        constraints: list[BoolRef] = []
        while min_ <= max_:
            temporal_list = []
            while min_ not in versions:
                min_ += 1
            while min_ in versions:
                temporal_list.append(min_)
                min_ += 1
            if temporal_list:
                if len(temporal_list) == 1:
                    constraints.append(var == temporal_list[0])
                else:
                    constraints.append(And(var >= temporal_list[0], var <= temporal_list[-1]))
        return Or(constraints)

    @staticmethod
    def mean(impacts: list[ArithRef]) -> ArithRef:
        if impacts:
            num_non_zero = sum([If(val == 0, 0, 1) for val in impacts])
            return If(num_non_zero == 0., 0., sum(impacts) / num_non_zero)
        return 0.

    @staticmethod
    def weighted_mean(impacts: list[ArithRef]) -> ArithRef:
        if impacts:
            divisors = sum([val * 0.1 for val in impacts])
            return If(divisors == 0., 0, sum([val**2 * 0.1 for val in impacts]) / divisors)
        return 0.