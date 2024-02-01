import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="flamapy-smt",
    version="1.3.3",
    author="Antonio Germán Márquez Trujillo",
    author_email="amtrujillo@us.es",
    description="This repo host the SMT model concrete classes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/flamapy/smt_metamodel",
    packages=setuptools.find_namespace_packages(include=["flamapy.*"]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    install_requires=["z3-solver==4.12.5.0", "flamapy==1.1.3", "univers==30.11.0"],
    tests_requires=[
        "prospector[with_everything]==1.10.2",
        "mypy==0.982",
        "types-setuptools==69.0.0.0",
    ],
)
