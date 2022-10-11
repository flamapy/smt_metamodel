import setuptools


with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name = "smt_metamodel",
    version = "0.1.0",
    author = "Antonio Germán Márquez Trujillo",
    author_email = "amtrujillo@us.es",
    description = "Una herramienta para el análisis de vulnerabilidades en proyectos software open-source",
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = "https://github.com/GermanMT/smt_metamodel",
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
    ],
    python_requires = '>=3.10',
    install_requires = [
        'z3-solver>=4.11.2.0',
        'famapy>=1.0.0'
    ]
)