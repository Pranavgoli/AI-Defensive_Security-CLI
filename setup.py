from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ds_cli",
    version="1.0.0",
    author="VSMK Defensive Security",
    description="AI Powered Defensive Security CLI for log ingestion and automated root cause analysis.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=[
        "click",
        "rich",
        "pydantic",
        "openai",
        "python-dateutil"
    ],
    entry_points={
        "console_scripts": [
            "ds_cli=ds_cli.main:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ],
    python_requires=">=3.8",
)
