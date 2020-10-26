import setuptools
from distutils.core import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="unwelcome",
    version="0.0.1",
    author="Jim Lestter",
    author_email="jim@jimlester.net",
    description="A bad tool for managing SSH bruteforce attacks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    python_requires='>=3.6',
    install_requires=[],
    entry_points={
        'console_scripts': [
            'unwelcome = unwelcome.unwelcome:main',
            ],
    },
)
