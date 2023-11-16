import os
from glob import glob
from os.path import basename, splitext

from setuptools import find_packages, setup

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name="ibl-lti-1p3-provider",
    version="2.0.2",
    packages=find_packages("src"),
    include_package_data=True,
    package_dir={"": "src"},
    py_modules=[splitext(basename(path))[0] for path in glob("src/*.py")],
    description="",
    author="IBL Studios",
    author_email="ibl@ibl.ibl",
    install_requires=[],
    entry_points={
        "lms.djangoapp": [
            "lti_1p3_provider = lti_1p3_provider.apps:Lti1p3ProviderConfig",
        ],
    },
    classifiers=[
        "Environment :: Web Environment",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    ],
)
