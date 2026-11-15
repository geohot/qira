# Only the C++ extension lives here; all other metadata is in pyproject.toml.
from Cython.Build import cythonize
from setuptools import Extension, setup

qiradb = Extension(
    "qira.legacy.qiradb.qiradb",
    sources=["middleware/qiradb/qiradb.pyx"],
    include_dirs=["middleware/qiradb/Trace"],
    language="c++",
    extra_compile_args=["-std=c++17", "-O2"],
)

setup(
    ext_modules=cythonize(
        [qiradb],
        include_path=["middleware/qiradb"],
        build_dir="build/cython",
        compiler_directives={"language_level": 3},
    ),
)
