# Third-party runtime

The offline wheelhouse contains official Python package artifacts downloaded
from PyPI for Linux x86_64:

- cryptography 49.0.0: Apache-2.0 OR BSD-3-Clause;
- cffi 2.0.0: MIT;
- pycparser 2.23: BSD-3-Clause.

Each wheel retains its upstream package metadata and license files. The package
builder validates every wheel against the pinned SHA-256 values in
`runtime/requirements-linux-x86_64.lock`.
