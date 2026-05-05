"""Post-quantum cryptography helpers (ML-DSA-65 / Dilithium).

Requires liboqs (compiled in the Dockerfile builder stage) and the
``liboqs-python`` Python wrapper. If neither is available, importing
:mod:`forensics.quantum.auth` will raise ``ImportError`` — call sites
must handle that gracefully.
"""
