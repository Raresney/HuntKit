"""Low-level, dependency-light helpers shared across HuntKit.

Nothing in `utils` may import from `huntkit.core`, `huntkit.recon`, etc. —
it is the bottom of the dependency graph so it can be reused everywhere
without cycles.
"""
