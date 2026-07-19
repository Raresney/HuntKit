"""HuntKit core: configuration, logging, execution, cache, and state.

The core layer sits above `utils` and below the feature packages (recon,
scanners, intelligence, reporting, ai). Feature code depends on core; core
never depends on feature code.
"""
