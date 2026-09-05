"""The specialised detection mesh.

One detector per threat class, all behind the contract in :mod:`.base`. There is
deliberately no single universal classifier: the threat classes have different
evidence, different natural techniques (rule vs statistical vs supervised) and
different false-positive profiles, and collapsing them into one model makes every
alert unexplainable.
"""

from .base import Detector, DetectorRegistry, build_default_registry, safe_evaluate

__all__ = ["Detector", "DetectorRegistry", "build_default_registry", "safe_evaluate"]
