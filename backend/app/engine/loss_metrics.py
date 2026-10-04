"""Empirical annual-loss metrics, including discrete and zero-inflated samples."""
import numpy as np


def expected_shortfall(losses, confidence=.95):
    values = np.sort(np.asarray(losses, dtype=float))
    if not len(values):
        return None
    tail_mass = len(values) * (1 - confidence)
    if tail_mass <= 0:
        return float(values[-1])
    whole = int(np.floor(tail_mass + 1e-10))
    fraction = max(0., tail_mass - whole)
    total = float(values[-whole:].sum()) if whole else 0.
    if fraction > 1e-10:
        total += fraction * float(values[-whole - 1])
    return total / tail_mass


def exceedance_curve(losses, max_points=100):
    values = np.sort(np.asarray(losses, dtype=float))
    if not len(values):
        return []
    # Round before deduplicating so display thresholds cannot disagree.
    thresholds = np.unique(np.concatenate(([0.], np.ceil(values*100)/100)))
    if len(thresholds) > max_points:
        thresholds = thresholds[np.unique(np.linspace(0, len(thresholds)-1, max_points).astype(int))]
    return [[float(x), float((len(values)-np.searchsorted(values, x, side="right"))/len(values))]
            for x in thresholds]
