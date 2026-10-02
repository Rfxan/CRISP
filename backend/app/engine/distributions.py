import numpy as np
from scipy.stats import beta

def sample_pert(low: float, likely: float, high: float, size: int = 10000, gamma: float = 4.0, rng: np.random.Generator = None) -> np.ndarray:
    """
    Vectorized Modified PERT distribution sampler using SciPy Beta distribution.
    Parameters:
      low: minimum value
      likely: most likely mode
      high: maximum value
      size: number of samples (trials)
      gamma: shape parameter (default 4.0)
    """
    if low >= high:
        return np.full(size, low)
    if likely < low or likely > high:
        likely = np.clip(likely, low, high)

    # Calculate alpha and beta for standard PERT
    mu = (low + gamma * likely + high) / (gamma + 2.0)
    # Avoid zero variance
    if likely == mu:
        alpha_param = 1.0 + gamma / 2.0
        beta_param = 1.0 + gamma / 2.0
    else:
        alpha_param = ((mu - low) * (2.0 * likely - low - high)) / ((likely - mu) * (high - low))
        # Ensure positivity
        if alpha_param <= 0:
            alpha_param = 1.0 + gamma * (likely - low) / (high - low)
        beta_param = alpha_param * (high - mu) / (mu - low)

    alpha_param = max(0.1, float(alpha_param))
    beta_param = max(0.1, float(beta_param))

    if rng is not None:
        beta_samples = rng.beta(alpha_param, beta_param, size=size)
    else:
        beta_samples = np.random.beta(alpha_param, beta_param, size=size)

    return low + beta_samples * (high - low)

def sample_poisson(lam: float, size: int = 10000, rng: np.random.Generator = None) -> np.ndarray:
    """Vectorized Poisson count sampler."""
    from scipy.stats import poisson
    rates = np.maximum(np.asarray(lam, dtype=float), 0)
    uniform = (rng or np.random.default_rng()).random(size)
    return poisson.ppf(np.clip(uniform, 1e-12, 1-1e-12), rates).astype(int)

def sample_lognormal(mean_log: float = 0.0, sigma_log: float = 0.45, size: int = 10000, rng: np.random.Generator = None) -> np.ndarray:
    """Vectorized LogNormal sampler for systemic threat intensity factor G."""
    if rng is not None:
        return rng.lognormal(mean=mean_log, sigma=sigma_log, size=size)
    return np.random.lognormal(mean=mean_log, sigma=sigma_log, size=size)

def sample_beta(a: float, b: float, size: int = 10000, rng: np.random.Generator = None) -> np.ndarray:
    """Vectorized Beta distribution sampler for control effect size uncertainty."""
    if rng is not None:
        return rng.beta(a, b, size=size)
    return np.random.beta(a, b, size=size)
