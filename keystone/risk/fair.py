"""FAIR (Factor Analysis of Information Risk) Monte Carlo engine.

Model, per simulated year:
  TEF  ~ PERT(min, ml, max)          threat events per year
  Vuln = P(TCap > CS)                 from PERT samples of threat capability and
                                      control strength (0..1), or a direct Vuln range
  LEF  = TEF x Vuln                   loss events per year
  N    ~ Poisson(LEF)                 loss events this year
  Loss = N x PLM + Binomial(N, SLEF) x SLM

PLM/SLM are sampled once per simulated year (a common simplification). Use a seed for
repeatable results. Outputs are estimates for decision support, not predictions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

import numpy as np


@dataclass(frozen=True)
class Range:
    min: float
    ml: float
    max: float

    def __post_init__(self):
        if not (self.min <= self.ml <= self.max):
            raise ValueError(f"range must satisfy min <= most likely <= max (got {self.min}, {self.ml}, {self.max})")
        if self.min < 0:
            raise ValueError("range values must not be negative")

    @classmethod
    def of(cls, value) -> Range | None:
        if value is None or isinstance(value, Range):
            return value
        if isinstance(value, dict):
            return cls(float(value["min"]), float(value["ml"]), float(value["max"]))
        a, b, c = value
        return cls(float(a), float(b), float(c))

    def check_probability(self, name: str) -> None:
        if self.max > 1:
            raise ValueError(f"{name} is a probability and must be between 0 and 1")


@dataclass(frozen=True)
class FairInputs:
    tef: Range
    plm: Range
    tcap: Range | None = None
    cs: Range | None = None
    vuln: Range | None = None
    slef: Range | None = None
    slm: Range | None = None

    def __post_init__(self):
        if self.vuln is None and (self.tcap is None or self.cs is None):
            raise ValueError("give either a vulnerability range, or both threat capability and control strength")
        for name in ("tcap", "cs", "vuln", "slef"):
            r = getattr(self, name)
            if r is not None:
                r.check_probability(name)
        if (self.slef is None) != (self.slm is None):
            raise ValueError("secondary loss needs both SLEF and SLM")

    @classmethod
    def from_dict(cls, d: dict) -> FairInputs:
        return cls(**{k: r for k in ("tef", "plm", "tcap", "cs", "vuln", "slef", "slm") if (r := Range.of(d.get(k))) is not None})

    def to_dict(self) -> dict:
        return {k: asdict(v) for k, v in self.__dict__.items() if v is not None}


@dataclass(frozen=True)
class FairResult:
    iterations: int
    seed: int | None
    vulnerability: float
    lef_mean: float
    ale_mean: float
    ale_p10: float
    ale_p50: float
    ale_p90: float
    ale_p95: float
    prob_any_loss: float
    exceedance: list[tuple[float, float]]  # (loss threshold, P(annual loss >= threshold))

    def to_dict(self) -> dict:
        return asdict(self)


def pert(rng: np.random.Generator, r: Range, n: int, lam: float = 4.0) -> np.ndarray:
    if r.max == r.min:
        return np.full(n, r.min)
    span = r.max - r.min
    alpha = 1 + lam * (r.ml - r.min) / span
    beta = 1 + lam * (r.max - r.ml) / span
    return r.min + rng.beta(alpha, beta, n) * span


def simulate(inputs: FairInputs, iterations: int = 10_000, seed: int | None = None) -> FairResult:
    if not 100 <= iterations <= 1_000_000:
        raise ValueError("iterations must be between 100 and 1,000,000")
    rng = np.random.default_rng(seed)
    tef = pert(rng, inputs.tef, iterations)
    if inputs.vuln is not None:
        vuln_samples = pert(rng, inputs.vuln, iterations)
        vuln = float(vuln_samples.mean())
        lef = tef * vuln_samples
    else:
        if inputs.tcap is None or inputs.cs is None:  # __post_init__ guarantees one or the other
            raise ValueError("give either a vulnerability range, or both threat capability and control strength")
        tcap = pert(rng, inputs.tcap, iterations)
        cs = pert(rng, inputs.cs, iterations)
        vuln = float((tcap > cs).mean())
        lef = tef * vuln
    events = rng.poisson(lef)
    loss = events * pert(rng, inputs.plm, iterations)
    if inputs.slef is not None and inputs.slm is not None:
        slef = pert(rng, inputs.slef, iterations)
        secondary_events = rng.binomial(events, np.clip(slef, 0, 1))
        loss = loss + secondary_events * pert(rng, inputs.slm, iterations)
    p10, p50, p90, p95 = (float(x) for x in np.percentile(loss, [10, 50, 90, 95]))
    top = float(np.percentile(loss, 99)) or 1.0
    thresholds = np.linspace(0, top, 21)[1:]
    exceed = [(float(t), float((loss >= t).mean())) for t in thresholds]
    return FairResult(
        iterations=iterations,
        seed=seed,
        vulnerability=round(vuln, 4),
        lef_mean=float(lef.mean()),
        ale_mean=float(loss.mean()),
        ale_p10=p10,
        ale_p50=p50,
        ale_p90=p90,
        ale_p95=p95,
        prob_any_loss=float((loss > 0).mean()),
        exceedance=exceed,
    )
