import sys
import numpy as np
import math
from tqdm import tqdm
import logging

import math
from math import fsum

log = logging.getLogger(__name__)
DEFAULT_STEP_SIZE_10_MB = 1 * 1024**2


class QuotaConfigError(ValueError):
    pass


class InsufficientBytesError(ValueError):
    pass


def floor_to_step(x: int, step: int) -> int:
    if step <= 0:
        raise ValueError("step must be > 0")
    return (x // step) * step


def ceil_to_step(x: int, step: int) -> int:
    if step <= 0:
        raise ValueError("step must be > 0")
    return ((x + step - 1) // step) * step


def quantize_bounds_to_step(
    v_min: np.ndarray, v_max: np.ndarray, step: int
) -> tuple[np.ndarray, np.ndarray]:
    # v_min snapped UP, v_max snapped DOWN (keeps feasibility honest)
    v_min_q = np.array([ceil_to_step(int(x), step) for x in v_min], dtype=int)
    v_max_q = np.array([floor_to_step(int(x), step) for x in v_max], dtype=int)
    return v_min_q, v_max_q


def clamp_small(x: float, tol: float) -> float:
    return 0.0 if abs(x) <= tol else x


def validate_quota_config(cfg: dict) -> None:
    tol = float(cfg["error_tol"])
    step = float(cfg["step_size_in_bytes"])
    daily = float(cfg["daily_bytes"])
    groups = cfg.get("groups", {})

    if not groups:
        raise QuotaConfigError("No groups configured.")

    if step <= 0:
        raise QuotaConfigError("step_size_in_bytes must be > 0.")
    if tol <= 0:
        raise QuotaConfigError("error_tol must be > 0.")
    if daily < 0:
        raise QuotaConfigError("daily_bytes must be >= 0.")

    # tol too much smaller than step
    if step / tol > 10:
        raise QuotaConfigError(
            f"error_tol ({tol}) is >10 times smaller than step ({step})."
        )

    active = [(name, g) for name, g in groups.items() if g.get("n", 0) > 0]
    if not active:
        raise QuotaConfigError("All groups have n=0; nothing to allocate.")

    # bounds + feasibility
    min_cost = 0.0
    max_cost = 0.0
    min_r_sum = 0.0
    desired_sum = 0.0

    for name, g in active:
        n = float(g["n"])
        vmin = float(g["min_num_bytes"])
        vmax = float(g["max_num_bytes"]) if g["max_num_bytes"] else None
        if n < 0:
            raise QuotaConfigError(f"{name}: n must be >= 0")
        if vmin < 0 or (vmax and vmax < 0):
            raise QuotaConfigError(f"{name}: min/max bytes must be >= 0")
        if vmax and (vmin > vmax):
            raise QuotaConfigError(f"{name}: min_num_bytes > max_num_bytes")

        mr = float(g["min_quota_ratio"])
        dr = float(g["desired_quota_ratio"])
        if not math.isfinite(mr) or not (0.0 <= mr <= 1.0):
            raise QuotaConfigError(f"{name}: min_quota_ratio must be in [0,1]")
        if not math.isfinite(dr) or dr < 0.0:
            raise QuotaConfigError(
                f"{name}: desired_quota_ratio must be >= 0 and finite"
            )

        min_cost += vmin * n
        max_cost += vmax * n if vmax else 0
        min_r_sum += mr
        desired_sum += dr

    if min_r_sum > 1.0 + tol:
        raise QuotaConfigError(
            f"Sum(min_quota_ratio)={min_r_sum} exceeds 1; impossible."
        )

    if daily < min_cost - tol or daily == 0:
        raise InsufficientBytesError(
            f"daily_bytes ({daily}) below min feasible total ({min_cost})."
        )

    # grid representability (practical check, not perfect for multi-group)
    snapped = round(daily / step) * step
    if abs(daily - snapped) > max(tol, step * 1e-6):
        raise QuotaConfigError(
            f"daily_bytes ({daily}) not close to a step-multiple ({snapped}); "
            f"no exact grid solution likely unless tol is large."
        )


def weighted_mse(r, desired_r, weights=None):
    if weights is None:
        w = np.ones_like(r, dtype=float)
    else:
        w = np.asarray([1.0 if x is None else float(x) for x in weights], dtype=float)
        if w.shape != r.shape:
            raise ValueError(f"weights shape {w.shape} must match r shape {r.shape}")
    diff = r - desired_r
    return np.sum(w * diff * diff)


def quota_vector_generator(
    quota_config_dict, leftover_penalty=1e-3, quantize=True, show_progress=None
):
    """
    Search for quota vectors v such that:
      - sum(v[i] * weights[i]) == total
      - r_i = v_i / sum(v) satisfies r_i >= min_r[i]
      - minimizes weighted MSE against desired_r
    """

    # Validate config first.
    try:
        validate_quota_config(quota_config_dict)
    except QuotaConfigError as e:
        log.error(f"quota_vector_generator: Unable to allocate quotas, error: {e}")
    except InsufficientBytesError:
        log.info(
            f"quota_vector_generator: Insufficient bytes to allocate quotas. Setting all user quotas to 0."
        )
        return {"v_dict": {name: 0 for name in quota_config_dict["groups"]}}

    groups = [group for group in quota_config_dict["groups"]]
    weights = [group["n"] for group in quota_config_dict["groups"].values()]
    v_min = [group["min_num_bytes"] for group in quota_config_dict["groups"].values()]
    v_max = [group["max_num_bytes"] for group in quota_config_dict["groups"].values()]
    desired_r = [
        group["desired_quota_ratio"] for group in quota_config_dict["groups"].values()
    ]
    min_r = [group["min_quota_ratio"] for group in quota_config_dict["groups"].values()]
    mse_weights = [
        group["mse_weights"] for group in quota_config_dict["groups"].values()
    ]

    step = int(quota_config_dict["step_size_in_bytes"])
    tol = quota_config_dict["error_tol"]

    if quantize:
        total_daily_bytes = float(quota_config_dict["daily_bytes"])

        total_daily_bytes = round(total_daily_bytes / step) * step
        total_daily_bytes = float(total_daily_bytes)
    else:
        total_daily_bytes = int(
            round(quota_config_dict["daily_bytes"])
        )  # or already int

    # Generate arrays of integers
    weights = np.asarray(weights, dtype=int)
    v_min = np.asarray([int(round(x)) for x in v_min], dtype=int)
    v_max = np.asarray([int(round(x)) for x in v_max], dtype=int)

    desired_r = np.asarray([round(r, 2) for r in desired_r], dtype=float)
    min_r = np.asarray(min_r, dtype=float)

    # Filter for active groups only
    active_idx = [k for k, w in enumerate(weights) if w > 0]

    groups = [groups[k] for k in active_idx]
    weights = weights[active_idx]
    v_min = v_min[active_idx]
    v_max = v_max[active_idx]
    desired_r = desired_r[active_idx]
    min_r = min_r[active_idx]
    mse_weights = [mse_weights[k] for k in active_idx]  # keep as list if it has None
    n = len(weights)

    best = {
        "mse": float("inf"),
        "v_dict": None,
        "r_dict": None,
        "failure": None,  # filled if no solutions
    }

    # ------ Add some diagnostics for failure ------

    diag = {
        "nodes_visited": 0,
        "pruned_budget_bounds": 0,
        "leaf_reject_budget_not_met": 0,
        "leaf_reject_v_sum_nonpositive": 0,
        "leaf_reject_min_ratio": 0,
        "leaf_accept": 0,
        "last_dim_no_grid_hit": 0,
        "precheck": {},
    }

    # --- Preflight feasibility checks (fast, very informative) ---
    min_total_possible = float(np.sum(v_min * weights))
    max_total_possible = float(np.sum(v_max * weights))
    diag["precheck"]["total_daily_mbytes"] = float(total_daily_bytes) / 1024**2
    diag["precheck"]["min_total_mbyte_possible"] = min_total_possible / 1024**2
    diag["precheck"]["max_total_mbyte_possible"] = max_total_possible / 1024**2

    if total_daily_bytes < min_total_possible - tol:
        best["failure"] = {
            "reason": "daily_bytes_too_small",
            "detail": "Even at all minimum quotas, weighted sum exceeds budget.",
            "total_daily_bytes": float(total_daily_bytes),
            "min_total_possible": min_total_possible,
            "max_total_possible": max_total_possible,
        }
        return best

    if total_daily_bytes > max_total_possible + tol:
        best["failure"] = {
            "reason": "daily_bytes_too_large",
            "detail": "Even at all maximum quotas, weighted sum cannot reach budget.",
            "total_daily_bytes": float(total_daily_bytes),
            "min_total_possible": min_total_possible,
            "max_total_possible": max_total_possible,
        }
        return best

    # Grid congruence check: if quantized, remaining_budget must be representable by step*weights combos.
    # Necessary (not sufficient) condition: remaining_budget must be divisible by gcd(step*weights).
    g = int(step)
    for w in weights:
        g = math.gcd(g, int(step) * int(w))
    diag["precheck"]["gcd_step_weight"] = g

    if quantize and (int(round(total_daily_bytes)) % g) != 0:
        best["failure"] = {
            "reason": "grid_infeasible_gcd",
            "detail": "Given step and weights, no combination can exactly match daily_bytes.",
            "total_daily_bytes": int(round(total_daily_bytes)),
            "gcd_step_weight": g,
            "hint": "Try a smaller step size or adjust daily_bytes quantization.",
        }
        return best

    # --- DROP-IN PATCH inside quota_vector_generator(), after you compute/quantize total_daily_bytes and after active filtering ---

    # Ensure step is an int (you use it as a grid size)
    step = int(quota_config_dict["step_size_in_bytes"])
    tol = float(tol)

    # Force bytes-like quantities to ints EARLY (avoid fractional max_num_bytes like ...644.800001)
    total_daily_bytes = int(round(total_daily_bytes))
    weights = np.asarray(weights, dtype=int)

    v_min = np.asarray([int(round(x)) for x in v_min], dtype=int)
    v_max = np.asarray([int(round(x)) for x in v_max], dtype=int)

    # Snap bounds to the grid so your search space is internally consistent
    v_min, v_max = quantize_bounds_to_step(v_min, v_max, step)

    # If quantization made any group impossible, fail immediately
    bad_bounds = [groups[i] for i in range(len(weights)) if v_min[i] > v_max[i]]
    if bad_bounds:
        best["failure"] = {
            "reason": "bounds_infeasible_after_quantization",
            "detail": "After snapping to step grid, at least one group has min_num_bytes > max_num_bytes.",
            "bad_groups": bad_bounds,
            "step": step,
        }
        return best

    # Re-check total feasibility after quantization
    min_cost = int(np.sum(v_min * weights))
    max_cost = int(np.sum(v_max * weights))

    # If budget is slightly above max feasible due to grid snapping, clamp it.
    # Keep track of what we couldn't allocate.
    unallocatable_bytes = 0

    if total_daily_bytes > max_cost:
        unallocatable_bytes = total_daily_bytes - max_cost
        total_daily_bytes = max_cost

    if total_daily_bytes < min_cost - tol:
        best["failure"] = {
            "reason": "daily_bytes_below_min_cost_after_quantization",
            "total_daily_bytes": total_daily_bytes,
            "min_cost": min_cost,
            "max_cost": max_cost,
            "step": step,
        }
        return best

    if total_daily_bytes > max_cost + tol:
        best["failure"] = {
            "reason": "daily_bytes_above_max_cost_after_quantization",
            "total_daily_bytes": total_daily_bytes,
            "min_cost": min_cost,
            "max_cost": max_cost,
            "step": step,
        }
        return best

    # --- OPTIONAL: DROP-IN "single active group" fast path (place after active filtering, before building grids) ---

    if n == 1:
        w = int(weights[0])
        v = total_daily_bytes / w

        # Snap to grid
        v = floor_to_step(int(round(v)), step)

        # Clamp to bounds
        v = max(int(v_min[0]), min(int(v), int(v_max[0])))

        used = v * w
        remaining = clamp_small(float(total_daily_bytes - used), float(tol))

        if remaining != 0.0:
            best["failure"] = {
                "reason": "single_group_cannot_hit_budget_on_grid",
                "total_daily_bytes": total_daily_bytes,
                "weight": w,
                "v": v,
                "remaining_budget": remaining,
                "step": step,
                "tol": tol,
            }
            return best

        best.update(
            {
                "mse": 0.0,
                "leftover_mb": 0.0,
                "sum_of_ratios": 1.0,
                "v_dict": {groups[0]: float(v)},
                "r_dict": {groups[0]: 1.0},
                "failure": None,
            }
        )
        return best

    # build integer grids
    grids = [range(int(v_min[i]), int(v_max[i]) + step, step) for i in range(n)]

    UPDATE_EVERY = 10_000

    def recurse(i, current_v, remaining_budget, avg_bar, max_bar):
        diag["nodes_visited"] += 1

        if show_progress and diag["nodes_visited"] % UPDATE_EVERY == 0:
            avg_bar.update(UPDATE_EVERY)
            max_bar.update(UPDATE_EVERY)

        nonlocal best

        if i == n:
            if abs(remaining_budget) > tol:
                diag["leaf_reject_budget_not_met"] += 1
                return

            v = np.array(current_v)
            v_sum = np.sum(v)

            if v_sum <= 0:
                diag["leaf_reject_v_sum_nonpositive"] += 1
                return

            r = v / v_sum

            if np.any(r < min_r - tol):
                diag["leaf_reject_min_ratio"] += 1
                return

            diag["leaf_accept"] += 1

            mse = weighted_mse(r, desired_r, mse_weights)
            mse += (abs(remaining_budget) / total_daily_bytes) * leftover_penalty

            if mse < best["mse"]:

                v_dict = {name: v for name, v in zip(groups, v.copy())}
                r_dict = {name: r for name, r in zip(groups, r.copy())}

                best = {
                    "mse": mse,
                    "leftover_mb": float(remaining_budget) / 1024**2,
                    "sum_of_ratios": sum([r for r in r_dict.values()]),
                    "unallocatable_mbytes": unallocatable_bytes / (1024**2),
                    "v_dict": v_dict,
                    "r_dict": r_dict,
                }
            return

        # Prune impossible branches
        min_possible = np.sum(v_min[i:] * weights[i:])
        max_possible = np.sum(v_max[i:] * weights[i:])

        if not (min_possible - tol <= remaining_budget <= max_possible + tol):
            diag["pruned_budget_bounds"] += 1
            return

        # --- DROP-IN PATCH for your "last dimension" block inside recurse() ---
        # Replace your current "if i == n - 1:" block with this version.

        if i == n - 1:
            # Ideal per-user quota for last group
            v_last_raw = remaining_budget / weights[i]

            # Snap DOWN to grid to avoid overshooting budget
            v_last = floor_to_step(int(round(v_last_raw)), step)

            # Clamp to [v_min, v_max] after snapping
            v_last = max(int(v_min[i]), min(int(v_last), int(v_max[i])))

            cost = v_last * weights[i]
            new_remaining = remaining_budget - cost
            new_remaining = clamp_small(float(new_remaining), float(tol))

            # Only accept if we hit budget within tolerance
            if abs(new_remaining) <= tol:
                recurse(
                    i + 1,
                    current_v + [v_last],
                    0.0,
                    avg_bar,
                    max_bar,
                )
            else:
                diag["last_dim_no_grid_hit"] += 1
                pass
            return

        for v_i in grids[i]:
            cost = v_i * weights[i]
            if cost > remaining_budget + tol:
                continue

            recurse(
                i + 1,
                current_v + [v_i],
                remaining_budget - cost,
                avg_bar,
                max_bar,
            )

    k_avg = ((np.average(v_max) - np.average(v_min)) / step) + 1
    n_recursions_avg = k_avg ** (n - 1) / (math.factorial(n - 1))

    k_max = ((np.max(v_max) - np.max(v_min)) / step) + 1
    n_recursions_max = k_max**n

    if show_progress is None:
        show_progress = sys.stderr.isatty()

    with tqdm(
        total=n_recursions_avg,
        desc="Finding best solution, average time bound...",
        disable=not show_progress,
    ) as avg_bar, tqdm(
        total=n_recursions_max,
        desc="Finding best solution, max time bound...",
        disable=not show_progress,
    ) as max_bar:
        recurse(0, [], total_daily_bytes, avg_bar, max_bar)

    if best["v_dict"] is None:
        best["failure"] = {
            "reason": "no_valid_solution_found",
            "detail": "Search completed without any candidate satisfying all constraints.",
            "diagnostics": {
                **diag,
                "n_groups_active": int(n),
                "step": int(step),
                "tol": float(tol),
            },
            "notes": [
                "If pruned_budget_bounds is huge, bounds are too tight or daily_bytes is near-infeasible.",
                "If last_dim_no_grid_hit is huge, step size / rounding is preventing exact budget matches.",
                "If leaf_reject_min_ratio dominates, min_quota_ratio constraints are too strict.",
            ],
        }
    return best


def gen_quota_config_dict(
    total_daily_bytes,
    groups_config_dict,
    step_size_in_bytes=DEFAULT_STEP_SIZE_10_MB,
    error_tol=None,
):
    if error_tol is None:
        error_tol = int(step_size_in_bytes / 2)

    quota_config_dict = {
        "daily_bytes": total_daily_bytes,
        "step_size_in_bytes": step_size_in_bytes,
        "error_tol": error_tol,
    }

    quota_config_dict["groups"] = groups_config_dict

    return quota_config_dict


def main():

    example_quota_config_dict = {
        "daily_bytes": (500 / 20) * 1024**3,
        "step_size_in_bytes": 10 * 1024**2,
        "error_tol": 5 * 1024**2,
        "groups": {
            "regular_students": {
                "n": 100,
                "desired_quota_ratio": 0.1,
                "min_quota_ratio": 0.05,
                "max_num_bytes": 1000 * 1024**2,
                "min_num_bytes": 150 * 1024**2,
                "mse_weights": None,
            },
            "computer_students": {
                "n": 10,
                "desired_quota_ratio": 0.2,
                "min_quota_ratio": 0.1,
                "max_num_bytes": 1500 * 1024**2,
                "min_num_bytes": 300 * 1024**2,
                "mse_weights": None,
            },
            "staff": {
                "n": 8,
                "desired_quota_ratio": 0.3,
                "min_quota_ratio": 0.1,
                "max_num_bytes": 1750 * 1024**2,
                "min_num_bytes": 500 * 1024**2,
                "mse_weights": None,
            },
            "admin": {
                "n": 3,
                "desired_quota_ratio": 0.4,
                "min_quota_ratio": 0.1,
                "max_num_bytes": 2000 * 1024**2,
                "min_num_bytes": 750 * 1024**2,
                "mse_weights": None,
            },
        },
    }

    result = quota_vector_generator(quota_config_dict=example_quota_config_dict)

    print(result)


if __name__ == "__main__":
    main()
