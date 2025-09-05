"""
PQC Benchmark Module

Benchmarks Post-Quantum Cryptography algorithms via liboqs (liboqs-python):
- KEMs: ML-KEM (Kyber family)
- Signatures: ML-DSA (Dilithium family)

All timings are reported in milliseconds (ms).
"""
from __future__ import annotations

import time
import statistics
from typing import Any, Dict, List, Optional

# Import liboqs-python runtime as "oqs"
OQS_AVAILABLE = False
try:
    import oqs  # liboqs-python installs the module name "oqs"
    OQS_AVAILABLE = True
except Exception:
    oqs = None  # type: ignore
    OQS_AVAILABLE = False

# Friendly name -> liboqs mechanism
KEM_ALG_MAP: Dict[str, str] = {
    "kyber512": "ML-KEM-512",
    "kyber768": "ML-KEM-768",
    "kyber1024": "ML-KEM-1024",
}
SIG_ALG_MAP: Dict[str, str] = {
    "dilithium2": "ML-DSA-44",
    "dilithium3": "ML-DSA-65",
    "dilithium5": "ML-DSA-87",
}


def _stats_ms(samples_s: List[float]) -> Dict[str, Any]:
    """Convert second-based samples to ms stats with robust percentiles."""
    if not samples_s:
        return {
            "mean_ms": None,
            "median_ms": None,
            "std_ms": None,
            "min_ms": None,
            "max_ms": None,
            "p95_ms": None,
            "p99_ms": None,
            "samples": 0,
        }
    samples_ms = [s * 1000.0 for s in samples_s]
    samples_ms_sorted = sorted(samples_ms)
    n = len(samples_ms_sorted)

    def pct(p: float) -> float:
        if n == 1:
            return samples_ms_sorted[0]
        idx = min(max(int(p * n), 0), n - 1)
        return samples_ms_sorted[idx]

    return {
        "mean_ms": statistics.mean(samples_ms),
        "median_ms": statistics.median(samples_ms),
        "std_ms": statistics.pstdev(samples_ms) if n > 1 else 0.0,
        "min_ms": samples_ms_sorted[0],
        "max_ms": samples_ms_sorted[-1],
        "p95_ms": pct(0.95),
        "p99_ms": pct(0.99),
        "samples": n,
    }


def get_pqc_system_info() -> Dict[str, Any]:
    """Get PQC library system information."""
    if not OQS_AVAILABLE:
        return {"liboqs_available": False, "error": "liboqs-python (oqs) not installed"}
    get_kems = getattr(oqs, "get_enabled_kem_mechanisms", None)  # type: ignore[attr-defined]
    get_sigs = getattr(oqs, "get_enabled_sig_mechanisms", None)  # type: ignore[attr-defined]
    kems = list(get_kems()) if callable(get_kems) else []
    sigs = list(get_sigs()) if callable(get_sigs) else []
    oqs_version = getattr(oqs, "oqs_version", lambda: getattr(oqs, "__version__", "unknown"))()  # type: ignore[attr-defined]
    oqs_py_version = getattr(oqs, "oqs_python_version", lambda: getattr(oqs, "__version__", "unknown"))()  # type: ignore[attr-defined]
    return {
        "liboqs_available": True,
        "liboqs_version": oqs_version,
        "liboqs_python_version": oqs_py_version,
        "enabled_kems": kems,
        "enabled_sigs": sigs,
        "kyber512_available": "ML-KEM-512" in kems,
        "kyber768_available": "ML-KEM-768" in kems,
        "kyber1024_available": "ML-KEM-1024" in kems,
        "dilithium2_available": "ML-DSA-44" in sigs,
        "dilithium3_available": "ML-DSA-65" in sigs,
        "dilithium5_available": "ML-DSA-87" in sigs,
    }


class PQCBenchmark:
    """PQC benchmarking helper with consistent timing and warmup."""
    def __init__(self, iterations: int = 30, warmup: int = 5, message_size: int = 1024):
        if not OQS_AVAILABLE:
            raise ImportError("liboqs-python (oqs) not installed")
        self.iterations = max(int(iterations), 1)
        self.warmup = max(int(warmup), 0)
        self.message_size = max(int(message_size), 1)

    def _override_once(self, iterations: Optional[int], warmup: Optional[int], message_size: Optional[int]):
        prev = (self.iterations, self.warmup, self.message_size)
        if iterations is not None:
            self.iterations = max(int(iterations), 1)
        if warmup is not None:
            self.warmup = max(int(warmup), 0)
        if message_size is not None:
            self.message_size = max(int(message_size), 1)
        return prev

    def benchmark_kem(self, algorithm: str) -> Dict[str, Any]:
        if algorithm not in KEM_ALG_MAP:
            return {"status": "skipped", "reason": f"unsupported KEM: {algorithm}"}
        oqs_alg = KEM_ALG_MAP[algorithm]
        enabled = list(getattr(oqs, "get_enabled_kem_mechanisms", lambda: [])())  # type: ignore[attr-defined]
        if oqs_alg not in enabled:
            return {"status": "skipped", "reason": f"KEM not enabled in liboqs: {oqs_alg}"}

        keygen_times: List[float] = []
        encaps_times: List[float] = []
        decaps_times: List[float] = []

        # Warmup
        with oqs.KEM(oqs_alg) as kem:  # type: ignore[attr-defined]
            for _ in range(self.warmup):
                kem.generate_keypair()
                pk = kem.generate_keypair()
                ct, _ = kem.encap_secret(pk)
                kem.decap_secret(ct)

        # Timed loops
        with oqs.KEM(oqs_alg) as kem:  # type: ignore[attr-defined]
            for _ in range(self.iterations):
                t0 = time.perf_counter()
                kem.generate_keypair()
                t1 = time.perf_counter()
                keygen_times.append(t1 - t0)

            for _ in range(self.iterations):
                pk = kem.generate_keypair()
                t0 = time.perf_counter()
                ct, _ = kem.encap_secret(pk)
                t1 = time.perf_counter()
                kem.decap_secret(ct)
                t2 = time.perf_counter()
                encaps_times.append(t1 - t0)
                decaps_times.append(t2 - t1)

            sizes = {
                "public_key_bytes": kem.length_public_key,
                "secret_key_bytes": kem.length_secret_key,
                "ciphertext_bytes": kem.length_ciphertext,
                "shared_secret_bytes": kem.length_shared_secret,
            }

        return {
            "status": "ok",
            "algorithm": algorithm,
            "oqs_algorithm": oqs_alg,
            "type": "KEM",
            "iterations": self.iterations,
            "sizes": sizes,
            "operations": {
                "keygen": _stats_ms(keygen_times),
                "encaps": _stats_ms(encaps_times),
                "decaps": _stats_ms(decaps_times),
            },
        }

    def benchmark_sig(self, algorithm: str) -> Dict[str, Any]:
        if algorithm not in SIG_ALG_MAP:
            return {"status": "skipped", "reason": f"unsupported SIG: {algorithm}"}
        oqs_alg = SIG_ALG_MAP[algorithm]
        enabled = list(getattr(oqs, "get_enabled_sig_mechanisms", lambda: [])())  # type: ignore[attr-defined]
        if oqs_alg not in enabled:
            return {"status": "skipped", "reason": f"SIG not enabled in liboqs: {oqs_alg}"}

        keygen_times: List[float] = []
        sign_times: List[float] = []
        verify_times: List[float] = []
        msg = b"\x00" * self.message_size

        # Warmup
        with oqs.Signature(oqs_alg) as sig:  # type: ignore[attr-defined]
            for _ in range(self.warmup):
                pk = sig.generate_keypair()
                s = sig.sign(msg)
                sig.verify(msg, s, pk)

        # Timed loops
        with oqs.Signature(oqs_alg) as sig:  # type: ignore[attr-defined]
            pubkey = None
            for _ in range(self.iterations):
                t0 = time.perf_counter()
                pubkey = sig.generate_keypair()
                t1 = time.perf_counter()
                keygen_times.append(t1 - t0)

            for _ in range(self.iterations):
                t0 = time.perf_counter()
                s = sig.sign(msg)
                t1 = time.perf_counter()
                sign_times.append(t1 - t0)
                t2 = time.perf_counter()
                sig.verify(msg, s, pubkey)  # type: ignore[arg-type]
                t3 = time.perf_counter()
                verify_times.append(t3 - t2)

            sizes = {
                "public_key_bytes": sig.length_public_key,
                "secret_key_bytes": sig.length_secret_key,
                "signature_bytes": sig.length_signature,
            }

        return {
            "status": "ok",
            "algorithm": algorithm,
            "oqs_algorithm": oqs_alg,
            "type": "SIG",
            "iterations": self.iterations,
            "message_size": self.message_size,
            "sizes": sizes,
            "operations": {
                "keygen": _stats_ms(keygen_times),
                "sign": _stats_ms(sign_times),
                "verify": _stats_ms(verify_times),
            },
        }

    def run_comprehensive_pqc_benchmark(
        self,
        algorithms: Optional[List[str]] = None,
        iterations: Optional[int] = None,
        warmup: Optional[int] = None,
        message_size: Optional[int] = None,
        **_: Any
    ) -> Dict[str, Any]:
        """Aggregate benchmarks; accepts overrides and optional algorithms."""
        prev_iters, prev_warmup, prev_msg = self._override_once(iterations, warmup, message_size)
        try:
            # Default to all enabled algorithms if not provided
            if algorithms is None:
                algorithms = []
                info = get_pqc_system_info()
                if info.get("liboqs_available"):
                    enabled_kems = set(info.get("enabled_kems", []))
                    enabled_sigs = set(info.get("enabled_sigs", []))
                    for name, mech in KEM_ALG_MAP.items():
                        if mech in enabled_kems:
                            algorithms.append(name)
                    for name, mech in SIG_ALG_MAP.items():
                        if mech in enabled_sigs:
                            algorithms.append(name)

            results: Dict[str, Any] = {"system_info": get_pqc_system_info(), "algorithms": {}}
            for alg in algorithms:
                try:
                    if alg in KEM_ALG_MAP:
                        results["algorithms"][alg] = self.benchmark_kem(alg)
                    elif alg in SIG_ALG_MAP:
                        results["algorithms"][alg] = self.benchmark_sig(alg)
                    else:
                        results["algorithms"][alg] = {"status": "skipped", "reason": "unsupported"}
                except Exception as e:
                    results["algorithms"][alg] = {"status": "failed", "error": str(e)}
            return results
        finally:
            self.iterations, self.warmup, self.message_size = prev_iters, prev_warmup, prev_msg


if __name__ == "__main__":
    if not OQS_AVAILABLE:
        print("liboqs-python (oqs) not installed; PQC benchmarks cannot run.")
    else:
        print("Testing PQC benchmarks (quick)...")
        bench = PQCBenchmark(iterations=5, warmup=1)
        print(bench.benchmark_kem("kyber768"))
        print(bench.benchmark_sig("dilithium2"))
