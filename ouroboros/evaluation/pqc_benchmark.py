"""
PQC Benchmark Module

Comprehensive benchmarking for Post-Quantum Cryptography algorithms:
- Kyber768 (Key Encapsulation Mechanism)
- Dilithium2 (Digital Signatures)
- Full PQC Protocol Flow

All benchmarks use consistent timing methodology for fair comparison with Ouroboros.
"""

import gc
import statistics
import time
from typing import Any, Dict, List

try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False
    print("Warning: liboqs-python not available, PQC benchmarks will be skipped")


def get_pqc_system_info() -> Dict[str, Any]:
    """Get PQC library system information."""
    if not OQS_AVAILABLE:
        return {
            'liboqs_available': False,
            'error': 'liboqs-python not installed'
        }
    
    return {
        'liboqs_available': True,
        'liboqs_version': oqs.oqs_version(),
        'liboqs_python_version': oqs.oqs_python_version(),
        'enabled_kems': oqs.get_enabled_kem_mechanisms(),
        'enabled_sigs': oqs.get_enabled_sig_mechanisms(),
        'kyber768_available': 'ML-KEM-768' in oqs.get_enabled_kem_mechanisms(),
        'dilithium2_available': 'ML-DSA-44' in oqs.get_enabled_sig_mechanisms()
    }


class PQCBenchmark:
    """Comprehensive PQC benchmarking class."""
    
    def __init__(self):
        """Initialize PQC benchmark."""
        if not OQS_AVAILABLE:
            raise ImportError("liboqs-python is required for PQC benchmarks")
    
    def benchmark_kyber768(self, iterations: int = 100, warmup: int = 10) -> Dict[str, Any]:
        """
        Benchmark Kyber768 KEM operations.
        
        Args:
            iterations: Number of benchmark iterations
            warmup: Number of warmup iterations
            
        Returns:
            Comprehensive Kyber768 benchmark results
        """
        print(f"    Benchmarking Kyber768 KEM ({iterations} iterations)...")
        
        # Initialize KEM
        kem = oqs.KeyEncapsulation('ML-KEM-768')
        
        # Get algorithm info
        details = kem.details
        pk_size = details['length_public_key']
        sk_size = details['length_secret_key']
        ct_size = details['length_ciphertext']
        
        results = {
            'algorithm': 'Kyber768',
            'type': 'KEM',
            'iterations': iterations,
            'pk_size_bytes': pk_size,
            'sk_size_bytes': sk_size,
            'ciphertext_size_bytes': ct_size,
            'operations': {}
        }
        
        # Benchmark key generation
        print(f"      Key generation...")
        keygen_times = []
        
        # Warmup
        for _ in range(warmup):
            with oqs.KeyEncapsulation('ML-KEM-768') as temp_kem:
                temp_kem.generate_keypair()

        gc.collect()
        for _ in range(iterations):
            start = time.perf_counter()
            with oqs.KeyEncapsulation('ML-KEM-768') as temp_kem:
                public_key = temp_kem.generate_keypair()
            end = time.perf_counter()
            keygen_times.append((end - start) * 1000)  # milliseconds

        results['operations']['keygen'] = self._analyze_timing(keygen_times)
        
        # Generate a keypair for encaps/decaps benchmarks
        public_key = kem.generate_keypair()
        
        # Benchmark encapsulation
        print(f"      Encapsulation...")
        encaps_times = []
        
        # Warmup
        for _ in range(warmup):
            try:
                kem.encap_secret(public_key)
            except Exception:
                pass

        gc.collect()
        for _ in range(iterations):
            start = time.perf_counter()
            try:
                ciphertext, shared_secret = kem.encap_secret(public_key)
            except ValueError:
                # Handle case where encap_secret returns more values
                encap_result = kem.encap_secret(public_key)
                ciphertext = encap_result[0]
                shared_secret = encap_result[1]
            end = time.perf_counter()
            encaps_times.append((end - start) * 1000)  # milliseconds

        results['operations']['encaps'] = self._analyze_timing(encaps_times)
        
        # Benchmark decapsulation
        print(f"      Decapsulation...")
        decaps_times = []
        try:
            ciphertext, expected_shared_secret = kem.encap_secret(public_key)
        except ValueError:
            # Handle case where encap_secret returns more than 2 values
            encap_result = kem.encap_secret(public_key)
            ciphertext = encap_result[0]
            expected_shared_secret = encap_result[1]
        
        # Warmup
        for _ in range(warmup):
            try:
                kem.decap_secret(ciphertext)
            except Exception:
                pass

        gc.collect()
        for _ in range(iterations):
            start = time.perf_counter()
            shared_secret = kem.decap_secret(ciphertext)
            end = time.perf_counter()
            decaps_times.append((end - start) * 1000)  # milliseconds

        results['operations']['decaps'] = self._analyze_timing(decaps_times)
        
        return results
    
    def benchmark_dilithium2(self, iterations: int = 100, warmup: int = 10, 
                           message_size: int = 1024) -> Dict[str, Any]:
        """
        Benchmark Dilithium2 signature operations.
        
        Args:
            iterations: Number of benchmark iterations
            warmup: Number of warmup iterations
            message_size: Size of test message in bytes
            
        Returns:
            Comprehensive Dilithium2 benchmark results
        """
        print(f"    Benchmarking Dilithium2 Signatures ({iterations} iterations, {message_size}B messages)...")
        
        # Initialize Signature
        sig = oqs.Signature('ML-DSA-44')
        
        # Get algorithm info
        details = sig.details
        pk_size = details['length_public_key']
        sk_size = details['length_secret_key']
        sig_size = details['length_signature']
        
        # Test message
        message = b'A' * message_size
        
        results = {
            'algorithm': 'Dilithium2',
            'type': 'Signature',
            'iterations': iterations,
            'message_size_bytes': message_size,
            'pk_size_bytes': pk_size,
            'sk_size_bytes': sk_size,
            'signature_size_bytes': sig_size,
            'operations': {}
        }
        
        # Benchmark key generation
        print(f"      Key generation...")
        keygen_times = []
        
        # Warmup
        for _ in range(warmup):
            with oqs.Signature('ML-DSA-44') as temp_sig:
                temp_sig.generate_keypair()

        gc.collect()
        for _ in range(iterations):
            start = time.perf_counter()
            with oqs.Signature('ML-DSA-44') as temp_sig:
                public_key = temp_sig.generate_keypair()
            end = time.perf_counter()
            keygen_times.append((end - start) * 1000)  # milliseconds

        results['operations']['keygen'] = self._analyze_timing(keygen_times)
        
        # Generate a keypair for signing/verification benchmarks  
        public_key = sig.generate_keypair()
        
        # Benchmark signing
        print(f"      Signing...")
        sign_times = []
        
        # Warmup
        for _ in range(warmup):
            try:
                sig.sign(message)
            except Exception:
                pass

        gc.collect()
        for _ in range(iterations):
            start = time.perf_counter()
            signature = sig.sign(message)
            end = time.perf_counter()
            sign_times.append((end - start) * 1000)  # milliseconds

        results['operations']['sign'] = self._analyze_timing(sign_times)
        
        # Benchmark verification
        print(f"      Verification...")
        verify_times = []
        signature = sig.sign(message)
        
        # Use same sig instance for verification (which has the correct key state)
        # Warmup
        for _ in range(warmup):
            try:
                sig.verify(message, signature, public_key)
            except Exception:
                pass
        
        gc.collect()
        for i in range(iterations):
            # Use pre-generated signature for consistent verification
            start = time.perf_counter()
            try:
                is_valid = sig.verify(message, signature, public_key)
                if not is_valid:
                    if i < 5:  # Only show first 5 warnings
                        print(f"        Warning: Signature verification returned False at iteration {i}")
                    elif i == 5:
                        print(f"        ... (suppressing further verification warnings)")
                    # Continue benchmark despite verification failure
            except Exception as e:
                if i < 5:
                    print(f"        Warning: Signature verification error at iteration {i}: {e}")
                continue  # Skip this iteration but don't fail
            end = time.perf_counter()
            verify_times.append((end - start) * 1000)  # milliseconds
        
        results['operations']['verify'] = self._analyze_timing(verify_times)
        
        return results
    
    def benchmark_full_pqc_protocol(self, iterations: int = 100, warmup: int = 50,
                                   message_size: int = 1024) -> Dict[str, Any]:
        """
        Benchmark complete PQC protocol flow: KEM + Signature.
        
        Simulates:
        1. Generate Dilithium2 keypair (long-term identity)
        2. Generate Kyber768 keypair (ephemeral)
        3. Encapsulate shared secret
        4. Sign the ciphertext + message with Dilithium2
        5. Verify signature
        6. Decapsulate shared secret
        
        Args:
            iterations: Number of full protocol runs
            warmup: Number of warmup iterations
            message_size: Size of test message
            
        Returns:
            Complete protocol benchmark results
        """
        print(f"    Benchmarking full PQC protocol ({iterations} iterations, {message_size}B messages)...")
        
        # Initialize algorithms
        kem = oqs.KeyEncapsulation('ML-KEM-768')
        sig = oqs.Signature('ML-DSA-44')
        
        message = b'A' * message_size
        
        # Generate long-term Dilithium keypair
        sig_public_key = sig.generate_keypair()
        
        results = {
            'protocol': 'Full PQC (Kyber768 + Dilithium2)',
            'iterations': iterations,
            'message_size_bytes': message_size,
            'total_overhead_bytes': (
                sig.details['length_public_key'] + 
                sig.details['length_signature'] +
                kem.details['length_public_key'] +
                kem.details['length_ciphertext']
            ),
            'operations': {}
        }
        
        # Warmup
        print(f"      Warming up...")
        for _ in range(warmup):
            # Full protocol run
            kem_public = kem.generate_keypair()
            ciphertext, shared_secret = kem.encap_secret(kem_public)
            signature = sig.sign(message + ciphertext)
            recovered_secret = kem.decap_secret(ciphertext)
        
        # Benchmark complete protocol
        print(f"      Full protocol execution...")
        protocol_times = []
        
        gc.collect()
        for _ in range(iterations):
            start = time.perf_counter()
            
            # 1. Generate ephemeral Kyber keypair  
            kem_public = kem.generate_keypair()
            
            # 2. Encapsulate shared secret
            ciphertext, shared_secret = kem.encap_secret(kem_public)
            
            # 3. Sign message + ciphertext
            signature = sig.sign(message + ciphertext)
            
            # 4. Verify signature (using same instance)
            try:
                is_valid = sig.verify(message + ciphertext, signature, sig_public_key)
                if not is_valid:
                    if _ < 5:
                        print(f"      Warning: Signature verification failed at iteration {_}")
                    # Continue benchmark despite verification failure
            except Exception as e:
                if _ < 5:
                    print(f"      Warning: Verification error at iteration {_}: {e}")
            
            # 5. Decapsulate shared secret
            recovered_secret = kem.decap_secret(ciphertext)
            if recovered_secret != shared_secret:
                if _ < 5:
                    print(f"      Warning: Secret recovery mismatch at iteration {_}")
                # Continue benchmark despite mismatch
            
            end = time.perf_counter()
            protocol_times.append((end - start) * 1000)  # milliseconds
        
        results['operations']['full_protocol'] = self._analyze_timing(protocol_times)
        
        return results
    
    def _analyze_timing(self, times: List[float]) -> Dict[str, Any]:
        """Analyze timing measurements and compute statistics."""
        if not times:
            return {'operation': 'unknown'}
        
        times_sorted = sorted(times)
        mean_time = statistics.mean(times)
        
        return {
            'mean_ms': mean_time,
            'median_ms': statistics.median(times),
            'std_ms': statistics.stdev(times) if len(times) > 1 else 0.0,
            'min_ms': min(times),
            'max_ms': max(times),
            'p95_ms': times_sorted[int(0.95 * len(times_sorted))],
            'p99_ms': times_sorted[int(0.99 * len(times_sorted))],
            'ops_per_sec': 1000.0 / mean_time if mean_time > 0 else 0.0,
            'samples': len(times)
        }
    
    def run_comprehensive_pqc_benchmark(self, iterations: int = 100,
                                       message_sizes: List[int] = [256, 1024]) -> Dict[str, Any]:
        """
        Run complete PQC benchmark suite for comparison with Ouroboros.
        
        Benchmarks:
        - Kyber768 KEM (keygen, encaps, decaps)
        - Dilithium2 Signatures (keygen, sign, verify) for each message size
        - Full PQC protocol for each message size
        
        Args:
            iterations: Number of iterations for each benchmark
            message_sizes: List of message sizes to benchmark
            
        Returns:
            Complete PQC benchmark results
        """
        print(f"  Running comprehensive PQC benchmark suite...")
        
        results = {
            'benchmark_type': 'Comprehensive PQC',
            'iterations': iterations,
            'message_sizes': message_sizes,
            'system_info': get_pqc_system_info()
        }
        
        # 1. Benchmark Kyber768 KEM
        try:
            results['kyber768'] = self.benchmark_kyber768(iterations)
        except Exception as e:
            print(f"    Kyber768 benchmark failed: {e}")
            results['kyber768'] = {'error': str(e)}
        
        # 2. Benchmark Dilithium2 for each message size
        results['dilithium2'] = {}
        for size in message_sizes:
            try:
                results['dilithium2'][f'{size}B'] = self.benchmark_dilithium2(
                    iterations, message_size=size
                )
            except Exception as e:
                print(f"    Dilithium2 benchmark failed for {size}B: {e}")
                results['dilithium2'][f'{size}B'] = {'error': str(e)}
        
        # 3. Benchmark full PQC protocol for each message size
        results['full_protocol'] = {}
        for size in message_sizes:
            try:
                results['full_protocol'][f'{size}B'] = self.benchmark_full_pqc_protocol(
                    iterations, message_size=size
                )
            except Exception as e:
                print(f"    Full PQC protocol benchmark failed for {size}B: {e}")
                results['full_protocol'][f'{size}B'] = {'error': str(e)}
        
        return results


if __name__ == "__main__":
    """Test PQC benchmarks."""
    if not OQS_AVAILABLE:
        print("liboqs-python not available, cannot run PQC benchmarks")
        exit(1)
    
    print("Testing PQC benchmarks...")
    bench = PQCBenchmark()
    
    # Quick test
    results = bench.run_comprehensive_pqc_benchmark(iterations=5, message_sizes=[256])
    
    print(f"\nPQC Benchmark Results:")
    if 'kyber768' in results and 'operations' in results['kyber768']:
        kyber = results['kyber768']['operations']
        print(f"  Kyber768 - Keygen: {kyber['keygen']['mean_ms']:.2f}ms, "
              f"Encaps: {kyber['encaps']['mean_ms']:.2f}ms, "
              f"Decaps: {kyber['decaps']['mean_ms']:.2f}ms")
    
    if 'dilithium2' in results and '256B' in results['dilithium2']:
        if 'operations' in results['dilithium2']['256B']:
            dil = results['dilithium2']['256B']['operations']
            print(f"  Dilithium2 - Keygen: {dil['keygen']['mean_ms']:.2f}ms, "
                  f"Sign: {dil['sign']['mean_ms']:.2f}ms, "
                  f"Verify: {dil['verify']['mean_ms']:.2f}ms")
    
    print("PQC benchmarks completed!")
