"""
Enhanced Ouroboros benchmarking for PQC comparison.

This module pro    def benchmark_isolated_aead(self, iterations: int = 100, warm    def benchmark_isolated_scramble(self, iterations: int = 10    def benchmark_full_ouroboros_protocol(self, iterations: int = 100, warmup: int = 10,
                                         message_size: int = 256) -> Dict[str, Any]: warmup: int = 10,
                                   data_size: int = 256) -> Dict[str, Any]:: int = 10,
                               message_size: int = 256) -> Dict[str, Any]:des detailed benchmarking of Ouroboros operations:
- Isolated operations: ratchet, AEAD, scrambling
- Combined pipeline: complete encryption/decryption flow
- Memory profiling and overhead analysis

Uses consistent timing methodology with PQC benchmarks for fair comparison.
"""

import time
import statistics
import gc
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path

from ..crypto.utils import generate_random_bytes
from ..crypto.ratchet import RatchetState
from ..crypto.aead import AEADCipher
from ..crypto.scramble import scramble_data, unscramble_data
from ..protocol.encryptor import create_encryption_context
from ..protocol.decryptor import create_decryption_context


class OuroborosComparativeBenchmark:
    """Enhanced Ouroboros benchmarking for PQC comparison."""
    
    def __init__(self, use_ascon: bool = True):
        """
        Initialize Ouroboros benchmark suite.
        
        Args:
            use_ascon: Whether to use ASCON algorithms (default for Ouroboros)
        """
        self.use_ascon = use_ascon
        self.results = {}
    
    def benchmark_isolated_ratchet(self, iterations: int = 100, warmup: int = 10) -> Dict[str, Any]:
        """
        Benchmark isolated key ratcheting operations.
        
        Args:
            iterations: Number of key derivations
            warmup: Number of warmup iterations
            
        Returns:
            Ratchet benchmark results
        """
        print(f"      Ratchet key derivation ({iterations} iterations)...")
        
        # Initialize ratchet
        master_psk = generate_random_bytes(32)
        ratchet = RatchetState(master_psk, use_ascon=self.use_ascon)
        channel_id = 42
        
        # Warmup
        for i in range(warmup):
            ratchet.derive_keys(channel_id, i)
        
        # Benchmark key derivation
        derive_times = []
        gc.collect()
        
        for i in range(iterations):
            start = time.perf_counter()
            ke, nonce, kp = ratchet.derive_keys(channel_id, i + warmup)
            end = time.perf_counter()
            derive_times.append((end - start) * 1000)  # milliseconds
        
        return self._analyze_timing(derive_times, 'ratchet_derive_keys')
    
    def benchmark_isolated_aead(self, iterations: int = 100, warmup: int = 50,
                               message_size: int = 1024) -> Dict[str, Any]:
        """
        Benchmark isolated AEAD operations (encrypt/decrypt).
        
        Args:
            iterations: Number of AEAD operations
            warmup: Number of warmup iterations
            message_size: Size of test messages
            
        Returns:
            AEAD benchmark results
        """
        print(f"      AEAD operations ({iterations} iterations, {message_size}B messages)...")
        
        # Initialize AEAD
        aead = AEADCipher(use_ascon=self.use_ascon)
        message = generate_random_bytes(message_size)
        
        # Fixed key and nonce for consistent benchmarking
        key = generate_random_bytes(32)
        nonce = generate_random_bytes(12)
        
        results = {
            'message_size_bytes': message_size,
            'aead_algorithm': 'ASCON-128a' if self.use_ascon else 'AES-GCM',
            'operations': {}
        }
        
        # Benchmark encryption
        encrypt_times = []
        
        # Warmup
        for _ in range(warmup):
            aead.encrypt(key, nonce, message)
        
        gc.collect()
        for _ in range(iterations):
            start = time.perf_counter()
            ciphertext, tag = aead.encrypt(key, nonce, message)
            end = time.perf_counter()
            encrypt_times.append((end - start) * 1000)
        
        results['operations']['encrypt'] = self._analyze_timing(encrypt_times, 'aead_encrypt')
        
        # Benchmark decryption
        decrypt_times = []
        ciphertext, tag = aead.encrypt(key, nonce, message)
        
        # Warmup
        for _ in range(warmup):
            aead.decrypt(key, nonce, ciphertext, tag)
        
        gc.collect()
        for _ in range(iterations):
            start = time.perf_counter()
            decrypted = aead.decrypt(key, nonce, ciphertext, tag)
            end = time.perf_counter()
            decrypt_times.append((end - start) * 1000)
        
        results['operations']['decrypt'] = self._analyze_timing(decrypt_times, 'aead_decrypt')
        
        return results
    
    def benchmark_isolated_scrambling(self, iterations: int = 100, warmup: int = 50,
                                    data_size: int = 1024) -> Dict[str, Any]:
        """
        Benchmark isolated scrambling operations.
        
        Args:
            iterations: Number of scrambling operations
            warmup: Number of warmup iterations
            data_size: Size of data to scramble
            
        Returns:
            Scrambling benchmark results
        """
        print(f"      Scrambling operations ({iterations} iterations, {data_size}B data)...")
        
        # Test data
        data = generate_random_bytes(data_size)
        permutation_key = generate_random_bytes(32)
        tag = generate_random_bytes(16)
        r = generate_random_bytes(4)
        
        results = {
            'data_size_bytes': data_size,
            'operations': {}
        }
        
        # Benchmark scrambling
        scramble_times = []
        
        # Warmup
        for _ in range(warmup):
            scramble_data(data, permutation_key, tag, r)
        
        gc.collect()
        for _ in range(iterations):
            start = time.perf_counter()
            scrambled = scramble_data(data, permutation_key, tag, r)
            end = time.perf_counter()
            scramble_times.append((end - start) * 1000)
        
        results['operations']['scramble'] = self._analyze_timing(scramble_times, 'scramble')
        
        # Benchmark unscrambling
        unscramble_times = []
        scrambled = scramble_data(data, permutation_key, tag, r)
        
        # Warmup
        for _ in range(warmup):
            unscramble_data(scrambled, permutation_key, tag, r)
        
        gc.collect()
        for _ in range(iterations):
            start = time.perf_counter()
            unscrambled = unscramble_data(scrambled, permutation_key, tag, r)
            end = time.perf_counter()
            unscramble_times.append((end - start) * 1000)
        
        results['operations']['unscramble'] = self._analyze_timing(unscramble_times, 'unscramble')
        
        return results
    
    def benchmark_full_ouroboros_protocol(self, iterations: int = 100, warmup: int = 50,
                                        message_size: int = 1024) -> Dict[str, Any]:
        """
        Benchmark complete Ouroboros protocol flow.
        
        Full pipeline:
        1. Derive keys from ratchet
        2. AEAD encrypt message
        3. Scramble ciphertext
        4. Build packet
        5. Parse packet
        6. Unscramble ciphertext
        7. AEAD decrypt message
        
        Args:
            iterations: Number of complete protocol runs
            warmup: Number of warmup iterations
            message_size: Size of test messages
            
        Returns:
            Complete protocol benchmark results
        """
        print(f"      Full Ouroboros protocol ({iterations} iterations, {message_size}B messages)...")
        
        # Setup
        master_psk = generate_random_bytes(32)
        channel_id = 42
        message = generate_random_bytes(message_size)
        
        # Create contexts
        encryptor = create_encryption_context(master_psk, channel_id, self.use_ascon)
        decryptor = create_decryption_context(master_psk, channel_id, self.use_ascon)
        
        results = {
            'protocol': 'Full Ouroboros',
            'message_size_bytes': message_size,
            'aead_algorithm': 'ASCON-128a' if self.use_ascon else 'AES-GCM',
            'header_overhead_bytes': 25,  # channel_id(1) + counter(4) + r(4) + tag(16)
            'iterations': iterations,
            'operations': {}
        }
        
        # Warmup
        for _ in range(warmup):
            packet = encryptor.encrypt_message(message)
            decrypted = decryptor.decrypt_packet(packet.to_bytes())
        
        # Benchmark encryption pipeline
        encrypt_times = []
        gc.collect()
        
        for _ in range(iterations):
            start = time.perf_counter()
            packet = encryptor.encrypt_message(message)
            end = time.perf_counter()
            encrypt_times.append((end - start) * 1000)
        
        results['operations']['encrypt_pipeline'] = self._analyze_timing(encrypt_times, 'encrypt_pipeline')
        
        # Benchmark decryption pipeline
        decrypt_times = []
        
        # Pre-generate packets to avoid replay protection during timing
        print(f"      Generating {iterations} test packets...")
        test_packets = []
        for _ in range(iterations):
            packet = encryptor.encrypt_message(message)
            test_packets.append(packet.to_bytes())
        
        gc.collect()
        for i in range(iterations):
            start = time.perf_counter()
            decrypted = decryptor.decrypt_packet(test_packets[i])
            end = time.perf_counter()
            decrypt_times.append((end - start) * 1000)
            
            if decrypted != message:
                raise RuntimeError("Protocol verification failed during benchmark")
        
        results['operations']['decrypt_pipeline'] = self._analyze_timing(decrypt_times, 'decrypt_pipeline')
        
        # Benchmark complete round-trip
        roundtrip_times = []
        gc.collect()
        
        for _ in range(iterations):
            start = time.perf_counter()
            
            # Encrypt
            packet = encryptor.encrypt_message(message)
            packet_bytes = packet.to_bytes()
            
            # Decrypt
            decrypted = decryptor.decrypt_packet(packet_bytes)
            
            end = time.perf_counter()
            roundtrip_times.append((end - start) * 1000)
            
            if decrypted != message:
                raise RuntimeError("Round-trip verification failed")
        
        results['operations']['full_roundtrip'] = self._analyze_timing(roundtrip_times, 'full_roundtrip')
        
        return results
    
    def _analyze_timing(self, times: List[float], operation_name: str) -> Dict[str, Any]:
        """Analyze timing measurements and compute statistics."""
        if not times:
            return {'operation': operation_name}
        
        times_sorted = sorted(times)
        mean_time = statistics.mean(times)
        
        return {
            'operation': operation_name,
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
    
    def run_comprehensive_ouroboros_benchmark(self, iterations: int = 100,
                                            message_sizes: List[int] = [256, 1024]) -> Dict[str, Any]:
        """
        Run complete Ouroboros benchmark suite for PQC comparison.
        
        Args:
            iterations: Number of iterations per test
            message_sizes: Message sizes to test
            
        Returns:
            Complete Ouroboros benchmark results
        """
        print(f"  Running comprehensive Ouroboros benchmark suite...")
        
        results = {
            'protocol': 'Ouroboros',
            'aead_algorithm': 'ASCON-128a' if self.use_ascon else 'AES-GCM',
            'ratchet_algorithm': 'ASCON-Hash256' if self.use_ascon else 'HKDF-SHA256',
            'scrambling_algorithm': 'Fisher-Yates + ChaCha20',
            'iterations': iterations,
            'isolated_operations': {},
            'full_protocol': {}
        }
        
        # Benchmark isolated operations
        print("    Isolated operations:")
        results['isolated_operations']['ratchet'] = self.benchmark_isolated_ratchet(iterations)
        
        for msg_size in message_sizes:
            results['isolated_operations'][f'aead_{msg_size}B'] = self.benchmark_isolated_aead(
                iterations, message_size=msg_size
            )
            results['isolated_operations'][f'scrambling_{msg_size}B'] = self.benchmark_isolated_scrambling(
                iterations, data_size=msg_size
            )
        
        # Benchmark full protocol
        print("    Full protocol:")
        for msg_size in message_sizes:
            results['full_protocol'][f'{msg_size}B'] = self.benchmark_full_ouroboros_protocol(
                iterations, message_size=msg_size
            )
        
        return results
    
    def get_protocol_overhead_analysis(self, message_sizes: List[int] = [256, 1024]) -> Dict[str, Any]:
        """
        Analyze Ouroboros protocol overhead.
        
        Args:
            message_sizes: Message sizes to analyze
            
        Returns:
            Overhead analysis results
        """
        overhead_analysis = {
            'header_size_bytes': 25,  # Fixed header: channel_id + counter + r + tag
            'header_breakdown': {
                'channel_id': 1,
                'counter': 4,
                'random_r': 4,
                'aead_tag': 16
            },
            'per_message_overhead': {}
        }
        
        for msg_size in message_sizes:
            overhead_bytes = 25  # Header only (no key exchange, no signatures)
            overhead_percent = (overhead_bytes / msg_size) * 100
            
            overhead_analysis['per_message_overhead'][f'{msg_size}B'] = {
                'message_size_bytes': msg_size,
                'overhead_bytes': overhead_bytes,
                'overhead_percent': overhead_percent,
                'total_packet_size_bytes': msg_size + overhead_bytes,
                'efficiency_percent': (msg_size / (msg_size + overhead_bytes)) * 100
            }
        
        return overhead_analysis


def create_ouroboros_vs_pqc_comparison_data(ouroboros_results: Dict[str, Any], 
                                          pqc_results: Dict[str, Any]) -> Dict[str, Any]:
    """Create comparison data structure for Ouroboros vs PQC analysis."""
    
    # Extract Ouroboros summary
    ouroboros_summary = {}
    if 'full_protocol' in ouroboros_results:
        for size, data in ouroboros_results['full_protocol'].items():
            ops = data.get('operations', {})
            roundtrip = ops.get('full_roundtrip', {})
            ouroboros_summary[size] = {
                'full_roundtrip_ms': roundtrip.get('mean_ms', 0.0),
                'throughput_ops_per_sec': roundtrip.get('ops_per_sec', 0.0),
                'overhead_bytes': ouroboros_results.get('overhead_analysis', {}).get('header_size_bytes', 25)
            }
    
    # Extract PQC summary - THIS WAS THE MISSING PIECE
    pqc_summary = {}
    if 'algorithms' in pqc_results:
        for alg_name, alg_data in pqc_results['algorithms'].items():
            if alg_data.get('status') == 'ok':
                ops = alg_data.get('operations', {})
                sizes = alg_data.get('sizes', {})
                alg_type = alg_data.get('type', '')
                
                if alg_type == 'KEM':
                    # KEM: keygen + encaps + decaps
                    keygen_ms = ops.get('keygen', {}).get('mean_ms', 0.0)
                    encaps_ms = ops.get('encaps', {}).get('mean_ms', 0.0) 
                    decaps_ms = ops.get('decaps', {}).get('mean_ms', 0.0)
                    full_kem_ms = keygen_ms + encaps_ms + decaps_ms
                    
                    pqc_summary[alg_name] = {
                        'type': 'KEM',
                        'keygen_ms': keygen_ms,
                        'encaps_ms': encaps_ms,
                        'decaps_ms': decaps_ms,
                        'full_kem_roundtrip_ms': full_kem_ms,
                        'throughput_ops_per_sec': 1000.0 / full_kem_ms if full_kem_ms > 0 else 0.0,
                        'public_key_bytes': sizes.get('public_key_bytes', 0),
                        'secret_key_bytes': sizes.get('secret_key_bytes', 0),
                        'ciphertext_bytes': sizes.get('ciphertext_bytes', 0)
                    }
                    
                elif alg_type == 'SIG':
                    # SIG: keygen + sign + verify
                    keygen_ms = ops.get('keygen', {}).get('mean_ms', 0.0)
                    sign_ms = ops.get('sign', {}).get('mean_ms', 0.0)
                    verify_ms = ops.get('verify', {}).get('mean_ms', 0.0)
                    full_sig_ms = keygen_ms + sign_ms + verify_ms
                    
                    pqc_summary[alg_name] = {
                        'type': 'SIG',
                        'keygen_ms': keygen_ms,
                        'sign_ms': sign_ms,
                        'verify_ms': verify_ms,
                        'full_sig_roundtrip_ms': full_sig_ms,
                        'throughput_ops_per_sec': 1000.0 / full_sig_ms if full_sig_ms > 0 else 0.0,
                        'public_key_bytes': sizes.get('public_key_bytes', 0),
                        'secret_key_bytes': sizes.get('secret_key_bytes', 0),
                        'signature_bytes': sizes.get('signature_bytes', 0)
                    }
    
    return {
        'comparison_type': 'Ouroboros vs PQC',
        'timestamp': time.time(),
        'methodology': 'Same timing harness, equivalent security assumptions',
        'ouroboros_summary': ouroboros_summary,
        'pqc_summary': pqc_summary,  # Now populated!
        'comparative_analysis': {
            'speed_advantage': 'Ouroboros symmetric operations vs PQC asymmetric operations',
            'overhead_advantage': 'Ouroboros 25-byte header vs PQC keys+signatures', 
            'security_model': 'Ouroboros: pre-shared keys, PQC: public-key cryptography',
            'use_case_fit': 'Ouroboros optimized for IoT, PQC for general internet'
        }
    }
