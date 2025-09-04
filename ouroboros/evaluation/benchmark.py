"""
Benchmark module for performance evaluation of Ouroboros Protocol.

This module provides comprehensive benchmarking tools to measure encryption/decryption
performance, memory usage, and protocol overhead for dissertation evaluation.
"""

import time
import psutil
import statistics
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import threading
import gc

from ..crypto.utils import generate_random_bytes
from ..protocol.encryptor import create_encryption_context, benchmark_encryption
from ..protocol.decryptor import create_decryption_context, benchmark_decryption


@dataclass
class BenchmarkResult:
    """Container for benchmark results."""
    name: str
    algorithm: str
    message_size: int
    iterations: int
    total_time: float
    avg_time: float
    throughput_mbps: float
    memory_usage: Optional[Dict[str, float]] = None
    overhead_bytes: Optional[int] = None
    overhead_percent: Optional[float] = None
    cpu_usage: Optional[float] = None


class PerformanceBenchmark:
    """
    Comprehensive performance benchmarking for Ouroboros Protocol.
    """
    
    def __init__(self):
        """Initialize benchmark suite."""
        self.results: List[BenchmarkResult] = []
        self.baseline_memory = None
    
    def measure_memory_usage(self) -> Dict[str, float]:
        """
        Measure current memory usage.
        
        Returns:
            Dictionary with memory statistics in MB
        """
        process = psutil.Process()
        memory_info = process.memory_info()
        
        return {
            'rss': memory_info.rss / 1024 / 1024,  # MB
            'vms': memory_info.vms / 1024 / 1024,  # MB
            'percent': process.memory_percent()
        }
    
    def benchmark_encryption_performance(self, message_sizes: List[int], 
                                       iterations: int = 1000,
                                       use_ascon: bool = False) -> List[BenchmarkResult]:
        """
        Benchmark encryption performance across different message sizes.
        
        Args:
            message_sizes: List of message sizes to test
            iterations: Number of iterations per size
            use_ascon: Whether to use ASCON algorithms
            
        Returns:
            List of benchmark results
        """
        algorithm = "ASCON" if use_ascon else "AES-GCM"
        results = []
        
        for size in message_sizes:
            # Force garbage collection before benchmark
            gc.collect()
            
            # Measure memory before
            memory_before = self.measure_memory_usage()
            
            # Run encryption benchmark
            bench_result = benchmark_encryption(
                plaintext_size=size,
                iterations=iterations,
                use_ascon=use_ascon
            )
            
            # Measure memory after
            memory_after = self.measure_memory_usage()
            memory_delta = {
                'rss_delta': memory_after['rss'] - memory_before['rss'],
                'vms_delta': memory_after['vms'] - memory_before['vms']
            }
            
            result = BenchmarkResult(
                name=f"Encryption-{algorithm}-{size}B",
                algorithm=algorithm,
                message_size=size,
                iterations=iterations,
                total_time=bench_result['total_time'],
                avg_time=bench_result['avg_time_per_message'],
                throughput_mbps=bench_result['throughput_mbps'],
                memory_usage=memory_delta,
                overhead_bytes=int(bench_result['protocol_overhead']),
                overhead_percent=bench_result['overhead_percent']
            )
            
            results.append(result)
            self.results.append(result)
        
        return results
    
    def benchmark_decryption_performance(self, message_sizes: List[int],
                                       iterations: int = 1000,
                                       use_ascon: bool = False) -> List[BenchmarkResult]:
        """
        Benchmark decryption performance across different message sizes.
        
        Args:
            message_sizes: List of message sizes to test
            iterations: Number of iterations per size
            use_ascon: Whether to use ASCON algorithms
            
        Returns:
            List of benchmark results
        """
        algorithm = "ASCON" if use_ascon else "AES-GCM"
        results = []
        
        for size in message_sizes:
            # Force garbage collection before benchmark
            gc.collect()
            
            # Measure memory before
            memory_before = self.measure_memory_usage()
            
            # Run decryption benchmark
            bench_result = benchmark_decryption(
                packet_size=size,
                iterations=iterations,
                use_ascon=use_ascon
            )
            
            # Measure memory after
            memory_after = self.measure_memory_usage()
            memory_delta = {
                'rss_delta': memory_after['rss'] - memory_before['rss'],
                'vms_delta': memory_after['vms'] - memory_before['vms']
            }
            
            result = BenchmarkResult(
                name=f"Decryption-{algorithm}-{size}B",
                algorithm=algorithm,
                message_size=size,
                iterations=iterations,
                total_time=bench_result['total_time'],
                avg_time=bench_result['avg_time_per_message'],
                throughput_mbps=bench_result['throughput_mbps'],
                memory_usage=memory_delta
            )
            
            results.append(result)
            self.results.append(result)
        
        return results
    
    def compare_algorithms(self, message_sizes: List[int], 
                          iterations: int = 1000) -> Dict[str, List[BenchmarkResult]]:
        """
        Compare AES-GCM vs ASCON performance.
        
        Args:
            message_sizes: List of message sizes to test
            iterations: Number of iterations per test
            
        Returns:
            Dictionary with results for each algorithm
        """
        results = {
            'AES-GCM': {
                'encryption': [],
                'decryption': []
            },
            'ASCON': {
                'encryption': [],
                'decryption': []
            }
        }
        
        # Test AES-GCM
        results['AES-GCM']['encryption'] = self.benchmark_encryption_performance(
            message_sizes, iterations, use_ascon=False
        )
        results['AES-GCM']['decryption'] = self.benchmark_decryption_performance(
            message_sizes, iterations, use_ascon=False
        )
        
        # Test ASCON (if available)
        try:
            results['ASCON']['encryption'] = self.benchmark_encryption_performance(
                message_sizes, iterations, use_ascon=True
            )
            results['ASCON']['decryption'] = self.benchmark_decryption_performance(
                message_sizes, iterations, use_ascon=True
            )
        except ImportError:
            print("ASCON not available, skipping ASCON benchmarks")
        
        return results
    
    def benchmark_scrambling_overhead(self, message_sizes: List[int],
                                    iterations: int = 1000) -> List[Dict[str, Any]]:
        """
        Measure overhead of scrambling vs plain AEAD.
        
        Args:
            message_sizes: List of message sizes to test
            iterations: Number of iterations per test
            
        Returns:
            List of overhead measurements
        """
        from ..crypto.aead import create_aead_cipher
        from ..crypto.scramble import DataScrambler
        
        results = []
        
        for size in message_sizes:
            plaintext = generate_random_bytes(size)
            key = generate_random_bytes(32)
            nonce = generate_random_bytes(12)
            seed = generate_random_bytes(32)
            
            # Benchmark AEAD only
            cipher = create_aead_cipher(use_ascon=False)
            start_time = time.perf_counter()
            
            for _ in range(iterations):
                ciphertext, tag = cipher.encrypt(key, nonce, plaintext)
            
            aead_time = time.perf_counter() - start_time
            
            # Benchmark AEAD + Scrambling
            scrambler = DataScrambler()
            start_time = time.perf_counter()
            
            for _ in range(iterations):
                ciphertext, tag = cipher.encrypt(key, nonce, plaintext)
                scrambled = scrambler.scramble(ciphertext, seed)
            
            full_time = time.perf_counter() - start_time
            
            # Calculate overhead
            scrambling_overhead = full_time - aead_time
            overhead_percent = (scrambling_overhead / aead_time) * 100
            
            result = {
                'message_size': size,
                'aead_time': aead_time,
                'full_time': full_time,
                'scrambling_overhead': scrambling_overhead,
                'overhead_percent': overhead_percent,
                'scrambling_throughput': (size * iterations) / scrambling_overhead / 1024 / 1024
            }
            
            results.append(result)
        
        return results
    
    def stress_test(self, duration_seconds: int = 60, 
                   message_size: int = 1024, use_ascon: bool = False) -> Dict[str, Any]:
        """
        Run stress test for extended duration.
        
        Args:
            duration_seconds: Test duration in seconds
            message_size: Size of test messages
            use_ascon: Whether to use ASCON algorithms
            
        Returns:
            Stress test results
        """
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        encrypt_ctx = create_encryption_context(master_psk, channel_id, use_ascon)
        decrypt_ctx = create_decryption_context(master_psk, channel_id, use_ascon)
        
        plaintext = generate_random_bytes(message_size)
        
        start_time = time.perf_counter()
        end_time = start_time + duration_seconds
        
        operations = 0
        errors = 0
        latencies = []
        memory_samples = []
        
        # Monitor memory usage in background
        def memory_monitor():
            while time.perf_counter() < end_time:
                memory_samples.append(self.measure_memory_usage())
                time.sleep(1.0)
        
        memory_thread = threading.Thread(target=memory_monitor, daemon=True)
        memory_thread.start()
        
        # Run stress test
        while time.perf_counter() < end_time:
            try:
                op_start = time.perf_counter()
                
                # Encrypt
                packet = encrypt_ctx.encrypt_message(plaintext)
                packet_bytes = packet.to_bytes()
                
                # Decrypt
                decrypted = decrypt_ctx.decrypt_packet(packet_bytes)
                
                op_end = time.perf_counter()
                latencies.append(op_end - op_start)
                
                assert decrypted == plaintext
                operations += 1
                
            except Exception:
                errors += 1
        
        actual_duration = time.perf_counter() - start_time
        
        # Calculate statistics
        avg_latency = statistics.mean(latencies) if latencies else 0
        p95_latency = statistics.quantiles(latencies, n=20)[18] if latencies else 0
        p99_latency = statistics.quantiles(latencies, n=100)[98] if latencies else 0
        
        throughput = operations / actual_duration
        data_throughput = (operations * message_size) / actual_duration / 1024 / 1024
        
        # Memory statistics
        if memory_samples:
            peak_memory = max(sample['rss'] for sample in memory_samples)
            avg_memory = statistics.mean(sample['rss'] for sample in memory_samples)
        else:
            peak_memory = avg_memory = 0
        
        return {
            'algorithm': 'ASCON' if use_ascon else 'AES-GCM',
            'duration': actual_duration,
            'message_size': message_size,
            'total_operations': operations,
            'errors': errors,
            'error_rate': errors / (operations + errors) if (operations + errors) > 0 else 0,
            'operations_per_second': throughput,
            'data_throughput_mbps': data_throughput,
            'latency': {
                'avg': avg_latency,
                'p95': p95_latency,
                'p99': p99_latency
            },
            'memory': {
                'peak_mb': peak_memory,
                'avg_mb': avg_memory
            }
        }
    
    def get_summary_report(self) -> Dict[str, Any]:
        """
        Generate summary report of all benchmark results.
        
        Returns:
            Comprehensive summary report
        """
        if not self.results:
            return {'error': 'No benchmark results available'}
        
        # Group results by algorithm
        by_algorithm = {}
        for result in self.results:
            if result.algorithm not in by_algorithm:
                by_algorithm[result.algorithm] = []
            by_algorithm[result.algorithm].append(result)
        
        summary = {
            'total_benchmarks': len(self.results),
            'algorithms_tested': list(by_algorithm.keys()),
            'by_algorithm': {}
        }
        
        for algorithm, results in by_algorithm.items():
            throughputs = [r.throughput_mbps for r in results]
            latencies = [r.avg_time for r in results]
            
            summary['by_algorithm'][algorithm] = {
                'benchmark_count': len(results),
                'avg_throughput_mbps': statistics.mean(throughputs),
                'max_throughput_mbps': max(throughputs),
                'avg_latency_ms': statistics.mean(latencies) * 1000,
                'min_latency_ms': min(latencies) * 1000,
                'message_sizes_tested': sorted(set(r.message_size for r in results))
            }
        
        return summary


def run_comprehensive_benchmark(quick: bool = False) -> Dict[str, Any]:
    """
    Run comprehensive benchmark suite.
    
    Args:
        quick: If True, run reduced test set for faster execution
        
    Returns:
        Complete benchmark results
    """
    benchmark = PerformanceBenchmark()
    
    if quick:
        message_sizes = [64, 512, 1024]
        iterations = 100
        stress_duration = 10
    else:
        message_sizes = [32, 64, 128, 256, 512, 1024, 2048, 4096]
        iterations = 1000
        stress_duration = 60
    
    print("Running comprehensive Ouroboros Protocol benchmark...")
    
    # Algorithm comparison
    print("Comparing AES-GCM vs ASCON...")
    algorithm_results = benchmark.compare_algorithms(message_sizes, iterations)
    
    # Scrambling overhead
    print("Measuring scrambling overhead...")
    scrambling_results = benchmark.benchmark_scrambling_overhead(message_sizes, iterations)
    
    # Stress tests
    print("Running stress tests...")
    stress_results = {
        'AES-GCM': benchmark.stress_test(stress_duration, 1024, use_ascon=False)
    }
    
    try:
        stress_results['ASCON'] = benchmark.stress_test(stress_duration, 1024, use_ascon=True)
    except ImportError:
        print("ASCON not available for stress test")
    
    # Generate summary
    summary = benchmark.get_summary_report()
    
    return {
        'summary': summary,
        'algorithm_comparison': algorithm_results,
        'scrambling_overhead': scrambling_results,
        'stress_tests': stress_results,
        'raw_results': benchmark.results
    }
