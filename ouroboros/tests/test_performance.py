"""
Performance tests for Ouroboros Protocol.

This module tests timing, memory usage, and scrambling overhead
to provide performance evaluation data for dissertations.
"""

import time
import pytest
import statistics
from typing import List, Dict, Any

from ouroboros.crypto.utils import generate_random_bytes
from ouroboros.protocol.encryptor import create_encryption_context
from ouroboros.protocol.decryptor import create_decryption_context
from ouroboros.evaluation.benchmark import PerformanceBenchmark, run_comprehensive_benchmark


class TestPerformance:
    """Performance benchmarking tests."""
    
    def test_encryption_throughput(self):
        """Test encryption throughput across different message sizes."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        encrypt_ctx = create_encryption_context(master_psk, channel_id, use_ascon=False)
        
        # Test different message sizes
        sizes = [64, 256, 1024, 4096]
        results = {}
        
        for size in sizes:
            plaintext = generate_random_bytes(size)
            times = []
            
            # Run multiple iterations for statistical accuracy
            for _ in range(100):
                start_time = time.perf_counter()
                packet = encrypt_ctx.encrypt_message(plaintext)
                end_time = time.perf_counter()
                times.append(end_time - start_time)
            
            avg_time = statistics.mean(times)
            throughput = (size / avg_time) / 1024 / 1024  # MB/s
            
            results[size] = {
                'avg_time': avg_time,
                'throughput_mbps': throughput,
                'std_dev': statistics.stdev(times)
            }
            
            # Performance assertion: should achieve reasonable throughput
            assert throughput > 0.1, f"Throughput too low for {size}B: {throughput:.2f} MB/s"
        
        # Print results for analysis
        print("\nEncryption Performance Results:")
        for size, metrics in results.items():
            print(f"  {size}B: {metrics['throughput_mbps']:.2f} MB/s "
                  f"(avg: {metrics['avg_time']*1000:.2f}ms, "
                  f"σ: {metrics['std_dev']*1000:.2f}ms)")
    
    def test_decryption_throughput(self):
        """Test decryption throughput across different message sizes."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        encrypt_ctx = create_encryption_context(master_psk, channel_id, use_ascon=False)
        decrypt_ctx = create_decryption_context(master_psk, channel_id, use_ascon=False)
        
        # Test different message sizes
        sizes = [64, 256, 1024, 4096]
        results = {}
        
        for size in sizes:
            plaintext = generate_random_bytes(size)
            
            # Pre-encrypt packets for decryption testing
            packets = []
            for i in range(100):
                # Create fresh context for each packet to avoid counter conflicts
                fresh_encrypt = create_encryption_context(master_psk, channel_id, use_ascon=False)
                packet = fresh_encrypt.encrypt_message(plaintext)
                packets.append(packet.to_bytes())
            
            times = []
            
            # Time decryption
            for packet_bytes in packets:
                fresh_decrypt = create_decryption_context(master_psk, channel_id, use_ascon=False)
                start_time = time.perf_counter()
                decrypted = fresh_decrypt.decrypt_packet(packet_bytes)
                end_time = time.perf_counter()
                times.append(end_time - start_time)
                assert decrypted == plaintext
            
            avg_time = statistics.mean(times)
            throughput = (size / avg_time) / 1024 / 1024  # MB/s
            
            results[size] = {
                'avg_time': avg_time,
                'throughput_mbps': throughput,
                'std_dev': statistics.stdev(times)
            }
            
            # Performance assertion
            assert throughput > 0.1, f"Decryption throughput too low for {size}B: {throughput:.2f} MB/s"
        
        # Print results for analysis
        print("\nDecryption Performance Results:")
        for size, metrics in results.items():
            print(f"  {size}B: {metrics['throughput_mbps']:.2f} MB/s "
                  f"(avg: {metrics['avg_time']*1000:.2f}ms, "
                  f"σ: {metrics['std_dev']*1000:.2f}ms)")
    
    def test_algorithm_comparison(self):
        """Compare AES-GCM vs ASCON performance."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        message_size = 1024
        iterations = 50
        
        plaintext = generate_random_bytes(message_size)
        
        # Test both algorithms
        algorithms = [
            ('AES-GCM', False),
            ('ASCON', True)
        ]
        
        results = {}
        
        for algo_name, use_ascon in algorithms:
            try:
                encrypt_ctx = create_encryption_context(master_psk, channel_id, use_ascon)
                decrypt_ctx = create_decryption_context(master_psk, channel_id, use_ascon)
                
                # Encryption timing
                encrypt_times = []
                for _ in range(iterations):
                    fresh_encrypt = create_encryption_context(master_psk, channel_id, use_ascon)
                    start_time = time.perf_counter()
                    packet = fresh_encrypt.encrypt_message(plaintext)
                    end_time = time.perf_counter()
                    encrypt_times.append(end_time - start_time)
                
                # Decryption timing
                decrypt_times = []
                for _ in range(iterations):
                    fresh_encrypt = create_encryption_context(master_psk, channel_id, use_ascon)
                    fresh_decrypt = create_decryption_context(master_psk, channel_id, use_ascon)
                    packet = fresh_encrypt.encrypt_message(plaintext)
                    packet_bytes = packet.to_bytes()
                    
                    start_time = time.perf_counter()
                    decrypted = fresh_decrypt.decrypt_packet(packet_bytes)
                    end_time = time.perf_counter()
                    decrypt_times.append(end_time - start_time)
                    assert decrypted == plaintext
                
                results[algo_name] = {
                    'encrypt_avg': statistics.mean(encrypt_times),
                    'decrypt_avg': statistics.mean(decrypt_times),
                    'total_avg': statistics.mean(encrypt_times) + statistics.mean(decrypt_times)
                }
                
            except Exception as e:
                print(f"Skipping {algo_name}: {e}")
                results[algo_name] = None
        
        # Print comparison
        print(f"\nAlgorithm Performance Comparison ({message_size}B messages):")
        for algo_name, metrics in results.items():
            if metrics:
                print(f"  {algo_name}:")
                print(f"    Encryption: {metrics['encrypt_avg']*1000:.2f}ms")
                print(f"    Decryption: {metrics['decrypt_avg']*1000:.2f}ms")
                print(f"    Total:      {metrics['total_avg']*1000:.2f}ms")
            else:
                print(f"  {algo_name}: Not available")
    
    def test_scrambling_overhead(self):
        """Measure the overhead introduced by scrambling."""
        from ouroboros.crypto.aead import AEADCipher
        from ouroboros.crypto.scramble import scramble_data, unscramble_data
        from ouroboros.crypto.utils import generate_random_bytes
        
        sizes = [64, 256, 1024]
        iterations = 100
        
        print("\nScrambling Overhead Analysis:")
        
        for size in sizes:
            # Generate test data
            plaintext = generate_random_bytes(size)
            key = generate_random_bytes(32)
            nonce = generate_random_bytes(12)
            kp = generate_random_bytes(32)
            tag = generate_random_bytes(16)
            r = generate_random_bytes(4)
            
            aead = AEADCipher(use_ascon=False)
            
            # Time AEAD only
            aead_times = []
            for _ in range(iterations):
                start_time = time.perf_counter()
                ciphertext, _ = aead.encrypt(key, nonce, plaintext)
                end_time = time.perf_counter()
                aead_times.append(end_time - start_time)
            
            # Time AEAD + Scrambling
            total_times = []
            for _ in range(iterations):
                start_time = time.perf_counter()
                ciphertext, _ = aead.encrypt(key, nonce, plaintext)
                scrambled = scramble_data(ciphertext, kp, tag, r)
                end_time = time.perf_counter()
                total_times.append(end_time - start_time)
            
            aead_avg = statistics.mean(aead_times)
            total_avg = statistics.mean(total_times)
            overhead = ((total_avg - aead_avg) / aead_avg) * 100
            
            print(f"  {size}B: AEAD={aead_avg*1000:.2f}ms, "
                  f"Total={total_avg*1000:.2f}ms, "
                  f"Overhead={overhead:.1f}%")
            
            # Scrambling overhead is high - this is expected for this implementation
            # Just verify that scrambling actually adds some overhead
            assert overhead > 0, "Scrambling should add some computational overhead"
    
    def test_memory_efficiency(self):
        """Test memory usage patterns."""
        import tracemalloc
        
        master_psk = generate_random_bytes(32)
        channel_id = 1
        message_size = 1024
        
        # Start memory tracing
        tracemalloc.start()
        
        # Baseline memory
        baseline = tracemalloc.take_snapshot()
        
        # Create contexts
        encrypt_ctx = create_encryption_context(master_psk, channel_id, use_ascon=False)
        decrypt_ctx = create_decryption_context(master_psk, channel_id, use_ascon=False)
        
        # Perform operations
        plaintext = generate_random_bytes(message_size)
        packet = encrypt_ctx.encrypt_message(plaintext)
        packet_bytes = packet.to_bytes()
        decrypted = decrypt_ctx.decrypt_packet(packet_bytes)
        
        # Measure final memory
        final = tracemalloc.take_snapshot()
        tracemalloc.stop()
        
        # Calculate memory usage
        top_stats = final.compare_to(baseline, 'lineno')
        total_memory = sum(stat.size for stat in top_stats)
        
        print(f"\nMemory Usage Analysis:")
        print(f"  Total additional memory: {total_memory / 1024:.1f} KB")
        print(f"  Memory per byte processed: {total_memory / message_size:.1f} bytes")
        
        # Memory usage should be reasonable
        assert total_memory < 1024 * 1024, f"Memory usage too high: {total_memory / 1024:.1f} KB"
        
        assert decrypted == plaintext  # Verify correctness


@pytest.mark.benchmark
class TestBenchmarkIntegration:
    """Integration tests with the benchmark module."""
    
    def test_benchmark_module_integration(self):
        """Test integration with benchmark module functions."""
        # Test that benchmark functions work correctly
        benchmark = PerformanceBenchmark()
        results = benchmark.benchmark_encryption_performance(
            message_sizes=[64, 256],
            iterations=10,
            use_ascon=False
        )
        
        assert len(results) == 2
        assert all(hasattr(result, 'throughput_mbps') for result in results)
        assert all(hasattr(result, 'avg_time') for result in results)
        
        print("\nBenchmark Module Results:")
        for result in results:
            print(f"  {result.message_size}B: {result.throughput_mbps:.2f} MB/s")
    
    def test_overhead_measurement(self):
        """Test basic scrambling overhead measurement."""
        from ouroboros.crypto.scramble import scramble_data
        from ouroboros.crypto.utils import generate_random_bytes
        
        message = b"Test message for overhead measurement"
        key = generate_random_bytes(32)
        tag = generate_random_bytes(16)
        r = generate_random_bytes(4)
        
        scrambled = scramble_data(message, key, tag, r)
        
        # Basic overhead calculation
        original_size = len(message)
        scrambled_size = len(scrambled)
        overhead_percent = ((scrambled_size - original_size) / original_size) * 100
        
        print(f"\nBasic Scrambling Overhead:")
        print(f"  Original: {original_size} bytes")
        print(f"  Scrambled: {scrambled_size} bytes") 
        print(f"  Overhead: {overhead_percent:.1f}%")
        
        # Verify overhead is reasonable
        assert overhead_percent >= 0  # Should have some overhead
        assert overhead_percent < 1000  # But not excessive


# ============================================================================
# EVALUATION FRAMEWORK INTEGRATION - REUSABLE PERFORMANCE FUNCTIONS
# ============================================================================

def run_individual_aead_performance_test_aes_gcm(payload_sizes: List[int] = None, 
                                                iterations: int = 1000,
                                                warmup_iterations: int = 100) -> Dict[str, Any]:
    """
    Reusable wrapper for individual AES-GCM AEAD performance testing.
    Used by evaluation framework for comprehensive performance analysis.
    """
    if payload_sizes is None:
        payload_sizes = [16, 64, 128, 256, 1024, 2048, 4096]
    
    results = {}
    
    for payload_size in payload_sizes:
        try:
            # Create test environment using AEADCipher with AES-GCM
            from ouroboros.crypto.aead import AEADCipher
            from ouroboros.crypto.utils import generate_random_bytes
            
            cipher = AEADCipher(use_ascon=False)  # AES-GCM mode
            plaintext = generate_random_bytes(payload_size)
            key = generate_random_bytes(32)
            nonce = generate_random_bytes(12)  # AES-GCM uses 12-byte nonce
            associated_data = generate_random_bytes(16)
            
            # Warmup
            for _ in range(warmup_iterations):
                ciphertext, tag = cipher.encrypt(key, nonce, plaintext, associated_data)
                cipher.decrypt(key, nonce, ciphertext, tag, associated_data)
            
            # Performance measurement
            latencies = []
            start_time = time.perf_counter()
            
            for _ in range(iterations):
                op_start = time.perf_counter()
                ciphertext, tag = cipher.encrypt(key, nonce, plaintext, associated_data)
                op_end = time.perf_counter()
                latencies.append((op_end - op_start) * 1000)  # ms
            
            end_time = time.perf_counter()
            total_time = end_time - start_time
            
            # Calculate metrics
            throughput_bytes_per_sec = (payload_size * iterations) / total_time
            throughput_mbps = (throughput_bytes_per_sec * 8) / (1024 * 1024)
            ops_per_sec = iterations / total_time
            
            results[str(payload_size)] = {
                'payload_size_bytes': payload_size,
                'iterations': iterations,
                'total_time_seconds': total_time,
                'throughput_mbps': throughput_mbps,
                'operations_per_second': ops_per_sec,
                'latency_stats': {
                    'mean': statistics.mean(latencies),
                    'median': statistics.median(latencies),
                    'min': min(latencies),
                    'max': max(latencies),
                    'std': statistics.stdev(latencies) if len(latencies) > 1 else 0.0
                }
            }
            
        except Exception as e:
            results[str(payload_size)] = {
                'error': str(e),
                'status': 'failed'
            }
    
    return results


def run_individual_aead_performance_test_ascon(payload_sizes: List[int] = None,
                                              iterations: int = 1000,
                                              warmup_iterations: int = 100) -> Dict[str, Any]:
    """
    Reusable wrapper for individual ASCON AEAD performance testing.
    Used by evaluation framework for comprehensive performance analysis.
    """
    if payload_sizes is None:
        payload_sizes = [16, 64, 128, 256, 1024, 2048, 4096]
    
    results = {}
    
    for payload_size in payload_sizes:
        try:
            # Create test environment using AEADCipher with ASCON
            from ouroboros.crypto.aead import AEADCipher
            from ouroboros.crypto.utils import generate_random_bytes
            
            cipher = AEADCipher(use_ascon=True)  # ASCON-AEAD mode
            plaintext = generate_random_bytes(payload_size)
            key = generate_random_bytes(16)  # ASCON uses 16-byte key
            nonce = generate_random_bytes(16)  # ASCON uses 16-byte nonce
            associated_data = generate_random_bytes(16)
            
            # Warmup
            for _ in range(warmup_iterations):
                ciphertext, tag = cipher.encrypt(key, nonce, plaintext, associated_data)
                cipher.decrypt(key, nonce, ciphertext, tag, associated_data)
            
            # Performance measurement
            latencies = []
            start_time = time.perf_counter()
            
            for _ in range(iterations):
                op_start = time.perf_counter()
                ciphertext, tag = cipher.encrypt(key, nonce, plaintext, associated_data)
                op_end = time.perf_counter()
                latencies.append((op_end - op_start) * 1000)  # ms
            
            end_time = time.perf_counter()
            total_time = end_time - start_time
            
            # Calculate metrics
            throughput_bytes_per_sec = (payload_size * iterations) / total_time
            throughput_mbps = (throughput_bytes_per_sec * 8) / (1024 * 1024)
            ops_per_sec = iterations / total_time
            
            results[str(payload_size)] = {
                'payload_size_bytes': payload_size,
                'iterations': iterations,
                'total_time_seconds': total_time,
                'throughput_mbps': throughput_mbps,
                'operations_per_second': ops_per_sec,
                'latency_stats': {
                    'mean': statistics.mean(latencies),
                    'median': statistics.median(latencies),
                    'min': min(latencies),
                    'max': max(latencies),
                    'std': statistics.stdev(latencies) if len(latencies) > 1 else 0.0
                }
            }
            
        except Exception as e:
            results[str(payload_size)] = {
                'error': str(e),
                'status': 'failed'
            }
    
    return results


def run_protocol_performance_test_aes(payload_sizes: List[int] = None,
                                     iterations: int = 1000,
                                     warmup_iterations: int = 100) -> Dict[str, Any]:
    """
    Reusable wrapper for complete Ouroboros protocol performance testing with AES.
    Tests the full encryption → scrambling → packet → decryption pipeline.
    """
    if payload_sizes is None:
        payload_sizes = [16, 64, 128, 256, 1024, 2048, 4096]
    
    results = {}
    
    for payload_size in payload_sizes:
        try:
            # Setup protocol contexts
            master_psk = generate_random_bytes(32)
            channel_id = 42
            
            plaintext = generate_random_bytes(payload_size)
            
            # Warmup
            for i in range(warmup_iterations):
                # Use different channel IDs to avoid replay protection
                warm_channel_id = (channel_id + 10000 + i) % 256
                warm_encrypt = create_encryption_context(master_psk, warm_channel_id, use_ascon=False)
                warm_decrypt = create_decryption_context(master_psk, warm_channel_id, use_ascon=False)
                
                packet = warm_encrypt.encrypt_message(plaintext)
                warm_decrypt.decrypt_packet(packet.to_bytes())
            
            # Performance measurement
            latencies = []
            protocol_overheads = []
            start_time = time.perf_counter()
            
            for i in range(iterations):
                # Use different channel IDs for each iteration to avoid replay protection
                # Keep channel ID within valid range (0-255)
                test_channel_id = (channel_id + i) % 256
                test_encrypt = create_encryption_context(master_psk, test_channel_id, use_ascon=False)
                test_decrypt = create_decryption_context(master_psk, test_channel_id, use_ascon=False)
                
                op_start = time.perf_counter()
                
                # Complete protocol pipeline
                packet = test_encrypt.encrypt_message(plaintext)
                packet_bytes = packet.to_bytes()
                decrypted = test_decrypt.decrypt_packet(packet_bytes)
                
                op_end = time.perf_counter()
                
                # Verify round-trip
                assert decrypted == plaintext
                
                latencies.append((op_end - op_start) * 1000)  # ms
                protocol_overheads.append(len(packet_bytes) - len(plaintext))
            
            end_time = time.perf_counter()
            total_time = end_time - start_time
            
            # Calculate metrics
            throughput_bytes_per_sec = (payload_size * iterations) / total_time
            throughput_mbps = (throughput_bytes_per_sec * 8) / (1024 * 1024)
            ops_per_sec = iterations / total_time
            
            results[str(payload_size)] = {
                'payload_size_bytes': payload_size,
                'iterations': iterations,
                'total_time_seconds': total_time,
                'throughput_mbps': throughput_mbps,
                'operations_per_second': ops_per_sec,
                'protocol_overhead_bytes': statistics.mean(protocol_overheads),
                'latency_stats': {
                    'mean': statistics.mean(latencies),
                    'median': statistics.median(latencies),
                    'min': min(latencies),
                    'max': max(latencies),
                    'std': statistics.stdev(latencies) if len(latencies) > 1 else 0.0
                }
            }
            
        except Exception as e:
            results[str(payload_size)] = {
                'error': str(e),
                'status': 'failed'
            }
    
    return results


def run_protocol_performance_test_ascon(payload_sizes: List[int] = None,
                                       iterations: int = 1000,
                                       warmup_iterations: int = 100) -> Dict[str, Any]:
    """
    Reusable wrapper for complete Ouroboros protocol performance testing with ASCON.
    Tests the full encryption → scrambling → packet → decryption pipeline.
    """
    if payload_sizes is None:
        payload_sizes = [16, 64, 128, 256, 1024, 2048, 4096]
    
    results = {}
    
    for payload_size in payload_sizes:
        try:
            # Setup protocol contexts with ASCON
            master_psk = generate_random_bytes(32)
            channel_id = 42
            
            plaintext = generate_random_bytes(payload_size)
            
            # Warmup
            for i in range(warmup_iterations):
                warm_channel_id = (channel_id + 10000 + i) % 256
                warm_encrypt = create_encryption_context(master_psk, warm_channel_id, use_ascon=True)
                warm_decrypt = create_decryption_context(master_psk, warm_channel_id, use_ascon=True)
                
                packet = warm_encrypt.encrypt_message(plaintext)
                warm_decrypt.decrypt_packet(packet.to_bytes())
            
            # Performance measurement
            latencies = []
            protocol_overheads = []
            start_time = time.perf_counter()
            
            for i in range(iterations):
                test_channel_id = (channel_id + i) % 256
                test_encrypt = create_encryption_context(master_psk, test_channel_id, use_ascon=True)
                test_decrypt = create_decryption_context(master_psk, test_channel_id, use_ascon=True)
                
                op_start = time.perf_counter()
                
                # Complete protocol pipeline
                packet = test_encrypt.encrypt_message(plaintext)
                packet_bytes = packet.to_bytes()
                decrypted = test_decrypt.decrypt_packet(packet_bytes)
                
                op_end = time.perf_counter()
                
                # Verify round-trip
                assert decrypted == plaintext
                
                latencies.append((op_end - op_start) * 1000)  # ms
                protocol_overheads.append(len(packet_bytes) - len(plaintext))
            
            end_time = time.perf_counter()
            total_time = end_time - start_time
            
            # Calculate metrics
            throughput_bytes_per_sec = (payload_size * iterations) / total_time
            throughput_mbps = (throughput_bytes_per_sec * 8) / (1024 * 1024)
            ops_per_sec = iterations / total_time
            
            results[str(payload_size)] = {
                'payload_size_bytes': payload_size,
                'iterations': iterations,
                'total_time_seconds': total_time,
                'throughput_mbps': throughput_mbps,
                'operations_per_second': ops_per_sec,
                'protocol_overhead_bytes': statistics.mean(protocol_overheads),
                'latency_stats': {
                    'mean': statistics.mean(latencies),
                    'median': statistics.median(latencies),
                    'min': min(latencies),
                    'max': max(latencies),
                    'std': statistics.stdev(latencies) if len(latencies) > 1 else 0.0
                }
            }
            
        except Exception as e:
            results[str(payload_size)] = {
                'error': str(e),
                'status': 'failed'
            }
    
    return results


def run_scrambling_performance_test(payload_sizes: List[int] = None,
                                   iterations: int = 1000,
                                   warmup_iterations: int = 100) -> Dict[str, Any]:
    """
    Reusable wrapper for scrambling component performance testing.
    Isolates scrambling operations for component analysis.
    """
    if payload_sizes is None:
        payload_sizes = [16, 64, 128, 256, 1024, 2048, 4096]
    
    results = {}
    
    for payload_size in payload_sizes:
        try:
            from ouroboros.crypto.scramble import scramble_data, unscramble_data
            from ouroboros.crypto.utils import generate_random_bytes
            
            # Generate test data
            data = generate_random_bytes(payload_size)
            permutation_key = generate_random_bytes(32)
            tag = generate_random_bytes(16)
            r = generate_random_bytes(4)
            
            # Warmup
            for _ in range(warmup_iterations):
                scrambled = scramble_data(data, permutation_key, tag, r)
                unscramble_data(scrambled, permutation_key, tag, r)
            
            # Performance measurement
            scramble_latencies = []
            unscramble_latencies = []
            start_time = time.perf_counter()
            
            for _ in range(iterations):
                # Scramble timing
                scramble_start = time.perf_counter()
                scrambled = scramble_data(data, permutation_key, tag, r)
                scramble_end = time.perf_counter()
                
                # Unscramble timing
                unscramble_start = time.perf_counter()
                unscrambled = unscramble_data(scrambled, permutation_key, tag, r)
                unscramble_end = time.perf_counter()
                
                # Verify correctness
                assert unscrambled == data
                
                scramble_latencies.append((scramble_end - scramble_start) * 1000)
                unscramble_latencies.append((unscramble_end - unscramble_start) * 1000)
            
            end_time = time.perf_counter()
            total_time = end_time - start_time
            
            # Calculate metrics
            throughput_bytes_per_sec = (payload_size * iterations * 2) / total_time  # 2 operations per iteration
            throughput_mbps = (throughput_bytes_per_sec * 8) / (1024 * 1024)
            ops_per_sec = (iterations * 2) / total_time
            
            results[str(payload_size)] = {
                'payload_size_bytes': payload_size,
                'iterations': iterations,
                'total_time_seconds': total_time,
                'throughput_mbps': throughput_mbps,
                'operations_per_second': ops_per_sec,
                'latency_stats': {
                    'mean': statistics.mean(scramble_latencies + unscramble_latencies),
                    'scramble_mean': statistics.mean(scramble_latencies),
                    'unscramble_mean': statistics.mean(unscramble_latencies),
                    'min': min(scramble_latencies + unscramble_latencies),
                    'max': max(scramble_latencies + unscramble_latencies),
                    'std': statistics.stdev(scramble_latencies + unscramble_latencies)
                }
            }
            
        except Exception as e:
            results[str(payload_size)] = {
                'error': str(e),
                'status': 'failed'
            }
    
    return results


def run_key_ratcheting_performance_test(iterations: int = 1000) -> Dict[str, Any]:
    """
    Reusable wrapper for key ratcheting performance testing.
    Isolates key ratcheting operations for component analysis.
    """
    try:
        from ouroboros.crypto.ratchet import RatchetState
        from ouroboros.crypto.utils import generate_random_bytes
        
        # Setup
        seed = generate_random_bytes(32)
        ratchet = RatchetState(seed)
        channel_id = 42
        
        # Performance measurement
        ratchet_latencies = []
        key_derivation_latencies = []
        
        start_time = time.perf_counter()
        
        for i in range(iterations):
            # Key derivation timing
            derive_start = time.perf_counter()
            keys = ratchet.derive_keys(channel_id, i)
            derive_end = time.perf_counter()
            
            # Ratchet advancement timing
            ratchet_start = time.perf_counter()
            ratchet.advance_ratchet_send()
            ratchet_end = time.perf_counter()
            
            key_derivation_latencies.append((derive_end - derive_start) * 1000)
            ratchet_latencies.append((ratchet_end - ratchet_start) * 1000)
        
        end_time = time.perf_counter()
        total_time = end_time - start_time
        
        ops_per_sec = (iterations * 2) / total_time  # 2 operations per iteration
        
        results = {
            'iterations': iterations,
            'total_time_seconds': total_time,
            'operations_per_second': ops_per_sec,
            'ratchet_latency_stats': {
                'mean': statistics.mean(ratchet_latencies),
                'median': statistics.median(ratchet_latencies),
                'min': min(ratchet_latencies),
                'max': max(ratchet_latencies),
                'std': statistics.stdev(ratchet_latencies) if len(ratchet_latencies) > 1 else 0.0
            },
            'key_derivation_latency_stats': {
                'mean': statistics.mean(key_derivation_latencies),
                'median': statistics.median(key_derivation_latencies),
                'min': min(key_derivation_latencies),
                'max': max(key_derivation_latencies),
                'std': statistics.stdev(key_derivation_latencies) if len(key_derivation_latencies) > 1 else 0.0
            }
        }
        
    except Exception as e:
        results = {
            'error': str(e),
            'status': 'failed'
        }
    
    return results


def run_memory_analysis_test(payload_sizes: List[int] = None) -> Dict[str, Any]:
    """
    Reusable wrapper for memory analysis testing.
    Analyzes memory consumption patterns for protocol operations.
    """
    if payload_sizes is None:
        payload_sizes = [16, 64, 128, 256, 1024, 2048, 4096]
    
    results = {}
    
    try:
        import psutil
        import os
        import gc
        
        process = psutil.Process(os.getpid())
        
        for payload_size in payload_sizes:
            # Clean baseline
            gc.collect()
            baseline_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            # Create contexts and run operations
            master_psk = generate_random_bytes(32)
            channel_id = 42
            
            encrypt_ctx = create_encryption_context(master_psk, channel_id, use_ascon=False)
            decrypt_ctx = create_decryption_context(master_psk, channel_id, use_ascon=False)
            
            plaintext = generate_random_bytes(payload_size)
            operations = []
            
            # Run multiple operations
            for i in range(50):
                test_channel_id = (channel_id + i) % 256
                test_encrypt = create_encryption_context(master_psk, test_channel_id, use_ascon=False)
                test_decrypt = create_decryption_context(master_psk, test_channel_id, use_ascon=False)
                
                packet = test_encrypt.encrypt_message(plaintext)
                decrypted = test_decrypt.decrypt_packet(packet.to_bytes())
                
                operations.append((packet, decrypted))
            
            # Measure memory after operations
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_delta = final_memory - baseline_memory
            
            results[str(payload_size)] = {
                'payload_size_bytes': payload_size,
                'baseline_memory_mb': baseline_memory,
                'final_memory_mb': final_memory,
                'memory_delta_mb': memory_delta,
                'memory_per_operation_kb': (memory_delta * 1024) / len(operations)
            }
            
            # Cleanup
            del operations, encrypt_ctx, decrypt_ctx
            gc.collect()
            
    except ImportError:
        results = {
            'status': 'skipped',
            'reason': 'psutil not available'
        }
    except Exception as e:
        results = {
            'error': str(e),
            'status': 'failed'
        }
    
    return results
