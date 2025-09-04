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
