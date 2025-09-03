"""
Performance Tests for Ouroboros Protocol.

Tests timing, memory usage, and scrambling overhead.
"""

import pytest
import time
import psutil
import os
from typing import List, Tuple
from ouroboros.crypto.ratchet import HashRatchet, generate_root_key
from ouroboros.crypto.aead import AEADCipher
from ouroboros.crypto.scramble import scramble_data, unscramble_data
from ouroboros.protocol.encryptor import OuroborosEncryptor
from ouroboros.protocol.decryptor import OuroborosDecryptor
from ouroboros.protocol.window import SlidingWindow


class PerformanceTimer:
    """Context manager for timing operations."""
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.duration = None
    
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.perf_counter()
        self.duration = self.end_time - self.start_time


class MemoryProfiler:
    """Memory usage profiler."""
    
    def __init__(self):
        self.process = psutil.Process()
        self.initial_memory = None
        self.peak_memory = None
    
    def start(self):
        """Start memory profiling."""
        self.initial_memory = self.process.memory_info().rss
        self.peak_memory = self.initial_memory
    
    def update_peak(self):
        """Update peak memory usage."""
        current_memory = self.process.memory_info().rss
        if current_memory > self.peak_memory:
            self.peak_memory = current_memory
    
    def get_usage(self) -> int:
        """Get memory usage increase in bytes."""
        if self.initial_memory is None:
            return 0
        return self.peak_memory - self.initial_memory


class TestEncryptionPerformance:
    """Test encryption and decryption performance."""
    
    @pytest.mark.parametrize("message_size", [
        1, 16, 64, 256, 1024, 4096, 16384, 65536  # 1B to 64KB
    ])
    def test_encryption_speed(self, message_size: int):
        """Test encryption speed for various message sizes."""
        root_key = generate_root_key()
        plaintext = os.urandom(message_size)
        encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
        
        # Warm up
        for _ in range(10):
            encryptor.encrypt_message(plaintext)
        
        # Reset counter for clean measurement
        encryptor.reset_counter(0)
        
        # Time multiple encryptions
        num_iterations = max(1, 1000 // (message_size // 64 + 1))  # Adjust iterations based on size
        
        with PerformanceTimer() as timer:
            for _ in range(num_iterations):
                packet = encryptor.encrypt_message(plaintext)
        
        avg_time = timer.duration / num_iterations
        throughput = message_size / avg_time if avg_time > 0 else 0
        
        print(f"Encryption - Size: {message_size:6} bytes, "
              f"Time: {avg_time*1000:8.3f} ms, "
              f"Throughput: {throughput/1024/1024:8.2f} MB/s")
        
        # Performance assertions (these are rough guidelines)
        if message_size <= 1024:
            assert avg_time < 0.01, f"Encryption too slow for {message_size} bytes: {avg_time:.4f}s"
        else:
            assert avg_time < 0.1, f"Encryption too slow for {message_size} bytes: {avg_time:.4f}s"
    
    @pytest.mark.parametrize("message_size", [
        1, 16, 64, 256, 1024, 4096, 16384, 65536
    ])
    def test_decryption_speed(self, message_size: int):
        """Test decryption speed for various message sizes."""
        root_key = generate_root_key()
        plaintext = os.urandom(message_size)
        
        encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
        decryptor = OuroborosDecryptor(root_key, use_ratcheting=False)
        
        # Pre-encrypt messages
        packets = []
        for _ in range(100):
            packet = encryptor.encrypt_message(plaintext)
            packets.append(packet)
        
        # Warm up
        for packet in packets[:10]:
            decryptor.decrypt_packet(packet)
        
        # Reset decryptor
        decryptor = OuroborosDecryptor(root_key, use_ratcheting=False)
        
        # Time decryption
        num_iterations = len(packets)
        
        with PerformanceTimer() as timer:
            for packet in packets:
                decrypted = decryptor.decrypt_packet(packet)
        
        avg_time = timer.duration / num_iterations
        throughput = message_size / avg_time if avg_time > 0 else 0
        
        print(f"Decryption - Size: {message_size:6} bytes, "
              f"Time: {avg_time*1000:8.3f} ms, "
              f"Throughput: {throughput/1024/1024:8.2f} MB/s")
        
        # Performance assertions
        if message_size <= 1024:
            assert avg_time < 0.01, f"Decryption too slow for {message_size} bytes: {avg_time:.4f}s"
        else:
            assert avg_time < 0.1, f"Decryption too slow for {message_size} bytes: {avg_time:.4f}s"


class TestKeyDerivationPerformance:
    """Test key derivation performance."""
    
    def test_ratchet_performance(self):
        """Test hash ratchet performance."""
        root_key = generate_root_key()
        ratchet = HashRatchet(root_key)
        
        num_iterations = 1000
        
        with PerformanceTimer() as timer:
            for i in range(num_iterations):
                enc_key, scr_key = ratchet.derive_keys(i)
        
        avg_time = timer.duration / num_iterations
        
        print(f"Hash ratchet - {num_iterations} derivations in {timer.duration:.3f}s "
              f"({avg_time*1000:.3f} ms per derivation)")
        
        assert avg_time < 0.001, f"Ratchet too slow: {avg_time:.6f}s per derivation"
    
    def test_hkdf_performance(self):
        """Test HKDF performance."""
        from ouroboros.crypto.ratchet import derive_keys_hkdf
        
        root_key = generate_root_key()
        num_iterations = 1000
        
        with PerformanceTimer() as timer:
            for i in range(num_iterations):
                enc_key, scr_key = derive_keys_hkdf(root_key, i)
        
        avg_time = timer.duration / num_iterations
        
        print(f"HKDF - {num_iterations} derivations in {timer.duration:.3f}s "
              f"({avg_time*1000:.3f} ms per derivation)")
        
        assert avg_time < 0.001, f"HKDF too slow: {avg_time:.6f}s per derivation"


class TestScramblingPerformance:
    """Test scrambling performance and overhead."""
    
    @pytest.mark.parametrize("data_size", [
        16, 64, 256, 1024, 4096, 16384
    ])
    def test_scrambling_speed(self, data_size: int):
        """Test scrambling speed for various data sizes."""
        key = generate_root_key()
        data = os.urandom(data_size)
        
        num_iterations = max(1, 1000 // (data_size // 64 + 1))
        
        # Test scrambling
        with PerformanceTimer() as scramble_timer:
            for _ in range(num_iterations):
                scrambled = scramble_data(key, data)
        
        # Test unscrambling
        with PerformanceTimer() as unscramble_timer:
            for _ in range(num_iterations):
                unscrambled = unscramble_data(key, scrambled)
        
        scramble_avg = scramble_timer.duration / num_iterations
        unscramble_avg = unscramble_timer.duration / num_iterations
        
        scramble_throughput = data_size / scramble_avg if scramble_avg > 0 else 0
        unscramble_throughput = data_size / unscramble_avg if unscramble_avg > 0 else 0
        
        print(f"Scrambling - Size: {data_size:5} bytes, "
              f"Scramble: {scramble_avg*1000:6.3f} ms ({scramble_throughput/1024/1024:6.2f} MB/s), "
              f"Unscramble: {unscramble_avg*1000:6.3f} ms ({unscramble_throughput/1024/1024:6.2f} MB/s)")
        
        # Scrambling should be reasonably fast
        assert scramble_avg < 0.01, f"Scrambling too slow for {data_size} bytes: {scramble_avg:.6f}s"
        assert unscramble_avg < 0.01, f"Unscrambling too slow for {data_size} bytes: {unscramble_avg:.6f}s"
    
    def test_scrambling_overhead(self):
        """Test scrambling overhead compared to no scrambling."""
        key = generate_root_key()
        plaintext = b"Test message for overhead measurement" * 100  # ~3.7KB
        
        # Test with scrambling
        encryptor_with_scrambling = OuroborosEncryptor(key, use_ratcheting=False)
        decryptor_with_scrambling = OuroborosDecryptor(key, use_ratcheting=False)
        
        num_iterations = 100
        
        with PerformanceTimer() as timer_with:
            for _ in range(num_iterations):
                packet = encryptor_with_scrambling.encrypt_message(plaintext)
                decrypted = decryptor_with_scrambling.decrypt_packet(packet)
        
        time_with_scrambling = timer_with.duration
        
        # For comparison, measure just AEAD encryption/decryption
        from ouroboros.crypto.aead import encrypt_aes_gcm, decrypt_aes_gcm
        from ouroboros.crypto.ratchet import derive_keys_hkdf
        
        with PerformanceTimer() as timer_without:
            for i in range(num_iterations):
                enc_key, _ = derive_keys_hkdf(key, i)
                nonce, ciphertext_with_tag = encrypt_aes_gcm(enc_key, plaintext)
                decrypted = decrypt_aes_gcm(enc_key, nonce, ciphertext_with_tag)
        
        time_without_scrambling = timer_without.duration
        
        overhead_percent = ((time_with_scrambling - time_without_scrambling) / time_without_scrambling) * 100
        
        print(f"Scrambling overhead: {overhead_percent:.1f}% "
              f"(with: {time_with_scrambling:.3f}s, without: {time_without_scrambling:.3f}s)")
        
        # Scrambling overhead should be reasonable (less than 50%)
        assert overhead_percent < 50, f"Scrambling overhead too high: {overhead_percent:.1f}%"


class TestMemoryUsage:
    """Test memory usage of protocol operations."""
    
    def test_encryption_memory_usage(self):
        """Test memory usage during encryption."""
        root_key = generate_root_key()
        plaintext = os.urandom(64 * 1024)  # 64KB message
        encryptor = OuroborosEncryptor(root_key)
        
        profiler = MemoryProfiler()
        profiler.start()
        
        # Encrypt multiple messages
        for _ in range(100):
            packet = encryptor.encrypt_message(plaintext)
            profiler.update_peak()
        
        memory_usage = profiler.get_usage()
        memory_per_message = memory_usage / 100
        
        print(f"Encryption memory usage: {memory_usage / 1024:.1f} KB total, "
              f"{memory_per_message / 1024:.1f} KB per message")
        
        # Memory usage should be reasonable
        assert memory_per_message < 1024 * 1024, f"Too much memory per message: {memory_per_message} bytes"
    
    def test_sliding_window_memory(self):
        """Test sliding window memory usage."""
        window_size = 10000
        window = SlidingWindow(window_size)
        
        profiler = MemoryProfiler()
        profiler.start()
        
        # Fill the window
        for i in range(window_size):
            window.accept_counter(i)
            if i % 1000 == 0:
                profiler.update_peak()
        
        memory_usage = profiler.get_usage()
        memory_per_entry = memory_usage / window_size if window_size > 0 else 0
        
        print(f"Sliding window memory: {memory_usage / 1024:.1f} KB for {window_size} entries, "
              f"{memory_per_entry:.1f} bytes per entry")
        
        # Memory should scale reasonably with window size
        assert memory_per_entry < 100, f"Too much memory per window entry: {memory_per_entry} bytes"


class TestWindowPerformance:
    """Test sliding window performance."""
    
    def test_window_operations_speed(self):
        """Test sliding window operation speed."""
        window = SlidingWindow(window_size=1000)
        num_operations = 10000
        
        # Test counter acceptance
        with PerformanceTimer() as timer:
            for i in range(num_operations):
                window.accept_counter(i)
        
        avg_time = timer.duration / num_operations
        
        print(f"Window operations: {num_operations} accept operations in {timer.duration:.3f}s "
              f"({avg_time*1000000:.1f} μs per operation)")
        
        assert avg_time < 0.0001, f"Window operations too slow: {avg_time:.6f}s per operation"
    
    def test_large_window_performance(self):
        """Test performance with large window size."""
        large_window_size = 100000
        window = SlidingWindow(window_size=large_window_size)
        
        # Fill window with random counters
        import random
        counters = random.sample(range(large_window_size * 2), large_window_size)
        
        with PerformanceTimer() as timer:
            for counter in counters:
                window.accept_counter(counter)
        
        avg_time = timer.duration / len(counters)
        
        print(f"Large window: {len(counters)} operations in {timer.duration:.3f}s "
              f"({avg_time*1000000:.1f} μs per operation)")
        
        assert avg_time < 0.001, f"Large window too slow: {avg_time:.6f}s per operation"


class TestThroughputBenchmark:
    """Comprehensive throughput benchmarks."""
    
    def test_end_to_end_throughput(self):
        """Test end-to-end throughput for various message sizes."""
        root_key = generate_root_key()
        
        message_sizes = [64, 256, 1024, 4096, 16384]
        results = []
        
        for size in message_sizes:
            plaintext = os.urandom(size)
            encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
            decryptor = OuroborosDecryptor(root_key, use_ratcheting=False)
            
            num_messages = max(10, 10000 // size)  # Adjust based on size
            
            # Measure end-to-end throughput
            with PerformanceTimer() as timer:
                for _ in range(num_messages):
                    packet = encryptor.encrypt_message(plaintext)
                    decrypted = decryptor.decrypt_packet(packet)
                    assert len(decrypted) == size
            
            throughput_mbps = (size * num_messages) / timer.duration / 1024 / 1024
            results.append((size, throughput_mbps))
            
            print(f"End-to-end throughput - Size: {size:5} bytes, "
                  f"Throughput: {throughput_mbps:8.2f} MB/s")
        
        # Ensure reasonable throughput
        for size, throughput in results:
            if size >= 1024:
                assert throughput > 1.0, f"Throughput too low for {size} bytes: {throughput:.2f} MB/s"


def print_performance_summary():
    """Print a summary of performance characteristics."""
    print("\n" + "="*80)
    print("PERFORMANCE SUMMARY")
    print("="*80)
    print("Key Findings:")
    print("- Encryption/decryption should handle 1MB/s+ for messages >1KB")
    print("- Key derivation should be <1ms per operation")
    print("- Scrambling overhead should be <50%")
    print("- Memory usage should scale linearly with window size")
    print("- Window operations should be <100μs per operation")
    print("="*80)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
    print_performance_summary()