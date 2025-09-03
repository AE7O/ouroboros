"""
Performance Benchmarking for Ouroboros Protocol.

Collects timing and memory data for comprehensive evaluation.
"""

import time
import psutil
import statistics
import os
from typing import List, Dict, Tuple, Optional
from ..crypto.ratchet import generate_root_key, HashRatchet
from ..crypto.aead import AEADCipher
from ..crypto.scramble import scramble_data, unscramble_data
from ..protocol.encryptor import OuroborosEncryptor
from ..protocol.decryptor import OuroborosDecryptor
from ..protocol.window import SlidingWindow


class BenchmarkResult:
    """Container for benchmark results."""
    
    def __init__(self, name: str):
        self.name = name
        self.times: List[float] = []
        self.memory_usage: List[int] = []
        self.throughput: List[float] = []
        self.metadata: Dict = {}
    
    def add_measurement(self, time_taken: float, memory_used: int = 0, 
                       throughput: float = 0, **metadata):
        """Add a measurement to the benchmark results."""
        self.times.append(time_taken)
        self.memory_usage.append(memory_used)
        self.throughput.append(throughput)
        
        for key, value in metadata.items():
            if key not in self.metadata:
                self.metadata[key] = []
            self.metadata[key].append(value)
    
    def get_statistics(self) -> Dict:
        """Get statistical summary of the benchmark."""
        stats = {
            'name': self.name,
            'count': len(self.times),
        }
        
        if self.times:
            stats.update({
                'time_mean': statistics.mean(self.times),
                'time_median': statistics.median(self.times),
                'time_stdev': statistics.stdev(self.times) if len(self.times) > 1 else 0,
                'time_min': min(self.times),
                'time_max': max(self.times),
            })
        
        if self.memory_usage and any(m > 0 for m in self.memory_usage):
            stats.update({
                'memory_mean': statistics.mean(self.memory_usage),
                'memory_max': max(self.memory_usage),
            })
        
        if self.throughput and any(t > 0 for t in self.throughput):
            stats.update({
                'throughput_mean': statistics.mean(self.throughput),
                'throughput_max': max(self.throughput),
            })
        
        return stats


class PerformanceBenchmark:
    """Comprehensive performance benchmark suite."""
    
    def __init__(self):
        self.results: Dict[str, BenchmarkResult] = {}
        self.process = psutil.Process()
    
    def run_all_benchmarks(self) -> Dict[str, Dict]:
        """Run all performance benchmarks."""
        print("🚀 Running Ouroboros Performance Benchmarks")
        print("=" * 50)
        
        # Core crypto benchmarks
        self._benchmark_key_derivation()
        self._benchmark_encryption_decryption()
        self._benchmark_scrambling()
        
        # Protocol benchmarks
        self._benchmark_packet_processing()
        self._benchmark_window_operations()
        
        # End-to-end benchmarks
        self._benchmark_end_to_end_pipeline()
        self._benchmark_message_sizes()
        
        # Memory benchmarks
        self._benchmark_memory_usage()
        
        # Compile results
        return {name: result.get_statistics() for name, result in self.results.items()}
    
    def _benchmark_key_derivation(self):
        """Benchmark key derivation operations."""
        print("Benchmarking key derivation...")
        
        root_key = generate_root_key()
        
        # Hash ratchet benchmark
        ratchet_result = BenchmarkResult("hash_ratchet")
        ratchet = HashRatchet(root_key)
        
        for i in range(1000):
            start_time = time.perf_counter()
            enc_key, scr_key = ratchet.derive_keys(i)
            end_time = time.perf_counter()
            
            ratchet_result.add_measurement(end_time - start_time)
        
        self.results["hash_ratchet"] = ratchet_result
        
        # HKDF benchmark
        from ..crypto.ratchet import derive_keys_hkdf
        
        hkdf_result = BenchmarkResult("hkdf_derivation")
        
        for i in range(1000):
            start_time = time.perf_counter()
            enc_key, scr_key = derive_keys_hkdf(root_key, i)
            end_time = time.perf_counter()
            
            hkdf_result.add_measurement(end_time - start_time)
        
        self.results["hkdf_derivation"] = hkdf_result
        
        print(f"  Hash ratchet: {statistics.mean(ratchet_result.times)*1000:.3f} ms avg")
        print(f"  HKDF: {statistics.mean(hkdf_result.times)*1000:.3f} ms avg")
    
    def _benchmark_encryption_decryption(self):
        """Benchmark AEAD encryption and decryption."""
        print("Benchmarking AEAD operations...")
        
        cipher = AEADCipher(AEADCipher.AES_GCM)
        key = generate_root_key()
        plaintext = os.urandom(1024)  # 1KB
        
        # Encryption benchmark
        enc_result = BenchmarkResult("aead_encryption")
        
        for _ in range(1000):
            nonce = os.urandom(cipher.nonce_length)
            
            start_time = time.perf_counter()
            ciphertext = cipher.encrypt(key, nonce, plaintext)
            end_time = time.perf_counter()
            
            throughput = len(plaintext) / (end_time - start_time)
            enc_result.add_measurement(end_time - start_time, throughput=throughput)
        
        self.results["aead_encryption"] = enc_result
        
        # Decryption benchmark
        dec_result = BenchmarkResult("aead_decryption")
        nonce = os.urandom(cipher.nonce_length)
        ciphertext = cipher.encrypt(key, nonce, plaintext)
        
        for _ in range(1000):
            start_time = time.perf_counter()
            decrypted = cipher.decrypt(key, nonce, ciphertext)
            end_time = time.perf_counter()
            
            throughput = len(plaintext) / (end_time - start_time)
            dec_result.add_measurement(end_time - start_time, throughput=throughput)
        
        self.results["aead_decryption"] = dec_result
        
        print(f"  Encryption: {statistics.mean(enc_result.times)*1000:.3f} ms avg, "
              f"{statistics.mean(enc_result.throughput)/1024/1024:.1f} MB/s")
        print(f"  Decryption: {statistics.mean(dec_result.times)*1000:.3f} ms avg, "
              f"{statistics.mean(dec_result.throughput)/1024/1024:.1f} MB/s")
    
    def _benchmark_scrambling(self):
        """Benchmark scrambling operations."""
        print("Benchmarking scrambling...")
        
        key = generate_root_key()
        
        # Test different data sizes
        sizes = [64, 256, 1024, 4096]
        
        for size in sizes:
            data = os.urandom(size)
            
            # Scrambling benchmark
            scramble_result = BenchmarkResult(f"scrambling_{size}")
            
            for _ in range(100):
                start_time = time.perf_counter()
                scrambled = scramble_data(key, data)
                end_time = time.perf_counter()
                
                throughput = size / (end_time - start_time)
                scramble_result.add_measurement(end_time - start_time, throughput=throughput)
            
            # Unscrambling benchmark
            unscramble_result = BenchmarkResult(f"unscrambling_{size}")
            scrambled = scramble_data(key, data)
            
            for _ in range(100):
                start_time = time.perf_counter()
                unscrambled = unscramble_data(key, scrambled)
                end_time = time.perf_counter()
                
                throughput = size / (end_time - start_time)
                unscramble_result.add_measurement(end_time - start_time, throughput=throughput)
            
            self.results[f"scrambling_{size}"] = scramble_result
            self.results[f"unscrambling_{size}"] = unscramble_result
            
            print(f"  Size {size:4d}: Scramble {statistics.mean(scramble_result.times)*1000:.2f} ms, "
                  f"Unscramble {statistics.mean(unscramble_result.times)*1000:.2f} ms")
    
    def _benchmark_packet_processing(self):
        """Benchmark packet processing operations."""
        print("Benchmarking packet processing...")
        
        from ..protocol.packet import OuroborosPacket
        
        # Packet serialization benchmark
        ser_result = BenchmarkResult("packet_serialization")
        
        for _ in range(1000):
            packet = OuroborosPacket(
                channel_id=42,
                counter=12345,
                r=67890,
                auth_tag=os.urandom(16),
                scrambled_data=os.urandom(1024)
            )
            
            start_time = time.perf_counter()
            packet_bytes = packet.to_bytes()
            end_time = time.perf_counter()
            
            ser_result.add_measurement(end_time - start_time)
        
        self.results["packet_serialization"] = ser_result
        
        # Packet deserialization benchmark
        deser_result = BenchmarkResult("packet_deserialization")
        packet_bytes = packet.to_bytes()
        
        for _ in range(1000):
            start_time = time.perf_counter()
            parsed_packet = OuroborosPacket.from_bytes(packet_bytes)
            end_time = time.perf_counter()
            
            deser_result.add_measurement(end_time - start_time)
        
        self.results["packet_deserialization"] = deser_result
        
        print(f"  Serialization: {statistics.mean(ser_result.times)*1000000:.1f} μs avg")
        print(f"  Deserialization: {statistics.mean(deser_result.times)*1000000:.1f} μs avg")
    
    def _benchmark_window_operations(self):
        """Benchmark sliding window operations."""
        print("Benchmarking sliding window...")
        
        window = SlidingWindow(window_size=1000)
        
        # Window accept benchmark
        accept_result = BenchmarkResult("window_accept")
        
        for i in range(10000):
            start_time = time.perf_counter()
            accepted = window.accept_counter(i)
            end_time = time.perf_counter()
            
            accept_result.add_measurement(end_time - start_time)
        
        self.results["window_accept"] = accept_result
        
        # Window validation benchmark
        valid_result = BenchmarkResult("window_validation")
        
        for i in range(10000, 20000):
            start_time = time.perf_counter()
            valid = window.is_valid_counter(i)
            end_time = time.perf_counter()
            
            valid_result.add_measurement(end_time - start_time)
        
        self.results["window_validation"] = valid_result
        
        print(f"  Accept: {statistics.mean(accept_result.times)*1000000:.1f} μs avg")
        print(f"  Validation: {statistics.mean(valid_result.times)*1000000:.1f} μs avg")
    
    def _benchmark_end_to_end_pipeline(self):
        """Benchmark complete end-to-end encryption/decryption pipeline."""
        print("Benchmarking end-to-end pipeline...")
        
        root_key = generate_root_key()
        encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
        decryptor = OuroborosDecryptor(root_key, use_ratcheting=False)
        
        plaintext = os.urandom(1024)  # 1KB message
        
        # End-to-end benchmark
        e2e_result = BenchmarkResult("end_to_end_pipeline")
        
        for _ in range(500):
            start_time = time.perf_counter()
            
            # Encrypt
            packet = encryptor.encrypt_message(plaintext)
            
            # Decrypt
            decrypted = decryptor.decrypt_packet(packet)
            
            end_time = time.perf_counter()
            
            throughput = len(plaintext) / (end_time - start_time)
            e2e_result.add_measurement(end_time - start_time, throughput=throughput)
        
        self.results["end_to_end_pipeline"] = e2e_result
        
        print(f"  End-to-end: {statistics.mean(e2e_result.times)*1000:.3f} ms avg, "
              f"{statistics.mean(e2e_result.throughput)/1024/1024:.1f} MB/s")
    
    def _benchmark_message_sizes(self):
        """Benchmark performance across different message sizes."""
        print("Benchmarking message sizes...")
        
        root_key = generate_root_key()
        sizes = [16, 64, 256, 1024, 4096, 16384, 65536]  # 16B to 64KB
        
        for size in sizes:
            encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
            decryptor = OuroborosDecryptor(root_key, use_ratcheting=False)
            
            plaintext = os.urandom(size)
            iterations = max(10, 1000 // (size // 64 + 1))  # Fewer iterations for larger sizes
            
            size_result = BenchmarkResult(f"message_size_{size}")
            
            for _ in range(iterations):
                start_time = time.perf_counter()
                packet = encryptor.encrypt_message(plaintext)
                decrypted = decryptor.decrypt_packet(packet)
                end_time = time.perf_counter()
                
                throughput = size / (end_time - start_time)
                size_result.add_measurement(end_time - start_time, throughput=throughput)
            
            self.results[f"message_size_{size}"] = size_result
            
            print(f"  Size {size:5d}: {statistics.mean(size_result.times)*1000:.2f} ms, "
                  f"{statistics.mean(size_result.throughput)/1024/1024:.1f} MB/s")
    
    def _benchmark_memory_usage(self):
        """Benchmark memory usage patterns."""
        print("Benchmarking memory usage...")
        
        initial_memory = self.process.memory_info().rss
        
        root_key = generate_root_key()
        encryptor = OuroborosEncryptor(root_key)
        
        # Memory usage for encryption
        memory_result = BenchmarkResult("memory_usage")
        
        for i in range(100):
            plaintext = os.urandom(1024)
            packet = encryptor.encrypt_message(plaintext)
            
            current_memory = self.process.memory_info().rss
            memory_increase = current_memory - initial_memory
            
            memory_result.add_measurement(0, memory_used=memory_increase)
        
        self.results["memory_usage"] = memory_result
        
        avg_memory = statistics.mean(memory_result.memory_usage)
        print(f"  Average memory increase: {avg_memory / 1024:.1f} KB")
    
    def save_results(self, filename: str):
        """Save benchmark results to a file."""
        import json
        
        results_data = {}
        for name, result in self.results.items():
            results_data[name] = result.get_statistics()
        
        with open(filename, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        print(f"Results saved to {filename}")
    
    def print_summary(self):
        """Print a summary of all benchmark results."""
        print("\n" + "=" * 60)
        print("PERFORMANCE BENCHMARK SUMMARY")
        print("=" * 60)
        
        key_results = [
            ("Key Derivation (Hash Ratchet)", "hash_ratchet", "time_mean", 1000, "ms"),
            ("Key Derivation (HKDF)", "hkdf_derivation", "time_mean", 1000, "ms"),
            ("AEAD Encryption", "aead_encryption", "throughput_mean", 1/1024/1024, "MB/s"),
            ("AEAD Decryption", "aead_decryption", "throughput_mean", 1/1024/1024, "MB/s"),
            ("End-to-End Pipeline", "end_to_end_pipeline", "throughput_mean", 1/1024/1024, "MB/s"),
            ("Packet Serialization", "packet_serialization", "time_mean", 1000000, "μs"),
            ("Window Operations", "window_accept", "time_mean", 1000000, "μs"),
        ]
        
        for name, result_key, metric, multiplier, unit in key_results:
            if result_key in self.results:
                stats = self.results[result_key].get_statistics()
                if metric in stats:
                    value = stats[metric] * multiplier
                    print(f"{name:25s}: {value:8.1f} {unit}")
        
        print("=" * 60)


def run_benchmarks() -> Dict[str, Dict]:
    """Run all performance benchmarks and return results."""
    benchmark = PerformanceBenchmark()
    results = benchmark.run_all_benchmarks()
    benchmark.print_summary()
    return results


if __name__ == "__main__":
    results = run_benchmarks()
    
    # Save results to file
    import os
    os.makedirs("benchmark_results", exist_ok=True)
    
    benchmark = PerformanceBenchmark()
    benchmark.results = {k: BenchmarkResult(k) for k in results.keys()}
    for k, v in results.items():
        benchmark.results[k].metadata = v
    
    benchmark.save_results("benchmark_results/performance_results.json")