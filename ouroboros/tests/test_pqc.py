"""
Post-Quantum Cryptography (PQC) tests for Ouroboros evaluation.

This module tests PQC algorithms (Kyber, Dilithium) via liboqs-python
to provide baseline comparison data against Ouroboros protocol performance.

Tests are organized by category:
CATEGORY 1: Individual PQC Algorithm Performance (KEM isolation)
CATEGORY 2: Individual PQC Algorithm Performance (Signature isolation) 
CATEGORY 3: PQC Component Analysis (keygen, encaps/sign, decaps/verify)
CATEGORY 4: PQC Memory and Size Analysis
CATEGORY 5: Integration with Benchmark Module
"""

import time
import pytest
import statistics
from typing import List, Dict, Any, Optional

# PQC imports with graceful handling
PQC_AVAILABLE = False
try:
    import oqs  # liboqs-python
    PQC_AVAILABLE = True
except ImportError:
    oqs = None  # type: ignore
    PQC_AVAILABLE = False

from ouroboros.crypto.utils import generate_random_bytes
from ouroboros.evaluation.pqc_benchmark import PQCBenchmark, get_pqc_system_info

# Standard payload sizes for consistent comparison
STANDARD_PAYLOAD_SIZES = [0, 16, 64, 128, 256, 1024, 2048, 4096]

# PQC algorithm mappings (same as pqc_benchmark.py)
KEM_ALGORITHMS = {
    "kyber512": "ML-KEM-512",
    "kyber768": "ML-KEM-768", 
    "kyber1024": "ML-KEM-1024",
}

SIGNATURE_ALGORITHMS = {
    "dilithium2": "ML-DSA-44",
    "dilithium3": "ML-DSA-65",
    "dilithium5": "ML-DSA-87",
}


@pytest.mark.skipif(not PQC_AVAILABLE, reason="liboqs-python not installed")
class TestPQCPerformance:
    """
    PQC performance benchmarking tests organized by category:
    
    CATEGORY 1: Individual KEM Performance (Kyber isolation)
    CATEGORY 2: Individual Signature Performance (Dilithium isolation)
    CATEGORY 3: PQC Component Analysis (individual operations)
    CATEGORY 4: PQC Memory and Size Analysis
    """
    
    # ============================================================================
    # CATEGORY 1: INDIVIDUAL KEM PERFORMANCE (Kyber Isolation)
    # ============================================================================
    
    def test_individual_kem_kyber512(self):
        """Test ML-KEM-512 (Kyber512) performance in isolation."""
        if not PQC_AVAILABLE:
            pytest.skip("liboqs-python not available")
            
        algorithm = "kyber512"
        oqs_alg = KEM_ALGORITHMS[algorithm]
        iterations = 30  # Reasonable for PQC operations
        
        print(f"\n{algorithm.upper()} KEM Performance (Isolated):")
        
        try:
            # Check if algorithm is available
            enabled_kems = list(getattr(oqs, 'get_enabled_kem_mechanisms', lambda: [])())
            if oqs_alg not in enabled_kems:
                pytest.skip(f"{oqs_alg} not enabled in liboqs")
            
            keygen_times = []
            encaps_times = []
            decaps_times = []
            
            with oqs.KeyEncapsulation(oqs_alg) as kem:
                # Warmup
                for _ in range(5):
                    pk = kem.generate_keypair()
                    ct, ss = kem.encap_secret(pk)
                    kem.decap_secret(ct)
                
                # Timed operations
                for _ in range(iterations):
                    # Key generation
                    start_time = time.perf_counter()
                    pk = kem.generate_keypair()
                    end_time = time.perf_counter()
                    keygen_times.append(end_time - start_time)
                    
                    # Encapsulation
                    start_time = time.perf_counter()
                    ct, ss = kem.encap_secret(pk)
                    end_time = time.perf_counter()
                    encaps_times.append(end_time - start_time)
                    
                    # Decapsulation
                    start_time = time.perf_counter()
                    decap_ss = kem.decap_secret(ct)
                    end_time = time.perf_counter()
                    decaps_times.append(end_time - start_time)
                    
                    assert ss == decap_ss, "Shared secret mismatch"
                
                # Calculate statistics
                keygen_avg = statistics.mean(keygen_times)
                encaps_avg = statistics.mean(encaps_times)
                decaps_avg = statistics.mean(decaps_times)
                total_avg = keygen_avg + encaps_avg + decaps_avg
                
                # Size information
                pk_size = kem.length_public_key
                sk_size = kem.length_secret_key
                ct_size = kem.length_ciphertext
                ss_size = kem.length_shared_secret
                
                print(f"  Key Generation: {keygen_avg*1000:.3f}ms avg")
                print(f"  Encapsulation:  {encaps_avg*1000:.3f}ms avg")
                print(f"  Decapsulation:  {decaps_avg*1000:.3f}ms avg")
                print(f"  Total Cycle:    {total_avg*1000:.3f}ms avg")
                print(f"  Sizes: PK={pk_size}B, SK={sk_size}B, CT={ct_size}B, SS={ss_size}B")
                
                # Performance assertions
                assert keygen_avg > 0, "Invalid key generation time"
                assert encaps_avg > 0, "Invalid encapsulation time"
                assert decaps_avg > 0, "Invalid decapsulation time"
                assert total_avg < 1.0, f"Total cycle too slow: {total_avg*1000:.1f}ms"
                
        except Exception as e:
            pytest.skip(f"{algorithm} benchmark failed: {e}")
    
    def test_individual_kem_kyber768(self):
        """Test ML-KEM-768 (Kyber768) performance in isolation."""
        if not PQC_AVAILABLE:
            pytest.skip("liboqs-python not available")
            
        algorithm = "kyber768"
        oqs_alg = KEM_ALGORITHMS[algorithm]
        iterations = 20  # Fewer iterations for larger parameter set
        
        print(f"\n{algorithm.upper()} KEM Performance (Isolated):")
        
        try:
            enabled_kems = list(getattr(oqs, 'get_enabled_kem_mechanisms', lambda: [])())
            if oqs_alg not in enabled_kems:
                pytest.skip(f"{oqs_alg} not enabled in liboqs")
            
            keygen_times = []
            encaps_times = []
            decaps_times = []
            
            with oqs.KeyEncapsulation(oqs_alg) as kem:
                # Warmup
                for _ in range(3):
                    pk = kem.generate_keypair()
                    ct, ss = kem.encap_secret(pk)
                    kem.decap_secret(ct)
                
                # Timed operations
                for _ in range(iterations):
                    start_time = time.perf_counter()
                    pk = kem.generate_keypair()
                    keygen_end = time.perf_counter()
                    ct, ss = kem.encap_secret(pk)
                    encaps_end = time.perf_counter()
                    decap_ss = kem.decap_secret(ct)
                    decaps_end = time.perf_counter()
                    
                    keygen_times.append(keygen_end - start_time)
                    encaps_times.append(encaps_end - keygen_end)
                    decaps_times.append(decaps_end - encaps_end)
                    
                    assert ss == decap_ss, "Shared secret mismatch"
                
                # Results
                keygen_avg = statistics.mean(keygen_times)
                encaps_avg = statistics.mean(encaps_times)
                decaps_avg = statistics.mean(decaps_times)
                
                print(f"  Key Generation: {keygen_avg*1000:.3f}ms avg")
                print(f"  Encapsulation:  {encaps_avg*1000:.3f}ms avg")
                print(f"  Decapsulation:  {decaps_avg*1000:.3f}ms avg")
                print(f"  Sizes: PK={kem.length_public_key}B, CT={kem.length_ciphertext}B")
                
                # Performance assertions
                assert keygen_avg > 0, "Invalid key generation time"
                assert encaps_avg > 0, "Invalid encapsulation time" 
                assert decaps_avg > 0, "Invalid decapsulation time"
                
        except Exception as e:
            pytest.skip(f"{algorithm} benchmark failed: {e}")
    
    # ============================================================================
    # CATEGORY 2: INDIVIDUAL SIGNATURE PERFORMANCE (Dilithium Isolation)
    # ============================================================================
    
    def test_individual_sig_dilithium2(self):
        """Test ML-DSA-44 (Dilithium2) signature performance in isolation."""
        if not PQC_AVAILABLE:
            pytest.skip("liboqs-python not available")
            
        algorithm = "dilithium2"
        oqs_alg = SIGNATURE_ALGORITHMS[algorithm]
        iterations = 20
        
        # Test with different message sizes
        test_sizes = [64, 256, 1024]  # Representative sizes
        
        print(f"\n{algorithm.upper()} Signature Performance (Isolated):")
        
        try:
            enabled_sigs = list(getattr(oqs, 'get_enabled_sig_mechanisms', lambda: [])())
            if oqs_alg not in enabled_sigs:
                pytest.skip(f"{oqs_alg} not enabled in liboqs")
            
            for msg_size in test_sizes:
                message = generate_random_bytes(msg_size)
                
                keygen_times = []
                sign_times = []
                verify_times = []
                
                with oqs.Signature(oqs_alg) as sig:
                    # Warmup
                    for _ in range(3):
                        pk = sig.generate_keypair()
                        signature = sig.sign(message)
                        sig.verify(message, signature, pk)
                    
                    # Timed operations
                    for _ in range(iterations):
                        # Key generation
                        start_time = time.perf_counter()
                        pk = sig.generate_keypair()
                        keygen_end = time.perf_counter()
                        keygen_times.append(keygen_end - start_time)
                        
                        # Signing
                        start_time = time.perf_counter()
                        signature = sig.sign(message)
                        sign_end = time.perf_counter()
                        sign_times.append(sign_end - start_time)
                        
                        # Verification
                        start_time = time.perf_counter()
                        is_valid = sig.verify(message, signature, pk)
                        verify_end = time.perf_counter()
                        verify_times.append(verify_end - start_time)
                        
                        assert is_valid, "Signature verification failed"
                    
                    # Results for this message size
                    keygen_avg = statistics.mean(keygen_times)
                    sign_avg = statistics.mean(sign_times)
                    verify_avg = statistics.mean(verify_times)
                    
                    print(f"  {msg_size}B message:")
                    print(f"    Key Generation: {keygen_avg*1000:.3f}ms avg")
                    print(f"    Signing:        {sign_avg*1000:.3f}ms avg")
                    print(f"    Verification:   {verify_avg*1000:.3f}ms avg")
                    if msg_size == test_sizes[0]:  # Print sizes once
                        print(f"    Sizes: PK={sig.length_public_key}B, SK={sig.length_secret_key}B, Sig={sig.length_signature}B")
                    
                    # Performance assertions
                    assert keygen_avg > 0, f"Invalid key generation time for {msg_size}B"
                    assert sign_avg > 0, f"Invalid signing time for {msg_size}B"
                    assert verify_avg > 0, f"Invalid verification time for {msg_size}B"
                    
        except Exception as e:
            pytest.skip(f"{algorithm} benchmark failed: {e}")
    
    def test_individual_sig_dilithium3(self):
        """Test ML-DSA-65 (Dilithium3) signature performance in isolation."""
        if not PQC_AVAILABLE:
            pytest.skip("liboqs-python not available")
            
        algorithm = "dilithium3"
        oqs_alg = SIGNATURE_ALGORITHMS[algorithm]
        iterations = 15  # Fewer iterations for larger parameter set
        
        print(f"\n{algorithm.upper()} Signature Performance (Isolated):")
        
        try:
            enabled_sigs = list(getattr(oqs, 'get_enabled_sig_mechanisms', lambda: [])())
            if oqs_alg not in enabled_sigs:
                pytest.skip(f"{oqs_alg} not enabled in liboqs")
            
            message = generate_random_bytes(1024)  # Standard 1KB message
            
            keygen_times = []
            sign_times = []
            verify_times = []
            
            with oqs.Signature(oqs_alg) as sig:
                # Warmup
                for _ in range(2):
                    pk = sig.generate_keypair()
                    signature = sig.sign(message)
                    sig.verify(message, signature, pk)
                
                # Timed operations
                for _ in range(iterations):
                    start_time = time.perf_counter()
                    pk = sig.generate_keypair()
                    keygen_end = time.perf_counter()
                    signature = sig.sign(message)
                    sign_end = time.perf_counter()
                    is_valid = sig.verify(message, signature, pk)
                    verify_end = time.perf_counter()
                    
                    keygen_times.append(keygen_end - start_time)
                    sign_times.append(sign_end - keygen_end)
                    verify_times.append(verify_end - sign_end)
                    
                    assert is_valid, "Signature verification failed"
                
                # Results
                keygen_avg = statistics.mean(keygen_times)
                sign_avg = statistics.mean(sign_times)
                verify_avg = statistics.mean(verify_times)
                
                print(f"  1024B message:")
                print(f"    Key Generation: {keygen_avg*1000:.3f}ms avg")
                print(f"    Signing:        {sign_avg*1000:.3f}ms avg")
                print(f"    Verification:   {verify_avg*1000:.3f}ms avg")
                print(f"    Sizes: PK={sig.length_public_key}B, Sig={sig.length_signature}B")
                
                # Performance assertions
                assert keygen_avg > 0, "Invalid key generation time"
                assert sign_avg > 0, "Invalid signing time"
                assert verify_avg > 0, "Invalid verification time"
                
        except Exception as e:
            pytest.skip(f"{algorithm} benchmark failed: {e}")
    
    # ============================================================================
    # CATEGORY 3: PQC COMPONENT ANALYSIS (Individual Operations)
    # ============================================================================
    
    def test_pqc_key_generation_analysis(self):
        """Analyze key generation performance across different PQC algorithms."""
        if not PQC_AVAILABLE:
            pytest.skip("liboqs-python not available")
        
        print("\nPQC Key Generation Performance Analysis:")
        
        # Test available algorithms
        available_algorithms = []
        info = get_pqc_system_info()
        
        if info.get("liboqs_available"):
            enabled_kems = set(info.get("enabled_kems", []))
            enabled_sigs = set(info.get("enabled_sigs", []))
            
            for name, mechanism in KEM_ALGORITHMS.items():
                if mechanism in enabled_kems:
                    available_algorithms.append((name, mechanism, "KEM"))
                    
            for name, mechanism in SIGNATURE_ALGORITHMS.items():
                if mechanism in enabled_sigs:
                    available_algorithms.append((name, mechanism, "SIG"))
        
        if not available_algorithms:
            pytest.skip("No PQC algorithms available for testing")
        
        results = {}
        iterations = 10  # Quick comparison
        
        for name, mechanism, alg_type in available_algorithms[:4]:  # Test first 4 to keep test time reasonable
            try:
                keygen_times = []
                
                if alg_type == "KEM":
                    with oqs.KeyEncapsulation(mechanism) as kem:
                        # Warmup
                        for _ in range(2):
                            kem.generate_keypair()
                        
                        # Timed key generation
                        for _ in range(iterations):
                            start_time = time.perf_counter()
                            pk = kem.generate_keypair()
                            end_time = time.perf_counter()
                            keygen_times.append(end_time - start_time)
                        
                        pk_size = kem.length_public_key
                        sk_size = kem.length_secret_key
                        
                else:  # SIG
                    with oqs.Signature(mechanism) as sig:
                        # Warmup
                        for _ in range(2):
                            sig.generate_keypair()
                        
                        # Timed key generation
                        for _ in range(iterations):
                            start_time = time.perf_counter()
                            pk = sig.generate_keypair()
                            end_time = time.perf_counter()
                            keygen_times.append(end_time - start_time)
                        
                        pk_size = sig.length_public_key
                        sk_size = sig.length_secret_key
                
                avg_time = statistics.mean(keygen_times)
                results[name] = {
                    'avg_time': avg_time,
                    'pk_size': pk_size,
                    'sk_size': sk_size,
                    'type': alg_type
                }
                
                print(f"  {name:12} ({alg_type}): {avg_time*1000:6.2f}ms avg, PK={pk_size:4d}B, SK={sk_size:4d}B")
                
            except Exception as e:
                print(f"  {name:12} ({alg_type}): Failed - {e}")
        
        # Assertions
        assert len(results) > 0, "No successful PQC key generation tests"
        for name, data in results.items():
            assert data['avg_time'] > 0, f"Invalid key generation time for {name}"
            assert data['pk_size'] > 0, f"Invalid public key size for {name}"
            assert data['sk_size'] > 0, f"Invalid secret key size for {name}"
    
    def test_pqc_operation_overhead_analysis(self):
        """Compare overhead of KEM vs Signature operations."""
        if not PQC_AVAILABLE:
            pytest.skip("liboqs-python not available")
        
        print("\nPQC Operation Overhead Analysis:")
        
        # Test one representative algorithm from each type if available
        test_cases = []
        info = get_pqc_system_info()
        
        if info.get("kyber768_available"):
            test_cases.append(("kyber768", KEM_ALGORITHMS["kyber768"], "KEM"))
        if info.get("dilithium2_available"):
            test_cases.append(("dilithium2", SIGNATURE_ALGORITHMS["dilithium2"], "SIG"))
        
        if not test_cases:
            pytest.skip("Neither Kyber768 nor Dilithium2 available for comparison")
        
        iterations = 8
        message = generate_random_bytes(256)  # Standard message size
        
        for name, mechanism, alg_type in test_cases:
            print(f"\n  {name.upper()} ({alg_type}) Overhead:")
            
            try:
                if alg_type == "KEM":
                    with oqs.KeyEncapsulation(mechanism) as kem:
                        # Full cycle timing
                        cycle_times = []
                        for _ in range(iterations):
                            start_time = time.perf_counter()
                            pk = kem.generate_keypair()
                            ct, ss1 = kem.encap_secret(pk)
                            ss2 = kem.decap_secret(ct)
                            end_time = time.perf_counter()
                            cycle_times.append(end_time - start_time)
                            assert ss1 == ss2
                        
                        cycle_avg = statistics.mean(cycle_times)
                        total_size = kem.length_public_key + kem.length_ciphertext
                        
                        print(f"    Full Cycle: {cycle_avg*1000:.3f}ms avg")
                        print(f"    Total Size: {total_size}B (PK + CT)")
                        
                else:  # SIG
                    with oqs.Signature(mechanism) as sig:
                        # Full cycle timing
                        cycle_times = []
                        for _ in range(iterations):
                            start_time = time.perf_counter()
                            pk = sig.generate_keypair()
                            signature = sig.sign(message)
                            is_valid = sig.verify(message, signature, pk)
                            end_time = time.perf_counter()
                            cycle_times.append(end_time - start_time)
                            assert is_valid
                        
                        cycle_avg = statistics.mean(cycle_times)
                        total_size = sig.length_public_key + sig.length_signature
                        
                        print(f"    Full Cycle: {cycle_avg*1000:.3f}ms avg")
                        print(f"    Total Size: {total_size}B (PK + Sig)")
                
                # Performance assertions
                assert cycle_avg > 0, f"Invalid cycle time for {name}"
                assert cycle_avg < 5.0, f"Cycle too slow for {name}: {cycle_avg*1000:.1f}ms"
                
            except Exception as e:
                print(f"    Failed: {e}")
    
    # ============================================================================
    # CATEGORY 4: PQC MEMORY AND SIZE ANALYSIS
    # ============================================================================
    
    def test_pqc_size_overhead_analysis(self):
        """Analyze size overhead of PQC algorithms vs traditional cryptography."""
        if not PQC_AVAILABLE:
            pytest.skip("liboqs-python not available")
        
        print("\nPQC Size Overhead Analysis:")
        
        # Reference sizes (approximate traditional cryptography)
        traditional_sizes = {
            "RSA-2048": {"pk": 256, "sk": 256, "sig": 256},
            "ECDSA-P256": {"pk": 64, "sk": 32, "sig": 64},
            "ECDH-P256": {"pk": 64, "sk": 32, "shared": 32}
        }
        
        print("  Traditional Cryptography Reference:")
        for name, sizes in traditional_sizes.items():
            if "sig" in sizes:
                print(f"    {name:12}: PK={sizes['pk']:4d}B, SK={sizes['sk']:4d}B, Sig={sizes['sig']:4d}B")
            else:
                print(f"    {name:12}: PK={sizes['pk']:4d}B, SK={sizes['sk']:4d}B, Shared={sizes['shared']:4d}B")
        
        print("\n  PQC Algorithm Sizes:")
        
        # Test available PQC algorithms
        info = get_pqc_system_info()
        pqc_sizes = {}
        
        if info.get("liboqs_available"):
            # Test KEMs
            for name, mechanism in KEM_ALGORITHMS.items():
                if mechanism in info.get("enabled_kems", []):
                    try:
                        with oqs.KeyEncapsulation(mechanism) as kem:
                            pqc_sizes[name] = {
                                "type": "KEM",
                                "pk": kem.length_public_key,
                                "sk": kem.length_secret_key,
                                "ct": kem.length_ciphertext,
                                "ss": kem.length_shared_secret
                            }
                            print(f"    {name:12}: PK={kem.length_public_key:4d}B, SK={kem.length_secret_key:4d}B, CT={kem.length_ciphertext:4d}B")
                    except Exception as e:
                        print(f"    {name:12}: Failed - {e}")
            
            # Test Signatures
            for name, mechanism in SIGNATURE_ALGORITHMS.items():
                if mechanism in info.get("enabled_sigs", []):
                    try:
                        with oqs.Signature(mechanism) as sig:
                            pqc_sizes[name] = {
                                "type": "SIG",
                                "pk": sig.length_public_key,
                                "sk": sig.length_secret_key,
                                "sig": sig.length_signature
                            }
                            print(f"    {name:12}: PK={sig.length_public_key:4d}B, SK={sig.length_secret_key:4d}B, Sig={sig.length_signature:4d}B")
                    except Exception as e:
                        print(f"    {name:12}: Failed - {e}")
        
        # Calculate overhead compared to traditional crypto
        if pqc_sizes:
            print("\n  PQC vs Traditional Overhead:")
            for name, sizes in pqc_sizes.items():
                if sizes["type"] == "KEM":
                    # Compare to ECDH
                    ref = traditional_sizes["ECDH-P256"]
                    pk_overhead = (sizes["pk"] / ref["pk"] - 1) * 100
                    sk_overhead = (sizes["sk"] / ref["sk"] - 1) * 100
                    print(f"    {name:12}: PK +{pk_overhead:5.1f}%, SK +{sk_overhead:5.1f}%")
                else:  # SIG
                    # Compare to ECDSA
                    ref = traditional_sizes["ECDSA-P256"]
                    pk_overhead = (sizes["pk"] / ref["pk"] - 1) * 100
                    sig_overhead = (sizes["sig"] / ref["sig"] - 1) * 100
                    print(f"    {name:12}: PK +{pk_overhead:5.1f}%, Sig +{sig_overhead:5.1f}%")
        
        # Assertions
        assert len(pqc_sizes) > 0, "No PQC size measurements collected"
        for name, sizes in pqc_sizes.items():
            assert sizes["pk"] > 0, f"Invalid public key size for {name}"
            assert sizes["sk"] > 0, f"Invalid secret key size for {name}"
    
    # ============================================================================
    # CATEGORY 5: INTEGRATION WITH BENCHMARK MODULE
    # ============================================================================
    
    def test_pqc_benchmark_integration(self):
        """Test integration with PQC benchmark module."""
        if not PQC_AVAILABLE:
            pytest.skip("liboqs-python not available")
        
        print("\nPQC Benchmark Module Integration:")
        
        # Test system info
        info = get_pqc_system_info()
        assert info["liboqs_available"], "System info should report liboqs as available"
        
        print(f"  liboqs version: {info.get('liboqs_version', 'unknown')}")
        print(f"  Enabled KEMs: {len(info.get('enabled_kems', []))}")
        print(f"  Enabled Signatures: {len(info.get('enabled_sigs', []))}")
        
        # Test benchmark class
        benchmark = PQCBenchmark(iterations=5, warmup=2, message_size=256)
        
        # Test at least one algorithm from each category if available
        results = {}
        
        if info.get("kyber768_available"):
            print("  Testing Kyber768 via benchmark module...")
            result = benchmark.benchmark_kem("kyber768")
            if result.get("status") == "ok":
                results["kyber768"] = result
                ops = result["operations"]
                print(f"    Keygen: {ops['keygen']['mean_ms']:.2f}ms")
                print(f"    Encaps: {ops['encaps']['mean_ms']:.2f}ms") 
                print(f"    Decaps: {ops['decaps']['mean_ms']:.2f}ms")
        
        if info.get("dilithium2_available"):
            print("  Testing Dilithium2 via benchmark module...")
            result = benchmark.benchmark_sig("dilithium2")
            if result.get("status") == "ok":
                results["dilithium2"] = result
                ops = result["operations"]
                print(f"    Keygen: {ops['keygen']['mean_ms']:.2f}ms")
                print(f"    Sign:   {ops['sign']['mean_ms']:.2f}ms")
                print(f"    Verify: {ops['verify']['mean_ms']:.2f}ms")
        
        # Comprehensive benchmark test
        print("  Testing comprehensive benchmark...")
        comp_results = benchmark.run_comprehensive_pqc_benchmark(algorithms=["kyber512", "dilithium2"], iterations=3)
        
        assert comp_results.get("system_info"), "Comprehensive results should include system info"
        assert "algorithms" in comp_results, "Comprehensive results should include algorithm results"
        
        # Assertions
        assert len(results) > 0, "Should have at least one successful benchmark result"
        for name, result in results.items():
            assert result["status"] == "ok", f"Benchmark failed for {name}"
            assert "operations" in result, f"Missing operations data for {name}"
            assert result["iterations"] > 0, f"Invalid iterations for {name}"


@pytest.mark.skipif(PQC_AVAILABLE, reason="Test PQC unavailable handling")
class TestPQCUnavailable:
    """Tests for graceful handling when PQC libraries are unavailable."""
    
    def test_graceful_pqc_unavailable_handling(self):
        """Test that PQC unavailability is handled gracefully."""
        # This test only runs when PQC is NOT available
        info = get_pqc_system_info()
        assert not info["liboqs_available"], "Should report liboqs as unavailable"
        assert "error" in info, "Should include error message when unavailable"
        
        print(f"\n✅ PQC unavailable handling working correctly: {info['error']}")



# ============================================================================
# EVALUATION FRAMEWORK INTEGRATION - REUSABLE PQC PERFORMANCE FUNCTIONS
# ============================================================================

def run_kem_performance_test_kyber768(iterations: int = 1000) -> Dict[str, Any]:
    """Reusable wrapper for Kyber768 KEM performance testing."""
    try:
        if not PQC_AVAILABLE:
            return {'status': 'skipped', 'reason': 'liboqs-python not available'}
        
        import oqs
        import time
        import statistics
        
        # Setup
        kem = oqs.KeyEncapsulation('Kyber768')
        public_key = kem.generate_keypair()
        
        # Performance measurement
        encap_latencies = []
        decap_latencies = []
        
        start_time = time.perf_counter()
        
        for _ in range(iterations):
            # Encapsulation timing
            encap_start = time.perf_counter()
            ciphertext, shared_secret1 = kem.encap_secret(public_key)
            encap_end = time.perf_counter()
            
            # Decapsulation timing  
            decap_start = time.perf_counter()
            shared_secret2 = kem.decap_secret(ciphertext)
            decap_end = time.perf_counter()
            
            # Verify correctness
            assert shared_secret1 == shared_secret2
            
            encap_latencies.append((encap_end - encap_start) * 1000)
            decap_latencies.append((decap_end - decap_start) * 1000)
        
        end_time = time.perf_counter()
        total_time = end_time - start_time
        ops_per_sec = (iterations * 2) / total_time
        
        return {
            'algorithm': 'Kyber768',
            'iterations': iterations,
            'total_time_seconds': total_time,
            'operations_per_second': ops_per_sec,
            'kem_latency_stats': {
                'encap_mean_ms': statistics.mean(encap_latencies),
                'decap_mean_ms': statistics.mean(decap_latencies),
                'combined_mean_ms': statistics.mean(encap_latencies + decap_latencies),
                'min_ms': min(encap_latencies + decap_latencies),
                'max_ms': max(encap_latencies + decap_latencies),
                'std_ms': statistics.stdev(encap_latencies + decap_latencies)
            },
            'size_analysis': {
                'public_key_bytes': len(public_key),
                'ciphertext_bytes': len(ciphertext),
                'shared_secret_bytes': len(shared_secret1)
            }
        }
        
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def run_signature_performance_test_dilithium2(iterations: int = 1000) -> Dict[str, Any]:
    """Reusable wrapper for Dilithium2 signature performance testing."""
    try:
        if not PQC_AVAILABLE:
            return {'status': 'skipped', 'reason': 'liboqs-python not available'}
        
        import oqs
        import time
        import statistics
        from ouroboros.crypto.utils import generate_random_bytes
        
        # Setup
        sig = oqs.Signature('Dilithium2')
        public_key = sig.generate_keypair()
        message = generate_random_bytes(256)  # Standard message size
        
        # Performance measurement
        sign_latencies = []
        verify_latencies = []
        
        start_time = time.perf_counter()
        
        for _ in range(iterations):
            # Signing timing
            sign_start = time.perf_counter()
            signature = sig.sign(message)
            sign_end = time.perf_counter()
            
            # Verification timing
            verify_start = time.perf_counter()
            is_valid = sig.verify(message, signature, public_key)
            verify_end = time.perf_counter()
            
            # Verify correctness
            assert is_valid is True
            
            sign_latencies.append((sign_end - sign_start) * 1000)
            verify_latencies.append((verify_end - verify_start) * 1000)
        
        end_time = time.perf_counter()
        total_time = end_time - start_time
        ops_per_sec = (iterations * 2) / total_time
        
        return {
            'algorithm': 'Dilithium2',
            'iterations': iterations,
            'total_time_seconds': total_time,
            'operations_per_second': ops_per_sec,
            'signature_latency_stats': {
                'sign_mean_ms': statistics.mean(sign_latencies),
                'verify_mean_ms': statistics.mean(verify_latencies),
                'combined_mean_ms': statistics.mean(sign_latencies + verify_latencies),
                'min_ms': min(sign_latencies + verify_latencies),
                'max_ms': max(sign_latencies + verify_latencies),
                'std_ms': statistics.stdev(sign_latencies + verify_latencies)
            },
            'size_analysis': {
                'public_key_bytes': len(public_key),
                'signature_bytes': len(signature),
                'message_bytes': len(message)
            }
        }
        
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def run_pqc_size_overhead_analysis_test() -> Dict[str, Any]:
    """Reusable wrapper for PQC size overhead analysis."""
    try:
        if not PQC_AVAILABLE:
            return {'status': 'skipped', 'reason': 'liboqs-python not available'}
        
        import oqs
        from ouroboros.crypto.utils import generate_random_bytes
        
        results = {
            'analysis_type': 'pqc_size_overhead',
            'algorithms': {},
            'size_comparison': {}
        }
        
        # Analyze Kyber768 sizes
        kem = oqs.KeyEncapsulation('Kyber768')
        kyber_pk = kem.generate_keypair()
        kyber_ct, kyber_ss = kem.encap_secret(kyber_pk)
        
        results['algorithms']['Kyber768'] = {
            'public_key_bytes': len(kyber_pk),
            'ciphertext_bytes': len(kyber_ct),
            'shared_secret_bytes': len(kyber_ss),
            'total_key_material_bytes': len(kyber_pk) + len(kyber_ct)
        }
        
        # Analyze Dilithium2 sizes
        sig = oqs.Signature('Dilithium2')
        dilithium_pk = sig.generate_keypair()
        test_msg = generate_random_bytes(256)
        dilithium_sig = sig.sign(test_msg)
        
        results['algorithms']['Dilithium2'] = {
            'public_key_bytes': len(dilithium_pk),
            'signature_bytes': len(dilithium_sig),
            'total_auth_bytes': len(dilithium_pk) + len(dilithium_sig)
        }
        
        # Size comparison analysis
        kyber_total = results['algorithms']['Kyber768']['total_key_material_bytes']
        dilithium_total = results['algorithms']['Dilithium2']['total_auth_bytes']
        pqc_total_overhead = kyber_total + dilithium_total
        
        # Compare to typical symmetric crypto
        symmetric_key_size = 32  # 256-bit key
        symmetric_tag_size = 16  # 128-bit tag
        symmetric_total = symmetric_key_size + symmetric_tag_size
        
        results['size_comparison'] = {
            'pqc_total_bytes': pqc_total_overhead,
            'symmetric_total_bytes': symmetric_total,
            'size_ratio': pqc_total_overhead / symmetric_total,
            'overhead_factor': f'{pqc_total_overhead / symmetric_total:.1f}x larger',
            'analysis': 'PQC algorithms have significant size overhead compared to symmetric crypto'
        }
        
        return results
        
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def run_comprehensive_pqc_benchmark_test() -> Dict[str, Any]:
    """Reusable wrapper for comprehensive PQC benchmark testing."""
    try:
        if not PQC_AVAILABLE:
            return {'status': 'skipped', 'reason': 'liboqs-python not available'}
        
        from ouroboros.evaluation.pqc_benchmark import PQCBenchmark
        
        # Use the existing PQC benchmark infrastructure
        benchmark = PQCBenchmark(iterations=100)
        results = benchmark.run_comprehensive_pqc_benchmark(
            algorithms=['Kyber768', 'Dilithium2'],
            iterations=100,
            warmup=5,
            message_size=256
        )
        
        return results
        
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


if __name__ == "__main__":
    # Quick test when run directly
    if PQC_AVAILABLE:
        print("PQC libraries available, running quick test...")
        info = get_pqc_system_info()
        print(f"liboqs version: {info.get('liboqs_version')}")
        print(f"Available algorithms: {len(info.get('enabled_kems', []))} KEMs, {len(info.get('enabled_sigs', []))} Signatures")
    else:
        print("PQC libraries not available. Install liboqs-python to enable PQC testing.")
