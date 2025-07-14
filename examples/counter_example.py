#!/usr/bin/env python3
"""
Counter Management Module - Example & Test

This demonstrates and tests the Ouroboros counter management system,
including counter generation, replay protection, and thread safety.
"""

import sys
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ouroboros.utils.counter import CounterManager


def main():
    print("🔢 Counter Management Module - Example & Test")
    print("=" * 50)
    
    try:
        # Test 1: Basic counter operations
        print("1. Testing basic counter operations...")
        
        counter_mgr = CounterManager()
        
        # Get first counter
        counter1 = counter_mgr.get_next_send_counter()
        assert counter1 == 0, "First counter should be 0"
        
        # Get second counter
        counter2 = counter_mgr.get_next_send_counter()
        assert counter2 == 1, "Second counter should be 1"
        assert counter2 > counter1, "Counters should be monotonically increasing"
        
        print(f"   ✅ Generated counters: {counter1}, {counter2}")
        
        # Test 2: Counter validation and replay protection
        print("\n2. Testing counter validation...")
        
        # Test received counter validation (not send counter validation)
        assert counter_mgr.validate_received_counter(100), "Should accept first received counter"
        assert not counter_mgr.validate_received_counter(100), "Should reject duplicate counter"
        assert counter_mgr.validate_received_counter(101), "Should accept newer counter"
        assert counter_mgr.validate_received_counter(102), "Should accept sequential counter"
        
        # Test replay protection
        assert not counter_mgr.validate_received_counter(101), "Should reject previously seen counter"
        
        print("   ✅ Counter validation working correctly")
        
        # Test 3: Replay protection window
        print("\n3. Testing replay protection window...")
        
        # Create new manager for clean state
        replay_mgr = CounterManager(window_size=5)
        
        # Process some counters
        for i in range(1, 6):
            counter = replay_mgr.get_next_counter()
            assert counter == i, f"Counter {i} should be generated correctly"
        
        # Test window validation
        assert not replay_mgr.is_valid_counter(1), "Counter 1 should be outside window"
        assert replay_mgr.is_valid_counter(6), "Counter 6 should be valid (next)"
        assert replay_mgr.is_valid_counter(10), "Counter 10 should be valid (future)"
        
        # Process counter 7 (skip 6)
        replay_mgr.process_counter(7)
        assert not replay_mgr.is_valid_counter(6), "Counter 6 should now be invalid"
        assert replay_mgr.is_valid_counter(8), "Counter 8 should be valid"
        
        print("   ✅ Replay protection window working correctly")
        
        # Test 4: Out-of-order processing
        print("\n4. Testing out-of-order processing...")
        
        ooo_mgr = CounterManager(window_size=10)
        
        # Generate some counters but process out of order
        c1 = ooo_mgr.get_next_counter()  # 1
        c2 = ooo_mgr.get_next_counter()  # 2
        c3 = ooo_mgr.get_next_counter()  # 3
        
        # Process counter 5 (future)
        assert ooo_mgr.is_valid_counter(5), "Future counter 5 should be valid"
        ooo_mgr.process_counter(5)
        
        # Process counter 4 (past but within window)
        assert ooo_mgr.is_valid_counter(4), "Counter 4 should still be valid"
        ooo_mgr.process_counter(4)
        
        # Try to process 4 again (replay)
        assert not ooo_mgr.is_valid_counter(4), "Counter 4 should be invalid after processing"
        
        # Try to process 3 (should still be valid)
        assert ooo_mgr.is_valid_counter(3), "Counter 3 should still be valid"
        
        print("   ✅ Out-of-order processing working correctly")
        
        # Test 5: Thread safety
        print("\n5. Testing thread safety...")
        
        thread_mgr = CounterManager()
        generated_counters = []
        counter_lock = threading.Lock()
        
        def generate_counters(thread_id, count):
            """Generate counters in a thread"""
            local_counters = []
            for _ in range(count):
                counter = thread_mgr.get_next_counter()
                local_counters.append(counter)
                time.sleep(0.001)  # Small delay to encourage race conditions
            
            with counter_lock:
                generated_counters.extend([(thread_id, c) for c in local_counters])
        
        # Run multiple threads generating counters
        num_threads = 5
        counters_per_thread = 20
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []
            for thread_id in range(num_threads):
                future = executor.submit(generate_counters, thread_id, counters_per_thread)
                futures.append(future)
            
            # Wait for all threads to complete
            for future in futures:
                future.result()
        
        # Verify no duplicate counters
        all_counters = [counter for _, counter in generated_counters]
        unique_counters = set(all_counters)
        
        assert len(all_counters) == len(unique_counters), "No duplicate counters should be generated"
        assert len(all_counters) == num_threads * counters_per_thread, "All counters should be generated"
        assert min(all_counters) == 1, "First counter should be 1"
        assert max(all_counters) == num_threads * counters_per_thread, "Last counter should be correct"
        
        print(f"   ✅ Generated {len(all_counters)} unique counters across {num_threads} threads")
        
        # Test 6: Large window size
        print("\n6. Testing large window size...")
        
        large_mgr = CounterManager(window_size=1000)
        
        # Generate many counters
        for i in range(1, 501):
            counter = large_mgr.get_next_counter()
            assert counter == i, f"Counter {i} should be generated correctly"
        
        # Test that old counters are still invalid
        assert not large_mgr.is_valid_counter(1), "Very old counter should be invalid"
        assert not large_mgr.is_valid_counter(250), "Old counter should be invalid"
        
        # Test that recent counters are valid for processing
        assert large_mgr.is_valid_counter(501), "Next counter should be valid"
        assert large_mgr.is_valid_counter(1000), "Future counter should be valid"
        
        print("   ✅ Large window size working correctly")
        
        # Test 7: Counter wraparound (edge case)
        print("\n7. Testing counter edge cases...")
        
        # Test with custom start counter
        start_counter = 2**32 - 5  # Near 32-bit limit
        edge_mgr = CounterManager()
        edge_mgr._next_counter = start_counter
        
        for i in range(10):
            counter = edge_mgr.get_next_counter()
            assert counter == start_counter + i, f"Counter {i} should be correct"
        
        print(f"   ✅ Edge case counters generated correctly from {start_counter}")
        
        # Test 8: Performance test
        print("\n8. Testing counter performance...")
        
        perf_mgr = CounterManager(window_size=1000)
        
        # Time counter generation
        start_time = time.time()
        for _ in range(10000):
            perf_mgr.get_next_counter()
        generation_time = time.time() - start_time
        
        # Time counter validation
        start_time = time.time()
        for i in range(1, 1001):
            perf_mgr.is_valid_counter(i + 10000)
        validation_time = time.time() - start_time
        
        print(f"   ✅ Generated 10,000 counters in {generation_time:.3f}s")
        print(f"   ✅ Validated 1,000 counters in {validation_time:.3f}s")
        
        # Test 9: Reset functionality
        print("\n9. Testing counter reset...")
        
        reset_mgr = CounterManager()
        
        # Generate some counters
        for _ in range(5):
            reset_mgr.get_next_counter()
        
        old_counter = reset_mgr.get_current_counter()
        assert old_counter == 5, "Current counter should be 5"
        
        # Reset
        reset_mgr.reset()
        
        new_counter = reset_mgr.get_next_counter()
        assert new_counter == 1, "Counter should reset to 1"
        
        print("   ✅ Counter reset working correctly")
        
        print("\n🎉 All counter management tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Counter management test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
