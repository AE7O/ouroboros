#!/usr/bin/env python3
"""
Ouroboros Protocol - Examples as Tests Runner

This script runs all examples as executable tests, providing a comprehensive
validation of the entire protocol implementation.
"""

import sys
import os
import importlib
import traceback
from typing import List, Tuple, Callable

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class ExampleTestRunner:
    """Runs examples as tests and reports results."""
    
    def __init__(self):
        self.results: List[Tuple[str, bool, str]] = []
    
    def run_example_test(self, module_name: str, description: str) -> bool:
        """Run a single example as a test."""
        try:
            print(f"\n🧪 Running {description}...")
            print("=" * 60)
            
            # Import and run the example
            module = importlib.import_module(f"examples.{module_name}")
            module.main()
            
            self.results.append((description, True, "Passed"))
            print(f"✅ {description} - PASSED")
            return True
            
        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)}"
            self.results.append((description, False, error_msg))
            print(f"❌ {description} - FAILED: {error_msg}")
            
            # Print traceback for debugging
            print("\nTraceback:")
            traceback.print_exc()
            return False
    
    def print_summary(self):
        """Print a summary of all test results."""
        print("\n" + "=" * 80)
        print("📊 EXAMPLE-TESTS SUMMARY")
        print("=" * 80)
        
        passed = sum(1 for _, success, _ in self.results if success)
        failed = len(self.results) - passed
        
        print(f"Total Examples: {len(self.results)}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print()
        
        # Print detailed results
        for description, success, message in self.results:
            status = "✅ PASS" if success else "❌ FAIL"
            print(f"{status} - {description}")
            if not success:
                print(f"      Error: {message}")
        
        print("=" * 80)
        
        if failed == 0:
            print("🎉 ALL EXAMPLE-TESTS PASSED! 🎉")
            print("The Ouroboros Protocol implementation is working correctly!")
        else:
            print(f"⚠️  {failed} example-test(s) failed. Please check the issues above.")
        
        return failed == 0


def main():
    """Run all examples as tests."""
    print("🧪 Ouroboros Protocol - Examples as Tests")
    print("Running comprehensive validation of all protocol components...")
    
    runner = ExampleTestRunner()
    
    # Define the order of tests (from low-level to high-level)
    example_tests = [
        # Core crypto components
        ("key_derivation_example", "Key Derivation Functions"),
        ("aes_gcm_example", "AES-GCM Authenticated Encryption"),  
        ("scrambling_example", "Data Scrambling Operations"),
        
        # Protocol components
        ("packet_example", "Packet Handling and Serialization"),
        ("counter_example", "Counter Management and Replay Protection"),
        ("config_example", "Configuration Management"),
        
        # Integration tests
        ("complete_example", "Complete Message Processing"),
        ("holistic_example", "End-to-End Protocol Operation"),
    ]
    
    # Run each example as a test
    all_passed = True
    for module_name, description in example_tests:
        try:
            success = runner.run_example_test(module_name, description)
            all_passed = all_passed and success
        except ImportError:
            print(f"⚠️  Skipping {description} - module not found")
            runner.results.append((description, False, "Module not found"))
            all_passed = False
    
    # Print summary
    runner.print_summary()
    
    # Exit with appropriate code
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
