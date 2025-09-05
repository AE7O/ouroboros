#!/usr/bin/env python3
"""
Comprehensive evaluation runner for Ouroboros protocol.

Usage:
    python -m ouroboros.evaluation.runner correctness [--trials N] [--verbose]
    python -m ouroboros.evaluation.runner performance [--duration SECONDS] [--warmup SECONDS]
    python -m ouroboros.evaluation.runner security [--exhaustive]
    python -m ouroboros.evaluation.runner pqc [--algorithms ALG1,ALG2] [--sizes SIZE1,SIZE2]
    python -m ouroboros.evaluation.runner all [--quick]
"""

import argparse
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
import traceback

from .results import new_run_root, write_summary
from .sysinfo import capture_system_info
from .experiments import (
    run_correctness_experiments,
    run_performance_experiments,
    run_security_experiments,
    run_pqc_experiments,
    run_comparison_experiments
)


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(prog='runner.py', description='Ouroboros Evaluation Suite')
    subparsers = parser.add_subparsers(dest='command', help='Sub-commands')
    
    # Global options
    parser.add_argument('--output-dir', type=str, 
                       help='Custom output directory (default: auto-generated timestamp)')
    parser.add_argument('--no-charts', action='store_true', help='Disable chart generation')
    parser.add_argument('--format', choices=['csv', 'json', 'both'], default='both',
                       help='Output format for data files')
    
    # Correctness evaluation
    correctness_parser = subparsers.add_parser('correctness',
                                             help='Run correctness tests and analysis')
    correctness_parser.add_argument('--trials', type=int, default=100,
                                   help='Number of test trials (default: 100)')
    correctness_parser.add_argument('--verbose', action='store_true',
                                   help='Verbose output during testing')
    correctness_parser.add_argument('--include-edge-cases', action='store_true',
                                   help='Include edge case testing')
    
    # Performance evaluation
    performance_parser = subparsers.add_parser('performance',
                                             help='Run performance benchmarks')
    performance_parser.add_argument('--duration', type=int, default=30,
                                   help='Duration for each benchmark in seconds (default: 30)')
    performance_parser.add_argument('--warmup', type=int, default=5,
                                   help='Warmup time in seconds (default: 5)')
    performance_parser.add_argument('--packet-sizes', type=str,
                                   default='64,256,1024,1500',
                                   help='Comma-separated packet sizes to test')
    performance_parser.add_argument('--include-memory', action='store_true',
                                   help='Include memory profiling')
    
    # Security evaluation
    security_parser = subparsers.add_parser('security',
                                          help='Run security analysis')
    security_parser.add_argument('--exhaustive', action='store_true',
                                help='Run exhaustive security tests (slower)')
    security_parser.add_argument('--include-timing', action='store_true',
                                help='Include timing attack analysis')
    security_parser.add_argument('--replay-window-size', type=int, default=1000,
                                help='Window size for replay protection tests')
    
    # PQC baseline evaluation
    pqc_parser = subparsers.add_parser('pqc', help='Run post-quantum cryptography comparison')
    pqc_parser.add_argument('--algorithms', type=str, default='kyber768,dilithium2',
                            help='Comma-separated PQC algorithms (e.g., kyber768,dilithium2)')
    pqc_parser.add_argument('--key-sizes', type=str, default='2048,3072',
                            help='Comma-separated RSA key sizes for classical baseline')
    pqc_parser.add_argument('--operations', type=int, default=100,
                            help='Number of operations per algorithm')
    pqc_parser.add_argument('--no-charts', action='store_true',
                            help='Disable chart generation')
    pqc_parser.add_argument('--output-dir', type=str, default=None,
                            help='Output directory (default: new timestamped folder under evaluation_results)')
    pqc_parser.add_argument('--format', type=str, choices=['csv', 'json', 'both'], default='both',
                            help='Output format')

    # Complete evaluation suite
    all_parser = subparsers.add_parser('all',
                                     help='Run complete evaluation suite')
    all_parser.add_argument('--quick', action='store_true',
                           help='Run with reduced parameters for quick testing')
    all_parser.add_argument('--skip-pqc', action='store_true',
                           help='Skip PQC comparison (requires liboqs)')
    
    # Ouroboros vs PQC comparison
    comparison_parser = subparsers.add_parser('comparison',
                                            help='Run Ouroboros vs PQC comparative analysis')
    comparison_parser.add_argument('--duration', type=int, default=5,
                                 help='Duration for benchmarks in seconds (default: 5)')
    comparison_parser.add_argument('--packet-sizes', type=str, default='256,1024',
                                 help='Comma-separated packet sizes to compare')
    comparison_parser.add_argument('--iterations', type=int, default=100,
                                 help='Number of iterations per benchmark (default: 100)')
    
    return parser


def main():
    """Main entry point for the evaluation runner."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Set up output directory
    if args.output_dir:
        output_root = Path(args.output_dir)
        output_root.mkdir(parents=True, exist_ok=True)
    else:
        output_root = new_run_root("evaluation_results")
    
    print(f"🔬 Ouroboros Evaluation Suite")
    print(f"📁 Output directory: {output_root}")
    print(f"⚡ Command: {args.command}")
    print()
    
    # Capture system information
    sysinfo = capture_system_info()
    
    try:
        results = {}
        
        if args.command == 'correctness':
            print("🧪 Running correctness evaluation...")
            results = run_correctness_experiments(
                output_root=output_root,
                trials=args.trials,
                verbose=args.verbose,
                include_edge_cases=args.include_edge_cases,
                format=args.format
            )
            
        elif args.command == 'performance':
            print("⚡ Running performance evaluation...")
            packet_sizes = [int(x.strip()) for x in args.packet_sizes.split(',')]
            results = run_performance_experiments(
                output_root=output_root,
                duration=args.duration,
                warmup=args.warmup,
                packet_sizes=packet_sizes,
                include_memory=args.include_memory,
                format=args.format,
                generate_charts=not args.no_charts
            )
            
        elif args.command == 'security':
            print("🔒 Running security evaluation...")
            results = run_security_experiments(
                output_root=output_root,
                exhaustive=args.exhaustive,
                include_timing=args.include_timing,
                replay_window_size=args.replay_window_size,
                format=args.format
            )
            
        elif args.command == 'pqc':
            print("🔮 Running post-quantum cryptography comparison...")
            algorithms = [x.strip() for x in args.algorithms.split(',')]
            key_sizes = [int(x.strip()) for x in args.key_sizes.split(',')]
            results = run_pqc_experiments(
                output_root=output_root,
                algorithms=algorithms,
                key_sizes=key_sizes,
                operations=args.operations,
                format=args.format,
                generate_charts=not args.no_charts
            )
            
        elif args.command == 'all':
            print("🚀 Running complete evaluation suite...")
            results = run_complete_suite(
                output_root=output_root,
                quick=args.quick,
                skip_pqc=args.skip_pqc,
                format=args.format,
                generate_charts=not args.no_charts
            )
            
        elif args.command == 'comparison':
            print("⚖️  Running Ouroboros vs PQC comparative analysis...")
            packet_sizes = [int(x.strip()) for x in args.packet_sizes.split(',')]
            results = run_comparison_experiments(
                output_root=output_root,
                duration=args.duration,
                packet_sizes=packet_sizes,
                iterations=args.iterations,
                format=args.format,
                generate_charts=not args.no_charts
            )
        
        # Write final summary
        summary_data = {
            'command': args.command,
            'system_info': sysinfo,
            'results_summary': results,
            'output_directory': str(output_root)
        }
        
        write_summary(output_root, f"{args.command}_evaluation", summary_data)
        
        print(f"\n✅ Evaluation complete!")
        print(f"📊 Results saved to: {output_root}")
        print(f"📄 Summary: {output_root}/SUMMARY.md")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Evaluation failed: {e}")
        traceback.print_exc()
        return 1


def run_complete_suite(output_root: Path, quick: bool, skip_pqc: bool,
                      format: str, generate_charts: bool) -> Dict[str, Any]:
    """Run the complete evaluation suite."""
    results = {}
    
    # Adjust parameters for quick mode
    if quick:
        correctness_trials = 30
        performance_duration = 10
        performance_warmup = 5
        pqc_operations = 30
    else:
        correctness_trials = 100
        performance_duration = 30
        performance_warmup = 20
        pqc_operations = 100
    
    # Run correctness evaluation
    print("📋 Phase 1/4: Correctness evaluation...")
    results['correctness'] = run_correctness_experiments(
        output_root=output_root / 'correctness',
        trials=correctness_trials,
        verbose=False,
        include_edge_cases=not quick,
        format=format
    )
    
    # Run performance evaluation
    print("📋 Phase 2/4: Performance evaluation...")
    packet_sizes = [64, 256, 1024, 1500] if not quick else [256, 1024]
    results['performance'] = run_performance_experiments(
        output_root=output_root / 'performance',
        duration=performance_duration,
        warmup=performance_warmup,
        packet_sizes=packet_sizes,
        include_memory=not quick,
        format=format,
        generate_charts=generate_charts
    )
    
    # Run security evaluation
    print("📋 Phase 3/4: Security evaluation...")
    results['security'] = run_security_experiments(
        output_root=output_root / 'security',
        exhaustive=not quick,
        include_timing=not quick,
        replay_window_size=1000 if not quick else 100,
        format=format
    )
    
    # Run PQC comparison (if requested and available)
    if not skip_pqc:
        print("📋 Phase 4/4: Post-quantum cryptography comparison...")
        try:
            algorithms = ['kyber512', 'kyber768', 'dilithium2'] if quick else [
                'kyber512', 'kyber768', 'kyber1024', 'dilithium2', 'dilithium3'
            ]
            results['pqc'] = run_pqc_experiments(
                output_root=output_root / 'pqc',
                algorithms=algorithms,
                key_sizes=[2048, 3072],
                operations=pqc_operations,
                format=format,
                generate_charts=generate_charts
            )
        except Exception as e:
            print(f"⚠️  PQC evaluation failed: {e}")
            results['pqc'] = {'status': 'failed', 'error': str(e)}
    else:
        print("📋 Phase 4/4: Skipped (--skip-pqc)")
        results['pqc'] = {'status': 'skipped', 'reason': 'user requested skip'}
    return results


if __name__ == '__main__':
    sys.exit(main())
