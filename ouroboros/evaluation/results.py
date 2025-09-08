"""
Results handling and manifest generation for Ouroboros evaluation.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Union
import pandas as pd


def new_run_root(outdir: Path) -> Path:
    """Create a new timestamped results directory."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_root = Path(outdir) / timestamp
    run_root.mkdir(parents=True, exist_ok=True)
    
    # Create subdirectories
    (run_root / "correctness").mkdir(exist_ok=True)
    (run_root / "performance").mkdir(exist_ok=True)
    (run_root / "security").mkdir(exist_ok=True)
    (run_root / "pqc").mkdir(exist_ok=True)
    
    return run_root


def write_data(output_root: Path, filename: str, data: Any, format: str = 'both') -> List[Path]:
    """
    Write data to files in the specified format(s).
    
    Args:
        output_root: Directory to write files
        filename: Base filename (without extension)
        data: Data to write
        format: 'csv', 'json', or 'both'
    
    Returns:
        List of written file paths
    """
    import json
    import csv
    
    output_root.mkdir(parents=True, exist_ok=True)
    written_files = []
    
    if format in ['csv', 'both']:
        csv_path = output_root / f"{filename}.csv"
        try:
            # Try to write as CSV if data is structured appropriately
            if isinstance(data, list) and data and isinstance(data[0], dict):
                # List of dictionaries - write as CSV
                with open(csv_path, 'w', newline='') as f:
                    if data:
                        writer = csv.DictWriter(f, fieldnames=data[0].keys())
                        writer.writeheader()
                        writer.writerows(data)
                written_files.append(csv_path)
            elif isinstance(data, dict):
                # Single dict - try to flatten for CSV
                if all(isinstance(v, (int, float, str, bool)) for v in data.values()):
                    with open(csv_path, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=data.keys())
                        writer.writeheader()
                        writer.writerow(data)
                    written_files.append(csv_path)
        except Exception:
            # If CSV writing fails, skip it
            pass
    
    if format in ['json', 'both'] or not written_files:
        json_path = output_root / f"{filename}.json"
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)  # default=str for datetime objects
        written_files.append(json_path)
    
    return written_files


def _add_to_manifest(run_root: Path, relative_path: Path, description: str):
    """Add file entry to manifest (stored in memory until write_manifest)."""
    manifest_file = run_root / ".manifest_temp.json"
    
    try:
        if manifest_file.exists():
            with open(manifest_file) as f:
                manifest = json.load(f)
        else:
            manifest = {"files": []}
    except:
        manifest = {"files": []}
    
    manifest["files"].append({
        "path": str(relative_path),
        "description": description,
        "created": datetime.now().isoformat()
    })
    
    with open(manifest_file, 'w') as f:
        json.dump(manifest, f, indent=2)


def write_manifest(run_root: Path, sysinfo: Dict[str, Any]):
    """Write the final manifest.json file."""
    manifest_temp = run_root / ".manifest_temp.json"
    manifest_final = run_root / "manifest.json"
    
    try:
        if manifest_temp.exists():
            with open(manifest_temp) as f:
                manifest = json.load(f)
        else:
            manifest = {"files": []}
    except:
        manifest = {"files": []}
    
    manifest["sysinfo"] = sysinfo
    manifest["timestamp"] = datetime.now().isoformat()
    manifest["total_files"] = len(manifest["files"])
    
    with open(manifest_final, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    # Clean up temp file
    if manifest_temp.exists():
        manifest_temp.unlink()


def write_summary(output_root: Path, experiment_name: str, summary_data: Dict[str, Any]) -> Path:
    """Write experiment summary as markdown file."""
    from .sysinfo import get_timestamp
    
    summary_path = output_root / "SUMMARY.md"
    
    with open(summary_path, 'w') as f:
        f.write(f"# Ouroboros Evaluation Results: {experiment_name}\n\n")
        f.write(f"**Generated:** {get_timestamp()}\n")
        f.write(f"**Output Directory:** `{output_root}`\n\n")
        
        # System information
        if 'system_info' in summary_data:
            f.write("## System Information\n\n")
            sysinfo = summary_data['system_info']
            f.write(f"- **Platform:** {sysinfo.get('system', {}).get('platform', 'Unknown')}\n")
            f.write(f"- **Python:** {sysinfo.get('python', {}).get('version', 'Unknown')}\n")
            if 'hardware' in sysinfo and 'cpu' in sysinfo['hardware']:
                cpu = sysinfo['hardware']['cpu']
                f.write(f"- **CPU Cores:** {cpu.get('logical_cores', 'Unknown')}\n")
                f.write(f"- **Memory:** {sysinfo['hardware'].get('memory', {}).get('total_gb', 'Unknown')} GB\n")
            f.write("\n")
        
        # Results summary
        if 'results_summary' in summary_data:
            f.write("## Results Summary\n\n")
            results = summary_data['results_summary']
            
            if 'success_rate' in results:
                f.write(f"- **Success Rate:** {results['success_rate']*100:.1f}%\n")
            
            if 'throughput' in results:
                f.write("- **Throughput Results:**\n")
                for size, data in results['throughput'].items():
                    enc = data.get('encryption', {})
                    if 'throughput_mbps' in enc:
                        f.write(f"  - {size} bytes: {enc['throughput_mbps']:.2f} MB/s\n")
            
            if 'configuration' in results:
                f.write("- **Configuration:**\n")
                config = results['configuration']
                for key, value in config.items():
                    f.write(f"  - {key}: {value}\n")
        
        f.write("\n## Files Generated\n\n")
        
        # List generated files
        for file_path in output_root.glob("**/*"):
            if file_path.is_file() and file_path.name != "SUMMARY.md":
                relative_path = file_path.relative_to(output_root)
                f.write(f"- `{relative_path}`\n")
    
    return summary_path
