#!/usr/bin/env python3
"""
Test runner script for NVD Parser
Provides convenient ways to run different types of tests
"""

import sys
import subprocess
import argparse
from pathlib import Path

def run_command(cmd, description):
    """Run a command and handle errors"""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print('='*60)
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=False)
        print(f"\n✅ {description} completed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n❌ {description} failed with exit code {e.returncode}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Run NVD Parser tests')
    parser.add_argument('--type', choices=['unit', 'integration', 'all', 'coverage'], 
                       default='all', help='Type of tests to run')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Verbose output')
    parser.add_argument('--html', action='store_true', 
                       help='Generate HTML coverage report')
    
    args = parser.parse_args()
    
    # Base pytest command
    base_cmd = ['python', '-m', 'pytest']
    
    if args.verbose:
        base_cmd.append('-v')
    
    success = True
    
    if args.type == 'unit':
        success = run_command(
            base_cmd + ['test_main.py::TestHelperFunctions', 'test_main.py::TestDataProcessing', 'test_main.py::TestErrorHandling'],
            'Unit Tests'
        )
    
    elif args.type == 'integration':
        success = run_command(
            base_cmd + ['test_main.py::TestAPIEndpoints', 'test_main.py::TestIntegration'],
            'Integration Tests'
        )
    
    elif args.type == 'coverage':
        coverage_cmd = base_cmd + [
            '--cov=src',
            '--cov-report=term-missing',
            '--cov-report=html:htmlcov',
            '--cov-report=xml'
        ]
        success = run_command(coverage_cmd, 'Tests with Coverage')
        
        if success and args.html:
            print("\n📊 HTML coverage report generated in htmlcov/index.html")
    
    else:  # all
        success = run_command(base_cmd + ['test_main.py'], 'All Tests')
    
    if success:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed!")
        sys.exit(1)

if __name__ == '__main__':
    main() 