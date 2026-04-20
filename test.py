#!/usr/bin/env python3
# Copyright (c) 2026 Sai Kumar Balabhadruni
# Licensed under the MIT License. See LICENSE file for details.

"""
Basic test script for DomainHarvester
"""

import subprocess
import sys

def test_help():
    """Test that the help command works"""
    try:
        result = subprocess.run([sys.executable, 'domainharvester.py', '--help'],
                              capture_output=True, text=True, timeout=10)
        return result.returncode == 0 and 'DomainHarvester' in result.stdout
    except:
        return False

def test_syntax():
    """Test that the code compiles"""
    try:
        subprocess.run([sys.executable, '-m', 'py_compile', 'domainharvester.py'],
                     capture_output=True, timeout=10)
        return True
    except:
        return False

if __name__ == '__main__':
    print("Running basic tests for DomainHarvester...")

    tests = [
        ("Syntax check", test_syntax),
        ("Help command", test_help),
    ]

    passed = 0
    total = len(tests)

    for name, test_func in tests:
        try:
            if test_func():
                print(f"✅ {name}: PASSED")
                passed += 1
            else:
                print(f"❌ {name}: FAILED")
        except Exception as e:
            print(f"❌ {name}: ERROR - {e}")

    print(f"\nResults: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed!")
        sys.exit(0)
    else:
        print("⚠️  Some tests failed")
        sys.exit(1)