"""
AWS CIS Controls Compliance Assessment Framework

A production-ready, enterprise-grade framework for evaluating AWS account configurations against
CIS Controls Implementation Groups (IG1, IG2, IG3). Implements 199 unique AWS Config rule assessments
across all implementation groups covering 40 CIS Controls v8.1 safeguards.

Coverage (cumulative):
  - IG1: 24 of 56 safeguards (42.9%) with 122 rules
  - IG2: 27 of 74 safeguards (36.5%) with 75 rules (includes IG1)
  - IG3: 30 of 153 safeguards (19.6%) with 13 rules (includes IG1+IG2)
"""

__version__ = "1.2.5"
__author__ = "AWS CIS Assessment Team"
__description__ = "Production-ready AWS CIS Controls Compliance Assessment Framework with Enhanced IG1 Coverage"