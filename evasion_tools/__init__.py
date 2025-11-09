"""
Evasion Tools: A comprehensive toolkit for malware evasion.

This package provides multiple functionality-preserving evasion techniques
to evade machine learning-based detection systems.
"""

from .padding_evasion import PaddingEvasion
from .xor_encoding import XOREncoding
from .base64_encoding import Base64Encoding
from .pe_header_manipulation import PEHeaderManipulation
from .dropper_generator import DropperGenerator
from .goodware_collector import GoodwareCollector
from .behavior_verifier import BehaviorVerifier
from .main import MalwareEvasionOrchestrator

__all__ = [
    'PaddingEvasion',
    'XOREncoding',
    'Base64Encoding',
    'PEHeaderManipulation',
    'DropperGenerator',
    'GoodwareCollector',
    'BehaviorVerifier',
    'MalwareEvasionOrchestrator',
]

__version__ = '1.0.0'

