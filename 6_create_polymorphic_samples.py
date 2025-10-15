#!/usr/bin/env python3
"""
Polymorphic Adversarial Sample Generation Script

This script generates adversarial malware samples using the advanced polymorphic
dual evasion technique, specifically designed to evade:

1. Raw Byte Models (MalConv, byte n-gram models)
   - Via XOR payload encoding
   - Corrupts learned byte frequency distributions
   
2. Feature-Based Models (TF-IDF, static feature extractors)
   - Via dead import injection
   - Dilutes malicious feature weights in feature vectors

The technique ensures functional preservation while maximizing attack transference
across different ML detector architectures.
"""

import sys
import json
import csv
from pathlib import Path
from datetime import datetime
import logging

sys.path.insert(0, str(Path(__file__).parent))
from evasion_tools.polymorphic_dual_evasion import (
    polymorphic_dual_evasion,
    batch_generate_polymorphic_variants,
    analyze_evasion_effectiveness
)

# Configuration
MALWARE_DIR = Path("/home/gamdhameet/Attack/to_be_evaded_ds")
OUTPUT_BASE = Path("/home/gamdhameet/Attack/modified_samples")
RESULTS_DIR = Path("/home/gamdhameet/Attack/results")
LOG_FILE = Path("/home/gamdhameet/Attack/polymorphic_generation.log")

# Create output directories
OUTPUT_DIRS = {
    'polymorphic_low': OUTPUT_BASE / 'polymorphic_low',
    'polymorphic_medium': OUTPUT_BASE / 'polymorphic_medium',
    'polymorphic_high': OUTPUT_BASE / 'polymorphic_high',
    'polymorphic_variants': OUTPUT_BASE / 'polymorphic_variants'
}

for dir_path in OUTPUT_DIRS.values():
    dir_path.mkdir(parents=True, exist_ok=True)

RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def generate_single_intensity_samples(intensity_level='high'):
    """
    Generate polymorphic samples with specified intensity level.
    
    Args:
        intensity_level: 'low', 'medium', or 'high'
    """
    output_dir = OUTPUT_DIRS[f'polymorphic_{intensity_level}']
    results = []
    
    logger.info(f"=" * 80)
    logger.info(f"Generating {intensity_level.upper()} intensity polymorphic samples")
    logger.info(f"=" * 80)
    
    for sample_id in range(1, 51):
        sample_path = MALWARE_DIR / str(sample_id)
        
        if not sample_path.exists():
            logger.warning(f"Sample {sample_id} not found, skipping...")
            continue
        
        output_file = output_dir / f"{sample_id}.exe"
        
        logger.info(f"\nProcessing sample {sample_id}/50...")
        
        try:
            result = polymorphic_dual_evasion(
                str(sample_path),
                str(output_file),
                encoding_intensity=intensity_level,
                import_intensity=intensity_level
            )
            
            # Add sample metadata
            result['sample_id'] = sample_id
            result['intensity'] = intensity_level
            result['output_file'] = str(output_file)
            
            results.append(result)
            
            logger.info(f"  ✓ Generated: {output_file.name}")
            logger.info(f"    Encoding: {result['encoding']['scheme']}")
            logger.info(f"    Imports: {result['dead_imports']['count']}")
            logger.info(f"    Size: {result['original_size']} → {result['final_size']} bytes")
            
        except Exception as e:
            logger.error(f"  ✗ Failed for sample {sample_id}: {e}")
            results.append({
                'sample_id': sample_id,
                'intensity': intensity_level,
                'success': False,
                'error': str(e)
            })
    
    return results


def generate_polymorphic_variants_all_samples(variants_per_sample=3):
    """
    Generate multiple polymorphic variants for each malware sample.
    This demonstrates the polymorphic capability and uniqueness.
    
    Args:
        variants_per_sample: Number of variants to generate per sample
    """
    results = []
    
    logger.info(f"=" * 80)
    logger.info(f"Generating {variants_per_sample} polymorphic variants per sample")
    logger.info(f"=" * 80)
    
    for sample_id in range(1, 51):
        sample_path = MALWARE_DIR / str(sample_id)
        
        if not sample_path.exists():
            logger.warning(f"Sample {sample_id} not found, skipping...")
            continue
        
        output_dir = OUTPUT_DIRS['polymorphic_variants'] / f"sample_{sample_id}"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"\nProcessing sample {sample_id}/50 ({variants_per_sample} variants)...")
        
        try:
            variant_results = batch_generate_polymorphic_variants(
                str(sample_path),
                str(output_dir),
                variant_count=variants_per_sample
            )
            
            # Add sample metadata
            for i, result in enumerate(variant_results):
                result['sample_id'] = sample_id
                result['output_file'] = str(output_dir / f"variant_{i+1}.exe")
                results.append(result)
            
            logger.info(f"  ✓ Generated {len(variant_results)} variants for sample {sample_id}")
            
            # Show diversity metrics
            signatures = [r['polymorphic_signature'] for r in variant_results]
            logger.info(f"    Unique signatures: {len(set(signatures))}/{len(signatures)}")
            
        except Exception as e:
            logger.error(f"  ✗ Failed for sample {sample_id}: {e}")
    
    return results


def analyze_all_samples(intensity_level='high'):
    """
    Perform evasion effectiveness analysis on all generated samples.
    
    Args:
        intensity_level: Intensity level to analyze
    """
    output_dir = OUTPUT_DIRS[f'polymorphic_{intensity_level}']
    analysis_results = []
    
    logger.info(f"\n" + "=" * 80)
    logger.info(f"Analyzing evasion effectiveness ({intensity_level} intensity)")
    logger.info(f"=" * 80)
    
    for sample_id in range(1, 51):
        original_file = MALWARE_DIR / str(sample_id)
        modified_file = output_dir / f"{sample_id}.exe"
        
        if not original_file.exists() or not modified_file.exists():
            continue
        
        try:
            analysis = analyze_evasion_effectiveness(
                str(original_file),
                str(modified_file)
            )
            
            analysis['sample_id'] = sample_id
            analysis['intensity'] = intensity_level
            analysis_results.append(analysis)
            
            logger.info(f"Sample {sample_id}: "
                       f"Raw evasion={analysis['evasion_score']['raw_byte_evasion']:.1%}, "
                       f"Feature evasion={analysis['evasion_score']['feature_evasion']:.1%}")
            
        except Exception as e:
            logger.error(f"Analysis failed for sample {sample_id}: {e}")
    
    return analysis_results


def save_results_to_csv(results, output_file):
    """Save results to CSV file for analysis."""
    if not results:
        logger.warning("No results to save")
        return
    
    # Filter successful results
    successful_results = [r for r in results if r.get('success', True)]
    
    if not successful_results:
        logger.warning("No successful results to save")
        return
    
    csv_path = RESULTS_DIR / output_file
    
    with open(csv_path, 'w', newline='') as f:
        # Extract all possible keys
        all_keys = set()
        for result in successful_results:
            all_keys.update(result.keys())
            if 'encoding' in result:
                all_keys.update([f"encoding_{k}" for k in result['encoding'].keys()])
            if 'dead_imports' in result:
                all_keys.update([f"dead_imports_{k}" for k in result['dead_imports'].keys()])
        
        # Create flattened rows
        rows = []
        for result in successful_results:
            row = {
                'sample_id': result.get('sample_id', 'N/A'),
                'technique': result.get('technique', 'N/A'),
                'intensity': result.get('intensity', 'N/A'),
                'original_size': result.get('original_size', 0),
                'final_size': result.get('final_size', 0),
                'size_increase': result.get('size_increase', 0),
                'size_increase_ratio': result.get('size_increase_ratio', 0),
                'polymorphic_signature': result.get('polymorphic_signature', 'N/A'),
            }
            
            # Add encoding details
            if 'encoding' in result:
                row['encoding_scheme'] = result['encoding'].get('scheme', 'N/A')
                row['encoding_bytes'] = result['encoding'].get('bytes_encoded', 0)
                row['encoding_ratio'] = result['encoding'].get('encoding_ratio', 0)
            
            # Add import details
            if 'dead_imports' in result:
                row['imports_count'] = result['dead_imports'].get('count', 0)
                row['imports_bytes'] = result['dead_imports'].get('bytes_added', 0)
                row['feature_dilution'] = result['dead_imports'].get('feature_dilution_ratio', 0)
            
            rows.append(row)
        
        if rows:
            fieldnames = list(rows[0].keys())
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
            
            logger.info(f"Results saved to: {csv_path}")


def save_analysis_to_csv(analysis_results, output_file):
    """Save analysis results to CSV."""
    if not analysis_results:
        logger.warning("No analysis results to save")
        return
    
    csv_path = RESULTS_DIR / output_file
    
    rows = []
    for analysis in analysis_results:
        row = {
            'sample_id': analysis.get('sample_id', 'N/A'),
            'intensity': analysis.get('intensity', 'N/A'),
            
            # Byte analysis
            'original_entropy': analysis['byte_analysis']['original_entropy'],
            'modified_entropy': analysis['byte_analysis']['modified_entropy'],
            'entropy_delta': analysis['byte_analysis']['entropy_delta'],
            'new_byte_patterns': analysis['byte_analysis']['new_byte_patterns'],
            
            # Feature analysis
            'feature_divergence': analysis['feature_analysis']['feature_divergence'],
            'original_features': analysis['feature_analysis']['original_feature_count'],
            'modified_features': analysis['feature_analysis']['modified_feature_count'],
            
            # Size analysis
            'original_size': analysis['size_analysis']['original_size'],
            'modified_size': analysis['size_analysis']['modified_size'],
            
            # Evasion scores
            'raw_byte_evasion': analysis['evasion_score']['raw_byte_evasion'],
            'feature_evasion': analysis['evasion_score']['feature_evasion'],
            'overall_evasion': analysis['evasion_score']['overall_evasion'],
        }
        rows.append(row)
    
    with open(csv_path, 'w', newline='') as f:
        if rows:
            fieldnames = list(rows[0].keys())
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
            
            logger.info(f"Analysis results saved to: {csv_path}")


def generate_summary_report(all_results):
    """Generate a comprehensive summary report."""
    logger.info(f"\n" + "=" * 80)
    logger.info("POLYMORPHIC DUAL EVASION - SUMMARY REPORT")
    logger.info("=" * 80)
    
    successful = [r for r in all_results if r.get('success', True)]
    failed = [r for r in all_results if not r.get('success', True)]
    
    logger.info(f"\nGeneration Statistics:")
    logger.info(f"  Total samples processed: {len(all_results)}")
    logger.info(f"  Successful: {len(successful)}")
    logger.info(f"  Failed: {len(failed)}")
    logger.info(f"  Success rate: {len(successful)/len(all_results)*100:.1f}%")
    
    if successful:
        # Encoding statistics
        encoding_schemes = {}
        for r in successful:
            if 'encoding' in r:
                scheme = r['encoding'].get('scheme', 'unknown')
                encoding_schemes[scheme] = encoding_schemes.get(scheme, 0) + 1
        
        logger.info(f"\nEncoding Schemes Used:")
        for scheme, count in encoding_schemes.items():
            logger.info(f"  {scheme}: {count} samples")
        
        # Size statistics
        avg_original = sum(r.get('original_size', 0) for r in successful) / len(successful)
        avg_final = sum(r.get('final_size', 0) for r in successful) / len(successful)
        avg_increase = avg_final - avg_original
        
        logger.info(f"\nSize Statistics:")
        logger.info(f"  Average original size: {avg_original:,.0f} bytes")
        logger.info(f"  Average final size: {avg_final:,.0f} bytes")
        logger.info(f"  Average size increase: {avg_increase:,.0f} bytes ({avg_increase/avg_original*100:.1f}%)")
        
        # Import statistics
        avg_imports = sum(r['dead_imports'].get('count', 0) for r in successful if 'dead_imports' in r) / len(successful)
        logger.info(f"\nDead Import Statistics:")
        logger.info(f"  Average imports injected: {avg_imports:.0f}")
        
        # Polymorphic diversity
        unique_sigs = len(set(r.get('polymorphic_signature', '') for r in successful if r.get('polymorphic_signature')))
        logger.info(f"\nPolymorphic Diversity:")
        logger.info(f"  Unique signatures: {unique_sigs}/{len(successful)}")
    
    logger.info(f"\n" + "=" * 80)


def main():
    """Main execution flow."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Generate polymorphic adversarial malware samples',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate high-intensity samples
  python 6_create_polymorphic_samples.py --mode high
  
  # Generate all intensity levels
  python 6_create_polymorphic_samples.py --mode all
  
  # Generate polymorphic variants
  python 6_create_polymorphic_samples.py --mode variants --variants 5
  
  # Generate and analyze
  python 6_create_polymorphic_samples.py --mode high --analyze
        """
    )
    
    parser.add_argument('--mode', choices=['low', 'medium', 'high', 'all', 'variants'],
                       default='high',
                       help='Generation mode (default: high)')
    parser.add_argument('--variants', type=int, default=3,
                       help='Number of variants per sample (for variants mode, default: 3)')
    parser.add_argument('--analyze', action='store_true',
                       help='Perform evasion effectiveness analysis')
    
    args = parser.parse_args()
    
    start_time = datetime.now()
    all_results = []
    
    logger.info(f"=" * 80)
    logger.info(f"POLYMORPHIC DUAL EVASION SAMPLE GENERATOR")
    logger.info(f"Start time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"=" * 80)
    
    # Generate samples based on mode
    if args.mode == 'all':
        # Generate all intensity levels
        for intensity in ['low', 'medium', 'high']:
            results = generate_single_intensity_samples(intensity)
            all_results.extend(results)
            
            # Save results
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            save_results_to_csv(results, f'polymorphic_{intensity}_{timestamp}.csv')
            
            # Analyze if requested
            if args.analyze:
                analysis = analyze_all_samples(intensity)
                save_analysis_to_csv(analysis, f'polymorphic_analysis_{intensity}_{timestamp}.csv')
    
    elif args.mode == 'variants':
        # Generate polymorphic variants
        results = generate_polymorphic_variants_all_samples(args.variants)
        all_results.extend(results)
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        save_results_to_csv(results, f'polymorphic_variants_{timestamp}.csv')
    
    else:
        # Generate single intensity level
        results = generate_single_intensity_samples(args.mode)
        all_results.extend(results)
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        save_results_to_csv(results, f'polymorphic_{args.mode}_{timestamp}.csv')
        
        # Analyze if requested
        if args.analyze:
            analysis = analyze_all_samples(args.mode)
            save_analysis_to_csv(analysis, f'polymorphic_analysis_{args.mode}_{timestamp}.csv')
    
    # Generate summary report
    generate_summary_report(all_results)
    
    # Final summary
    end_time = datetime.now()
    duration = end_time - start_time
    
    logger.info(f"\n" + "=" * 80)
    logger.info(f"EXECUTION COMPLETE")
    logger.info(f"End time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Duration: {duration}")
    logger.info(f"Log file: {LOG_FILE}")
    logger.info(f"=" * 80)


if __name__ == "__main__":
    main()
