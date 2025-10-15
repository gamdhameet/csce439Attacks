# Malware Evasion - Batch Testing Framework

## Quick Start

### Step 1: Create Modified Samples
Apply all 8 evasion techniques to all 50 malware samples:

```bash
python 1_create_modified_samples.py
```

This creates modified samples organized by technique:
- `modified_samples/append_random/` - 50 samples with random data appended
- `modified_samples/pe_header/` - 50 samples with modified PE headers
- `modified_samples/packer/` - 50 samples packed with UPX
- `modified_samples/dropper/` - 50 samples embedded in benign binaries
- `modified_samples/mimicry/` - 50 samples mimicking benign files
- `modified_samples/dead_code/` - 50 samples with junk code injected
- `modified_samples/xor_encoding/` - 50 samples XOR encoded
- `modified_samples/combined/` - 50 samples with multiple techniques

### Step 2: Batch Test Against All Models (Parallel)
Test all modified samples against all models (except broken team_15):

```bash
python 2_batch_test_models.py
```

**Parallel Testing:**
- Loads all 15 models simultaneously on different ports (8080-8094)
- Tests each sample against all models in parallel using threading
- Dramatically faster than sequential testing
- Optimized for systems with sufficient RAM (15 models × 1GB = ~15GB)

**Output:**
- Location: `results/technique_scores_TIMESTAMP.csv`
- Columns: technique, team_3, team_4, ..., team_17, avg_evaded_per_team, total_samples
- Shows evasion score (evaded/total) for each technique against each team

## Results Format

CSV output includes:
- **technique**: Which evasion technique was used
- **team_X**: Score as "evaded_count/total_samples" (e.g., "30/50" means 30 evaded, 20 detected)
- **avg_evaded_per_team**: Average number of samples that evaded across all teams
- **total_samples**: Total samples tested (always 50)

**Scoring**: Higher evaded count = better evasion
- Example: "30/50" = 30 samples evaded detection (60% evasion rate)

## Techniques Implemented

1. **append_random** - Append 50KB random data
2. **pe_header** - Modify PE headers (timestamp, checksum)
3. **packer** - UPX compression
4. **dropper** - Embed in benign binary (/usr/bin/ls)
5. **mimicry** - Mimic benign file characteristics
6. **dead_code** - Insert 20KB junk code
7. **xor_encoding** - XOR encode partial file
8. **combined** - Multi-technique (append + PE header + dead code)

## Directory Structure

```
Attack/
├── 1_create_modified_samples.py   # Create all modified samples
├── 2_batch_test_models.py         # Batch test against models
├── evasion_tools/                 # Technique implementations
├── to_be_evaded_ds/               # Original 50 malware samples
├── modified_samples/              # Modified samples by technique
│   ├── append_random/
│   ├── pe_header/
│   ├── packer/
│   ├── dropper/
│   ├── mimicry/
│   ├── dead_code/
│   ├── xor_encoding/
│   └── combined/
└── results/                       # CSV test results
```

## Time Estimates

- Step 1 (Create samples): ~5-10 minutes (50 samples × 8 techniques)
- Step 2 (Parallel batch test): ~30-60 minutes (400 samples, 15 models in parallel)
  - Sequential would take: ~8-12 hours
  - Parallel speedup: ~10-15x faster!

## Notes

- Team_15 model is broken and excluded from testing
- All 15 remaining models are tested for each sample
- Results are saved incrementally to CSV
- Docker containers are auto-managed (start/stop)

