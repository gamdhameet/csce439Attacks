# Malware Evasion Project

**Educational University Assignment** - Adversarial Machine Learning for Malware Detection

## 🎯 Project Objective

The goal is to use adversarial techniques to modify malware samples from the `to_be_evaded_ds/` directory to evade detection by various team models, while maintaining the malware's functionality. Target success rate: **50/50 detection score** (50% detected as goodware).

## 📁 Project Structure

```
/home/gamdhameet/Attack/
├── models_v2/models/        # Docker images for detection models (16 teams)
│   ├── team_1.tar
│   ├── team_3.tar
│   ├── team_4.tar ... team_17.tar
├── to_be_evaded_ds/         # Malware samples to be modified (50 samples)
│   ├── 1, 2, 3, ... 50
│   └── sha256sums.txt
└── Readme.md
```

## 🐳 Docker Model Usage

### Loading a Model
Each team's malware detection model is packaged as a Docker tar archive:
```bash
docker load -i models_v2/models/team_<int>.tar
```
Docker will output the image tag (format: `team_<int>`)

### Running a Model
```bash
docker run --rm --memory=1g -p 8080:8080 <image-tag>
```
- Memory limit: 1GB
- Port: 8080
- Auto-remove after execution

### Testing Malware Against Models
Once a model is running, use this command to test samples:
```bash
python -m test -m <malware-file-or-zip> -b <benign-directory>
```

**Example:**
```bash
# Windows reference
python -m test -m MLSEC_2019_samples_and_variants.zip -b C:\Windows\System32\

# Linux equivalent (adjust benign directory as needed)
python -m test -m to_be_evaded_ds/1 -b /usr/bin/
```

**Parameters:**
- `-m`: Path to malware file or zip containing samples
- `-b`: Path to benign software directory (for comparison/baseline)

## 🛠️ Evasion Techniques to Implement

### Basic Techniques
1. **Appending Goodware or Random Data**
   - Changes frequency/distribution of malicious tokens
   - Append to end of sample or resource section
   - Confuses statistical models

2. **PE Header Manipulation**
   - Modify checksums, padding bytes, timestamps
   - Exploits lax OS loader validation
   - Mimics goodware header patterns

3. **Using Packers**
   - Tools: UPX, TeLock, ASPack
   - Changes binary's external appearance
   - Evades signature-based detection

### Intermediate Techniques
4. **Employing Droppers**
   - Embed payload in benign-looking binary
   - Hide in resource sections
   - Functions correctly at runtime, evades static analysis

5. **Mimicry**
   - Imitate known benign apps (e.g., calc.exe, notepad.exe)
   - Can be layered with droppers
   - Matches feature profiles of legitimate software

6. **Dead Code/Imports Insertion**
   - Add non-executed functions, APIs, libraries
   - Inflates benign-looking features
   - Dilutes malicious feature density

### Advanced Obfuscation
7. **XOR or Base64 Encoding**
   - Conceals headers, API strings
   - Creates "gibberish bytes" for static analysis
   - Decoded dynamically at runtime

8. **Adversarial Sampling/Perturbation**
   - Craft feature vectors with strategic perturbations
   - Forces benign classification
   - Model-specific optimization

### ML-Based Approaches
9. **Genetic Algorithms (GA/GAMMA)**
   - Iteratively inject benign content
   - Maximize evasion, minimize payload size
   - Automated variant generation

10. **Generative Adversarial Networks (GANs/Mal-LSGAN)**
    - Generator creates adversarial samples
    - Discriminator acts as surrogate model
    - Continuous improvement loop

11. **Model Poisoning Attacks** *(Advanced)*
    - Inject mislabeled data into training
    - Forces model to learn incorrect patterns
    - Useful if models can be retrained

## 📊 Results Tracking

Save results in **CSV or JSON** format with:
- Sample ID
- Original detection rate
- Modified detection rate
- Technique(s) used
- File size change
- Success/Failure status
- Notes

Example format:
```json
{
  "sample_id": "1",
  "original_score": 0.95,
  "modified_score": 0.42,
  "techniques": ["packer", "header_manipulation"],
  "size_change": "+15%",
  "evaded": true
}
```

## 🔄 Workflow

1. **Setup**: Load Docker models for testing
   ```bash
   docker load -i models_v2/models/team_1.tar
   docker run --rm --memory=1g -p 8080:8080 team_1
   ```

2. **Baseline**: Test original malware samples against models
   ```bash
   python -m test -m to_be_evaded_ds/1 -b /usr/bin/
   ```

3. **Modify**: Apply evasion techniques to samples
   - Create modified copies in separate directory
   - Keep originals intact for comparison

4. **Test**: Run modified samples through models
   ```bash
   python -m test -m modified_samples/1_modified -b /usr/bin/
   ```

5. **Analyze**: Compare scores and track which techniques work
   - Record original vs modified detection scores
   - Note which models were evaded successfully

6. **Iterate**: Combine techniques for better evasion
   - Layer multiple techniques (e.g., packer + header manipulation)
   - Test against multiple team models

7. **Document**: Save all results in structured JSON/CSV format

## 📝 Current Status

- [ ] Set up Docker environment
- [ ] Baseline testing of original samples
- [ ] Implement basic evasion techniques
- [ ] Implement advanced techniques
- [ ] Test against all team models
- [ ] Analyze and document results

## ⚠️ Important Notes

- This is an **educational project** for understanding adversarial ML
- All modifications should be tested in isolated environment
- Track file integrity with SHA256 checksums
- Keep original samples intact
- Document all changes thoroughly