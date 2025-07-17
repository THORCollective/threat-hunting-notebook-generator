# Threat Hunting Notebook Generator

A tool that ingests research articles and converts them into structured threat hunting notebooks based on the PEAK framework.

## PEAK Framework

The PEAK (Prepare, Execute, Act with Knowledge) framework supports three types of hunts:
1. **Hypothesis-Driven Hunts** - Traditional threat hunting based on specific hypotheses
2. **Baseline/Exploratory Hunts** - Data analysis to establish baselines and find anomalies  
3. **Model-Assisted Threat Hunts (M-ATH)** - Machine learning-based threat detection

### Framework Phases
- **Prepare**: Research, topic selection, and hunt planning
- **Execute**: Data analysis and investigation
- **Act**: Documentation, automation, and communication

## Project Structure

```
threat-hunting-notebook-generator/
├── src/
│   ├── ingestion/          # Article parsing and extraction
│   ├── analysis/           # Content analysis and PEAK mapping
│   ├── generation/         # Notebook generation logic
│   └── templates/          # PEAK notebook templates
├── notebooks/              # Generated threat hunting notebooks
├── tests/                  # Test suite
└── examples/               # Sample articles and outputs
```

## Usage

```bash
python -m src.main --input article.pdf --output threat_hunt_notebook.ipynb
```