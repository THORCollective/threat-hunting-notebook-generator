"""Jupyter notebook generation for PEAK threat hunting."""

import json
from typing import List, Dict, Any
from datetime import datetime
import nbformat as nbf
from ..analysis.peak_mapper import PEAKHunt, HuntType


class NotebookGenerator:
    """Generates Jupyter notebooks for PEAK threat hunting."""
    
    def __init__(self):
        self.notebook_version = 4
    
    def generate_notebook(self, hunts: List[PEAKHunt], article_data: Dict[str, Any], enable_colab: bool = True) -> nbf.NotebookNode:
        """
        Generate a Jupyter notebook from PEAK hunts.
        
        Args:
            hunts: List of PEAK hunting scenarios
            article_data: Original article data
            enable_colab: Whether to add Google Colab compatibility
            
        Returns:
            Jupyter notebook object
        """
        nb = nbf.v4.new_notebook()
        
        # Add Google Colab metadata if enabled
        if enable_colab:
            self._add_colab_metadata(nb, article_data)
        
        # Add title and metadata
        nb.cells.append(self._create_title_cell(article_data, enable_colab))
        nb.cells.append(self._create_overview_cell(hunts))
        
        # Add Colab setup if enabled
        if enable_colab:
            nb.cells.append(self._create_colab_setup_cell())
        
        nb.cells.append(self._create_imports_cell())
        
        # Add cells for each hunt
        for i, hunt in enumerate(hunts, 1):
            nb.cells.extend(self._create_hunt_cells(hunt, i))
        
        # Add conclusion cell
        nb.cells.append(self._create_conclusion_cell())
        
        return nb
    
    def save_notebook(self, notebook: nbf.NotebookNode, output_path: str):
        """Save notebook to file."""
        with open(output_path, 'w') as f:
            nbf.write(notebook, f)
    
    def generate_colab_url(self, github_repo: str, notebook_path: str) -> str:
        """
        Generate Google Colab URL for a notebook hosted on GitHub.
        
        Args:
            github_repo: GitHub repository in format 'owner/repo'
            notebook_path: Path to notebook within repository
            
        Returns:
            Google Colab URL
        """
        return f"https://colab.research.google.com/github/{github_repo}/blob/main/{notebook_path}"
    
    def _add_colab_metadata(self, nb: nbf.NotebookNode, article_data: Dict[str, Any]):
        """Add Google Colab metadata to notebook."""
        title = article_data.get('title', 'Threat Hunting Notebook')
        
        nb.metadata = {
            "colab": {
                "name": f"{title}.ipynb",
                "provenance": [],
                "collapsed_sections": [],
                "toc_visible": True
            },
            "kernelspec": {
                "display_name": "Python 3",
                "name": "python3"
            },
            "language_info": {
                "name": "python",
                "version": "3.8.10"
            }
        }
    
    def _create_colab_setup_cell(self) -> nbf.NotebookNode:
        """Create Colab-specific setup cell for dependencies."""
        code = """# Google Colab Setup
# This cell installs required packages in Google Colab environment

import sys
IN_COLAB = 'google.colab' in sys.modules

if IN_COLAB:
    print("Running in Google Colab - Installing required packages...")
    !pip install -q pandas numpy matplotlib seaborn nbformat
    
    # Mount Google Drive (optional - uncomment if you want to save results)
    # from google.colab import drive
    # drive.mount('/content/drive')
    
    print("Setup complete!")
else:
    print("Not running in Colab - assuming packages are already installed")"""
        
        return nbf.v4.new_code_cell(code)
    
    def _create_title_cell(self, article_data: Dict[str, Any], enable_colab: bool = False) -> nbf.NotebookNode:
        """Create title cell with article information."""
        title = article_data.get('title', 'Unknown Article')
        source = article_data.get('source', 'Unknown Source')
        generated_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        markdown = f"""# Threat Hunting Notebook: {title}
        
**Source:** {source}  
**Generated:** {generated_date}  
**Framework:** PEAK (Prepare, Execute, Act with Knowledge)"""

        if enable_colab:
            # Generate GitHub repository URL for Colab badge (assumes GitHub hosting)
            repo_url = "https://github.com/your-org/threat-hunting-notebook-generator"
            notebook_path = f"notebooks/{title.replace(' ', '_').lower()}_hunt.ipynb"
            colab_url = f"https://colab.research.google.com/github/your-org/threat-hunting-notebook-generator/blob/main/{notebook_path}"
            
            markdown += f"""

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)]({colab_url})

> **💡 Tip**: Click the "Open in Colab" badge above to run this notebook in Google Colab with zero setup required!"""

        markdown += """

## About This Notebook

This notebook contains threat hunting scenarios generated from the research article using the PEAK framework. Each hunt follows the three-phase PEAK methodology:

- **Prepare:** Research, planning, and hypothesis development
- **Execute:** Data analysis and investigation
- **Act:** Documentation, automation, and communication

---"""
        
        return nbf.v4.new_markdown_cell(markdown)
    
    def _create_overview_cell(self, hunts: List[PEAKHunt]) -> nbf.NotebookNode:
        """Create overview cell with hunt summary."""
        hunt_types = [hunt.hunt_type.value.replace('_', ' ').title() for hunt in hunts]
        
        markdown = f"""## Hunt Overview

This notebook contains **{len(hunts)}** threat hunting scenario(s):

"""
        
        for i, hunt in enumerate(hunts, 1):
            hunt_type = hunt.hunt_type.value.replace('_', ' ').title()
            markdown += f"{i}. **{hunt.title}** ({hunt_type})\n"
        
        markdown += "\n---"
        
        return nbf.v4.new_markdown_cell(markdown)
    
    def _create_imports_cell(self) -> nbf.NotebookNode:
        """Create imports and setup cell."""
        code = """# Required imports and setup
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import json

# Configure plotting
plt.style.use('default')
sns.set_palette("husl")

# Helper functions
def display_hunt_metrics(hunt_name, start_time, end_time, total_events, suspicious_events):
    \"\"\"Display hunt execution metrics.\"\"\"
    duration = end_time - start_time
    print(f"Hunt: {hunt_name}")
    print(f"Duration: {duration}")
    print(f"Total Events Analyzed: {total_events:,}")
    print(f"Suspicious Events: {suspicious_events:,}")
    print(f"Suspicious Rate: {(suspicious_events/total_events)*100:.2f}%")
    print("-" * 40)

print("Threat Hunting Environment Initialized")
print(f"Notebook executed at: {datetime.now()}")"""
        
        return nbf.v4.new_code_cell(code)
    
    def _create_hunt_cells(self, hunt: PEAKHunt, hunt_number: int) -> List[nbf.NotebookNode]:
        """Create cells for a single hunt."""
        cells = []
        
        # Hunt title and description
        cells.append(self._create_hunt_title_cell(hunt, hunt_number))
        
        # Prepare phase
        cells.append(self._create_prepare_phase_cell(hunt))
        cells.append(self._create_prepare_code_cell(hunt))
        
        # Execute phase
        cells.append(self._create_execute_phase_cell(hunt))
        cells.append(self._create_execute_code_cell(hunt))
        
        # Act phase
        cells.append(self._create_act_phase_cell(hunt))
        cells.append(self._create_act_code_cell(hunt))
        
        return cells
    
    def _create_hunt_title_cell(self, hunt: PEAKHunt, hunt_number: int) -> nbf.NotebookNode:
        """Create hunt title cell."""
        hunt_type = hunt.hunt_type.value.replace('_', ' ').title()
        
        markdown = f"""## Hunt {hunt_number}: {hunt.title}

**Hunt Type:** {hunt_type}"""
        
        if hunt.hypothesis:
            markdown += f"\n\n**Hypothesis:** {hunt.hypothesis}"
        
        markdown += f"\n\n**Threat Indicators:** {len(hunt.threat_indicators)} identified"
        
        return nbf.v4.new_markdown_cell(markdown)
    
    def _create_prepare_phase_cell(self, hunt: PEAKHunt) -> nbf.NotebookNode:
        """Create prepare phase documentation cell."""
        markdown = """### 🎯 PREPARE Phase

#### Research Questions"""
        
        for question in hunt.prepare_phase.get('research_questions', []):
            markdown += f"\n- {question}"
        
        markdown += "\n\n#### Data Sources"
        for source in hunt.prepare_phase.get('data_sources', []):
            markdown += f"\n- {source}"
        
        markdown += "\n\n#### Required Tools"
        for tool in hunt.prepare_phase.get('tools_required', []):
            markdown += f"\n- {tool}"
        
        scope = hunt.prepare_phase.get('scope', {})
        if scope:
            markdown += "\n\n#### Hunt Scope"
            for key, value in scope.items():
                markdown += f"\n- **{key.replace('_', ' ').title()}:** {value}"
        
        return nbf.v4.new_markdown_cell(markdown)
    
    def _create_prepare_code_cell(self, hunt: PEAKHunt) -> nbf.NotebookNode:
        """Create prepare phase code cell."""
        code = f"""# PREPARE Phase - Hunt Configuration
hunt_name = "{hunt.title}"
hunt_type = "{hunt.hunt_type.value}"
start_time = datetime.now()

# Hunt parameters
hunt_config = {{
    'time_range': '{hunt.prepare_phase.get('scope', {}).get('time_range', '30 days')}',
    'data_sources': {hunt.prepare_phase.get('data_sources', [])},
    'priority': '{hunt.prepare_phase.get('scope', {}).get('priority', 'Medium')}'
}}

print(f"Configured hunt: {{hunt_name}}")
print(f"Hunt type: {{hunt_type}}")
print(f"Priority: {{hunt_config['priority']}}")
print(f"Data sources: {{', '.join(hunt_config['data_sources'])}}")"""
        
        return nbf.v4.new_code_cell(code)
    
    def _create_execute_phase_cell(self, hunt: PEAKHunt) -> nbf.NotebookNode:
        """Create execute phase documentation cell."""
        markdown = """### 🔍 EXECUTE Phase

#### Analysis Steps"""
        
        for i, step in enumerate(hunt.execute_phase.get('analysis_steps', []), 1):
            markdown += f"\n{i}. {step}"
        
        markdown += "\n\n#### Search Queries"
        markdown += "\n```\n# Add your search queries here\n# Example: process_name:*suspicious* OR event_type:*malicious*\n\n```"
        
        markdown += "\n\n#### Detection Logic"
        markdown += "\n```\n# Add your detection logic here\n# Example: IF condition THEN action\n# IF process_name CONTAINS 'malware' THEN flag_high_priority\n\n```"
        
        return nbf.v4.new_markdown_cell(markdown)
    
    def _create_execute_code_cell(self, hunt: PEAKHunt) -> nbf.NotebookNode:
        """Create execute phase code cell."""
        code = """# EXECUTE Phase - Data Analysis

# Simulated data loading (replace with actual data connectors)
print("Loading data from configured sources...")

# Example: Load network logs
# network_logs = pd.read_csv('network_logs.csv')
# endpoint_logs = pd.read_csv('endpoint_logs.csv')

# Simulated data for demonstration
sample_data = pd.DataFrame({
    'timestamp': pd.date_range(start='2024-01-01', periods=1000, freq='H'),
    'source_ip': np.random.choice(['10.1.1.1', '10.1.1.2', '192.168.1.100'], 1000),
    'destination_ip': np.random.choice(['8.8.8.8', '1.1.1.1', '10.1.1.5'], 1000),
    'process_name': np.random.choice(['chrome.exe', 'powershell.exe', 'cmd.exe'], 1000),
    'event_type': np.random.choice(['process_creation', 'network_connection', 'file_access'], 1000)
})

print(f"Loaded {len(sample_data)} events for analysis")
print("\\nSample data preview:")
print(sample_data.head())

# Apply hunt-specific filters
suspicious_events = sample_data[
    (sample_data['process_name'].str.contains('powershell', case=False)) |
    (sample_data['event_type'] == 'process_creation')
]

print(f"\\nIdentified {len(suspicious_events)} potentially suspicious events")"""
        
        return nbf.v4.new_code_cell(code)
    
    def _create_act_phase_cell(self, hunt: PEAKHunt) -> nbf.NotebookNode:
        """Create act phase documentation cell."""
        markdown = """### 📊 ACT Phase

#### Documentation Requirements"""
        
        doc_template = hunt.act_phase.get('documentation_template', {})
        for key, value in doc_template.items():
            markdown += f"\n- **{key.replace('_', ' ').title()}:** {value}"
        
        markdown += "\n\n#### Automation Opportunities"
        for automation in hunt.act_phase.get('automation_opportunities', []):
            markdown += f"\n- {automation}"
        
        comm_plan = hunt.act_phase.get('communication_plan', {})
        if comm_plan:
            markdown += "\n\n#### Communication Plan"
            for key, value in comm_plan.items():
                markdown += f"\n- **{key.replace('_', ' ').title()}:** {value}"
        
        return nbf.v4.new_markdown_cell(markdown)
    
    def _create_act_code_cell(self, hunt: PEAKHunt) -> nbf.NotebookNode:
        """Create act phase code cell."""
        code = """# ACT Phase - Results Documentation and Automation

end_time = datetime.now()
total_events = len(sample_data)
suspicious_count = len(suspicious_events)

# Display hunt metrics
display_hunt_metrics(hunt_name, start_time, end_time, total_events, suspicious_count)

# Visualize findings
plt.figure(figsize=(12, 8))

# Event timeline
plt.subplot(2, 2, 1)
sample_data.set_index('timestamp')['event_type'].value_counts().plot(kind='bar')
plt.title('Event Types Distribution')
plt.xticks(rotation=45)

# Suspicious events over time
plt.subplot(2, 2, 2)
suspicious_timeline = suspicious_events.groupby(suspicious_events['timestamp'].dt.date).size()
suspicious_timeline.plot(kind='line', marker='o')
plt.title('Suspicious Events Timeline')
plt.xticks(rotation=45)

# Top processes
plt.subplot(2, 2, 3)
sample_data['process_name'].value_counts().head(10).plot(kind='barh')
plt.title('Top Processes')

# Findings summary
plt.subplot(2, 2, 4)
findings_data = ['Total Events', 'Suspicious Events', 'Clean Events']
findings_counts = [total_events, suspicious_count, total_events - suspicious_count]
plt.pie(findings_counts[1:], labels=findings_data[1:], autopct='%1.1f%%')
plt.title('Hunt Results Summary')

plt.tight_layout()
plt.show()

# Generate findings report
findings_report = {
    'hunt_name': hunt_name,
    'execution_time': str(end_time - start_time),
    'total_events_analyzed': total_events,
    'suspicious_events_found': suspicious_count,
    'false_positive_rate': 'TBD - Requires validation',
    'recommendations': [
        'Validate suspicious events with additional context',
        'Implement automated alerting for confirmed indicators',
        'Schedule regular execution of successful hunt queries'
    ]
}

print("\\n" + "="*50)
print("HUNT FINDINGS REPORT")
print("="*50)
for key, value in findings_report.items():
    if isinstance(value, list):
        print(f"{key.upper()}:")
        for item in value:
            print(f"  - {item}")
    else:
        print(f"{key.upper()}: {value}")"""
        
        return nbf.v4.new_code_cell(code)
    
    def _create_conclusion_cell(self) -> nbf.NotebookNode:
        """Create conclusion cell."""
        markdown = """## 📋 Conclusion

This threat hunting notebook has been generated based on the PEAK framework methodology. Each hunt scenario provides:

1. **Structured approach** following PEAK phases (Prepare, Execute, Act)
2. **Actionable search queries** and detection logic
3. **Visualization capabilities** for findings analysis
4. **Documentation templates** for reporting and communication

### Next Steps

1. **Customize data sources** - Replace simulated data with your actual security logs
2. **Validate findings** - Review and confirm any suspicious activities identified
3. **Implement automation** - Convert successful hunts into automated detection rules
4. **Schedule regular execution** - Run hunts periodically to maintain security posture

### Knowledge Integration

The Knowledge component of PEAK is integrated throughout each hunt scenario:
- Threat intelligence from the source research
- Organizational context and business knowledge
- Technical expertise and hunting experience
- Findings from previous hunt iterations

---
*Generated using PEAK Threat Hunting Framework*"""
        
        return nbf.v4.new_markdown_cell(markdown)