"""PEAK framework mapping and analysis logic."""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class HuntType(Enum):
    """Types of PEAK hunts."""
    HYPOTHESIS_DRIVEN = "hypothesis_driven"
    BASELINE_EXPLORATORY = "baseline_exploratory"
    MODEL_ASSISTED = "model_assisted"


@dataclass
class ThreatIndicator:
    """Represents a threat indicator extracted from research."""
    indicator_type: str  # IOC, TTP, behavior, etc.
    value: str
    context: str
    confidence: float


@dataclass
class PEAKHunt:
    """Represents a PEAK hunting scenario."""
    hunt_type: HuntType
    title: str
    hypothesis: Optional[str]
    prepare_phase: Dict[str, Any]
    execute_phase: Dict[str, Any]
    act_phase: Dict[str, Any]
    knowledge_base: List[str]
    threat_indicators: List[ThreatIndicator]


class PEAKMapper:
    """Maps research content to PEAK framework components."""
    
    def __init__(self):
        self.threat_patterns = {
            'malware': r'\b(?:malware|trojan|virus|ransomware|rootkit|backdoor)\b',
            'apt': r'\b(?:APT\d+|advanced persistent threat|nation-state)\b',
            'iocs': r'\b(?:hash|md5|sha1|sha256|ip address|domain|url|registry key)\b',
            'ttps': r'\b(?:MITRE|ATT&CK|T\d{4}|technique|tactic|procedure)\b',
            'tools': r'\b(?:cobalt strike|metasploit|powershell|empire|mimikatz)\b',
            'behaviors': r'\b(?:lateral movement|privilege escalation|persistence|exfiltration|command and control)\b'
        }
        
        self.data_sources = [
            'network logs', 'endpoint logs', 'dns logs', 'proxy logs',
            'windows event logs', 'sysmon', 'process logs', 'file system',
            'registry', 'memory dumps', 'packet captures'
        ]
    
    def analyze_article(self, article_data: Dict[str, Any]) -> List[PEAKHunt]:
        """
        Analyze article content and generate PEAK hunting scenarios.
        
        Args:
            article_data: Parsed article data from ArticleParser
            
        Returns:
            List of PEAK hunting scenarios
        """
        content = article_data.get('content', '')
        title = article_data.get('title', 'Unknown')
        
        # Extract threat indicators
        indicators = self._extract_threat_indicators(content)
        
        # Determine hunt types based on content
        hunt_types = self._determine_hunt_types(content, indicators)
        
        # Generate PEAK hunts
        hunts = []
        for hunt_type in hunt_types:
            hunt = self._create_peak_hunt(hunt_type, title, content, indicators)
            hunts.append(hunt)
        
        return hunts
    
    def _extract_threat_indicators(self, content: str) -> List[ThreatIndicator]:
        """Extract threat indicators from article content."""
        indicators = []
        
        for category, pattern in self.threat_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Get surrounding context
                start = max(0, match.start() - 100)
                end = min(len(content), match.end() + 100)
                context = content[start:end].strip()
                
                indicator = ThreatIndicator(
                    indicator_type=category,
                    value=match.group(),
                    context=context,
                    confidence=0.7  # Base confidence
                )
                indicators.append(indicator)
        
        return indicators
    
    def _determine_hunt_types(self, content: str, indicators: List[ThreatIndicator]) -> List[HuntType]:
        """Determine appropriate hunt types based on content analysis."""
        hunt_types = []
        
        # Check for hypothesis-driven indicators
        if any(ind.indicator_type in ['apt', 'ttps', 'tools'] for ind in indicators):
            hunt_types.append(HuntType.HYPOTHESIS_DRIVEN)
        
        # Check for baseline/exploratory indicators
        if any(ind.indicator_type in ['behaviors', 'malware'] for ind in indicators):
            hunt_types.append(HuntType.BASELINE_EXPLORATORY)
        
        # Check for model-assisted indicators
        if re.search(r'\b(?:anomaly|pattern|clustering|machine learning|ai|algorithm)\b', content, re.IGNORECASE):
            hunt_types.append(HuntType.MODEL_ASSISTED)
        
        # Default to hypothesis-driven if no specific indicators
        if not hunt_types:
            hunt_types.append(HuntType.HYPOTHESIS_DRIVEN)
        
        return hunt_types
    
    def _create_peak_hunt(self, hunt_type: HuntType, title: str, content: str, 
                         indicators: List[ThreatIndicator]) -> PEAKHunt:
        """Create a PEAK hunt structure for the given type."""
        
        # Generate hypothesis for hypothesis-driven hunts
        hypothesis = None
        if hunt_type == HuntType.HYPOTHESIS_DRIVEN:
            hypothesis = self._generate_hypothesis(indicators, content)
        
        # Build prepare phase
        prepare_phase = {
            'research_questions': self._generate_research_questions(hunt_type, indicators),
            'data_sources': self._identify_data_sources(indicators),
            'tools_required': self._identify_tools(hunt_type),
            'scope': self._define_scope(indicators)
        }
        
        # Build execute phase
        execute_phase = {
            'search_queries': self._generate_search_queries(indicators),
            'analysis_steps': self._generate_analysis_steps(hunt_type, indicators),
            'detection_logic': self._generate_detection_logic(indicators)
        }
        
        # Build act phase
        act_phase = {
            'documentation_template': self._create_documentation_template(),
            'automation_opportunities': self._identify_automation(indicators),
            'communication_plan': self._create_communication_plan()
        }
        
        # Build knowledge base
        knowledge_base = self._extract_knowledge_elements(content, indicators)
        
        return PEAKHunt(
            hunt_type=hunt_type,
            title=f"{title} - {hunt_type.value.replace('_', ' ').title()} Hunt",
            hypothesis=hypothesis,
            prepare_phase=prepare_phase,
            execute_phase=execute_phase,
            act_phase=act_phase,
            knowledge_base=knowledge_base,
            threat_indicators=indicators
        )
    
    def _generate_hypothesis(self, indicators: List[ThreatIndicator], content: str) -> str:
        """Generate hunting hypothesis based on indicators."""
        threat_types = [ind.indicator_type for ind in indicators]
        
        if 'apt' in threat_types:
            return "Advanced persistent threat actors may be conducting targeted attacks in our environment"
        elif 'malware' in threat_types:
            return "Malicious software may be present and executing in our environment"
        elif 'ttps' in threat_types:
            return "Attackers may be using known tactics, techniques, and procedures to compromise our systems"
        else:
            return "Suspicious activities may be occurring that warrant investigation"
    
    def _generate_research_questions(self, hunt_type: HuntType, indicators: List[ThreatIndicator]) -> List[str]:
        """Generate research questions for the prepare phase."""
        questions = [
            "What are the key threat indicators to search for?",
            "Which data sources contain relevant information?",
            "What is the expected attack timeline?",
            "What are the potential false positive scenarios?"
        ]
        
        if hunt_type == HuntType.MODEL_ASSISTED:
            questions.extend([
                "What machine learning models are appropriate?",
                "What features should be extracted for analysis?",
                "How will model performance be evaluated?"
            ])
        
        return questions
    
    def _identify_data_sources(self, indicators: List[ThreatIndicator]) -> List[str]:
        """Identify relevant data sources based on indicators."""
        sources = set()
        
        for indicator in indicators:
            if indicator.indicator_type in ['malware', 'tools']:
                sources.update(['endpoint logs', 'process logs', 'sysmon'])
            elif indicator.indicator_type == 'behaviors':
                sources.update(['network logs', 'windows event logs'])
            elif indicator.indicator_type == 'iocs':
                sources.update(['dns logs', 'proxy logs', 'network logs'])
        
        return list(sources) if sources else ['network logs', 'endpoint logs']
    
    def _identify_tools(self, hunt_type: HuntType) -> List[str]:
        """Identify tools required for the hunt."""
        base_tools = ['SIEM', 'Log analysis tools', 'Network monitoring']
        
        if hunt_type == HuntType.MODEL_ASSISTED:
            base_tools.extend(['Machine learning platform', 'Statistical analysis tools'])
        
        return base_tools
    
    def _define_scope(self, indicators: List[ThreatIndicator]) -> Dict[str, str]:
        """Define hunt scope based on indicators."""
        return {
            'time_range': '30 days',
            'network_segments': 'All internal networks',
            'systems': 'Critical infrastructure and user workstations',
            'priority': 'High' if any(ind.indicator_type == 'apt' for ind in indicators) else 'Medium'
        }
    
    def _generate_search_queries(self, indicators: List[ThreatIndicator]) -> List[str]:
        """Generate search queries for the execute phase."""
        queries = []
        
        for indicator in indicators:
            if indicator.indicator_type == 'malware':
                queries.append(f"process_name:*{indicator.value}* OR file_name:*{indicator.value}*")
            elif indicator.indicator_type == 'behaviors':
                queries.append(f"event_type:{indicator.value} OR description:*{indicator.value}*")
        
        return queries if queries else ["event_type:process_creation", "event_type:network_connection"]
    
    def _generate_analysis_steps(self, hunt_type: HuntType, indicators: List[ThreatIndicator]) -> List[str]:
        """Generate analysis steps for the execute phase."""
        steps = [
            "Collect and preprocess relevant log data",
            "Apply initial filters based on threat indicators",
            "Analyze temporal patterns and correlations",
            "Investigate anomalous activities"
        ]
        
        if hunt_type == HuntType.MODEL_ASSISTED:
            steps.extend([
                "Apply machine learning models for anomaly detection",
                "Validate model predictions with domain expertise"
            ])
        
        return steps
    
    def _generate_detection_logic(self, indicators: List[ThreatIndicator]) -> List[str]:
        """Generate detection logic based on indicators."""
        logic = []
        
        for indicator in indicators:
            if indicator.indicator_type == 'malware':
                logic.append(f"IF process_name CONTAINS '{indicator.value}' THEN flag_high_priority")
            elif indicator.indicator_type == 'behaviors':
                logic.append(f"IF behavior MATCHES '{indicator.value}' THEN investigate_further")
        
        return logic if logic else ["IF anomalous_activity THEN investigate"]
    
    def _create_documentation_template(self) -> Dict[str, str]:
        """Create documentation template for the act phase."""
        return {
            'findings_summary': 'Summary of hunt findings and conclusions',
            'evidence_collected': 'Description of evidence and artifacts',
            'recommendations': 'Actionable recommendations for security team',
            'lessons_learned': 'Key insights from the hunting process'
        }
    
    def _identify_automation(self, indicators: List[ThreatIndicator]) -> List[str]:
        """Identify automation opportunities."""
        return [
            "Automated alerting for confirmed indicators",
            "Scheduled execution of successful hunt queries",
            "Integration with SOAR platform for response actions"
        ]
    
    def _create_communication_plan(self) -> Dict[str, str]:
        """Create communication plan for the act phase."""
        return {
            'stakeholders': 'Security team, IT operations, management',
            'reporting_format': 'Executive summary with technical details',
            'escalation_criteria': 'Confirmed threats or critical vulnerabilities',
            'follow_up_actions': 'Remediation tracking and validation'
        }
    
    def _extract_knowledge_elements(self, content: str, indicators: List[ThreatIndicator]) -> List[str]:
        """Extract knowledge elements from content."""
        knowledge = []
        
        # Extract key concepts and facts
        sentences = content.split('.')
        for sentence in sentences:
            if any(pattern in sentence.lower() for pattern in ['attack', 'threat', 'malware', 'technique']):
                knowledge.append(sentence.strip())
        
        return knowledge[:10]  # Limit to top 10 knowledge elements