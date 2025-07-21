"""Main application entry point for threat hunting notebook generator."""

import argparse
import sys
from pathlib import Path
from typing import Optional

from .ingestion.article_parser import ArticleParser
from .analysis.peak_mapper import PEAKMapper
from .generation.notebook_generator import NotebookGenerator


def main():
    """Main application function."""
    parser = argparse.ArgumentParser(
        description="Generate threat hunting notebooks from research articles using PEAK framework"
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Input article (file path or URL)"
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output notebook file path (.ipynb)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--enable-colab",
        action="store_true",
        default=True,
        help="Enable Google Colab integration (default: True)"
    )
    parser.add_argument(
        "--github-repo",
        default="your-org/threat-hunting-notebook-generator",
        help="GitHub repository for Colab links (format: owner/repo)"
    )
    
    args = parser.parse_args()
    
    try:
        # Validate output path
        output_path = Path(args.output)
        if output_path.suffix != '.ipynb':
            output_path = output_path.with_suffix('.ipynb')
        
        # Create output directory if it doesn't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if args.verbose:
            print(f"Input source: {args.input}")
            print(f"Output path: {output_path}")
        
        # Parse article
        if args.verbose:
            print("Parsing article...")
        
        parser = ArticleParser()
        article_data = parser.parse_article(args.input)
        
        if args.verbose:
            print(f"Extracted {len(article_data['content'])} characters from article")
            print(f"Title: {article_data['title']}")
        
        # Analyze with PEAK framework
        if args.verbose:
            print("Mapping to PEAK framework...")
        
        mapper = PEAKMapper()
        hunts = mapper.analyze_article(article_data)
        
        if args.verbose:
            print(f"Generated {len(hunts)} hunt scenarios:")
            for i, hunt in enumerate(hunts, 1):
                print(f"  {i}. {hunt.title} ({hunt.hunt_type.value})")
        
        # Generate notebook
        if args.verbose:
            print("Generating notebook...")
        
        generator = NotebookGenerator()
        notebook = generator.generate_notebook(hunts, article_data, enable_colab=args.enable_colab)
        
        # Save notebook
        generator.save_notebook(notebook, str(output_path))
        
        print(f"Successfully generated threat hunting notebook: {output_path}")
        print(f"Created {len(hunts)} PEAK hunting scenarios")
        
        if args.enable_colab:
            notebook_name = output_path.name
            colab_url = generator.generate_colab_url(args.github_repo, f"notebooks/{notebook_name}")
            print(f"Google Colab URL: {colab_url}")
            print("📊 To run in Colab: Upload notebook to GitHub and use the generated URL")
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()