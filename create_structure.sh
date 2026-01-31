#!/bin/bash
# Create unified project structure for SOC_Intelligence

echo "Creating SOC_Intelligence project structure..."

# Main directories
mkdir -p src/{unified,app,charts,cli,utils}

# Unified core subdirectories
mkdir -p src/unified/{models,db,ingestion,analysis,reports,ai}

# App subdirectories  
mkdir -p src/app/{pages,components}

# Other directories
mkdir -p {templates/reports,config,schemas,tests,scripts,docs,data,logs}

# Test subdirectories
mkdir -p tests/unified/{models,db,ingestion,analysis,reports,ai}

# Create __init__.py files
find src -type d -exec touch {}/__init__.py \;
find tests -type d -exec touch {}/__init__.py \;

echo "✓ Directory structure created"
echo ""
echo "Structure:"
tree -L 3 -I '__pycache__|*.pyc|.git' || find . -type d -name ".*" -prune -o -print | head -50

