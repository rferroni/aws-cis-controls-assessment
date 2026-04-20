#!/bin/bash
# Build script for AWS CIS Assessment Tool

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting build process for AWS CIS Assessment Tool${NC}"

# Check if we're in a virtual environment
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo -e "${YELLOW}Warning: Not in a virtual environment${NC}"
    echo "Consider running: python -m venv venv && source venv/bin/activate"
fi

# Clean previous builds
echo -e "${GREEN}Cleaning previous builds...${NC}"
rm -rf build/ dist/ *.egg-info/

# Install build dependencies
echo -e "${GREEN}Installing build dependencies...${NC}"
python -m pip install --upgrade pip build twine

# Run tests before building
echo -e "${GREEN}Running tests...${NC}"
python -m pytest tests/ -v

# Run security checks
echo -e "${GREEN}Running security checks...${NC}"
python -m bandit -r aws_cis_assessment
python -m safety check

# Build the package
echo -e "${GREEN}Building package...${NC}"
python -m build

# Verify the build
echo -e "${GREEN}Verifying build...${NC}"
python -m twine check dist/*

# Display build artifacts
echo -e "${GREEN}Build artifacts:${NC}"
ls -la dist/

echo -e "${GREEN}Build completed successfully!${NC}"
echo -e "${YELLOW}To upload to PyPI:${NC}"
echo "  Test PyPI: python -m twine upload --repository testpypi dist/*"
echo "  Production: python -m twine upload dist/*"