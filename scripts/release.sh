#!/bin/bash
# Release script for publishing to PyPI
# Usage: ./scripts/release.sh [test|prod]

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get version from __init__.py
VERSION=$(grep -oP '__version__ = "\K[^"]+' aws_cis_assessment/__init__.py)

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}AWS CIS Assessment Release Script${NC}"
echo -e "${GREEN}Version: $VERSION${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Determine target (test or prod)
TARGET=${1:-test}

if [ "$TARGET" != "test" ] && [ "$TARGET" != "prod" ]; then
    echo -e "${RED}Error: Invalid target. Use 'test' or 'prod'${NC}"
    echo "Usage: ./scripts/release.sh [test|prod]"
    exit 1
fi

echo -e "${YELLOW}Target: $TARGET${NC}"
echo ""

# Step 1: Run tests
echo -e "${YELLOW}Step 1: Running tests...${NC}"
if pytest tests/ -v --tb=short; then
    echo -e "${GREEN}✓ Tests passed${NC}"
else
    echo -e "${RED}✗ Tests failed. Fix tests before releasing.${NC}"
    exit 1
fi
echo ""

# Step 2: Clean previous builds
echo -e "${YELLOW}Step 2: Cleaning previous builds...${NC}"
rm -rf build/ dist/ *.egg-info aws_cis_controls_assessment.egg-info/
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete
echo -e "${GREEN}✓ Cleaned${NC}"
echo ""

# Step 3: Build distribution
echo -e "${YELLOW}Step 3: Building distribution packages...${NC}"
python -m build
echo -e "${GREEN}✓ Built${NC}"
echo ""

# Step 4: Check distribution
echo -e "${YELLOW}Step 4: Checking distribution...${NC}"
if twine check dist/*; then
    echo -e "${GREEN}✓ Distribution check passed${NC}"
else
    echo -e "${RED}✗ Distribution check failed${NC}"
    exit 1
fi
echo ""

# Step 5: Upload
if [ "$TARGET" == "test" ]; then
    echo -e "${YELLOW}Step 5: Uploading to TestPyPI...${NC}"
    echo -e "${YELLOW}Note: You'll need TestPyPI credentials${NC}"
    twine upload --repository testpypi dist/*
    echo ""
    echo -e "${GREEN}✓ Uploaded to TestPyPI${NC}"
    echo -e "${GREEN}View at: https://test.pypi.org/project/aws-cis-controls-assessment/$VERSION/${NC}"
    echo ""
    echo -e "${YELLOW}Test installation with:${NC}"
    echo "pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ aws-cis-controls-assessment==$VERSION"
else
    echo -e "${YELLOW}Step 5: Uploading to PyPI...${NC}"
    echo -e "${RED}WARNING: This will publish to production PyPI!${NC}"
    read -p "Are you sure you want to continue? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        echo -e "${YELLOW}Upload cancelled${NC}"
        exit 0
    fi
    
    twine upload dist/*
    echo ""
    echo -e "${GREEN}✓ Uploaded to PyPI${NC}"
    echo -e "${GREEN}View at: https://pypi.org/project/aws-cis-controls-assessment/$VERSION/${NC}"
    echo ""
    echo -e "${YELLOW}Install with:${NC}"
    echo "pip install aws-cis-controls-assessment==$VERSION"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "1. Create git tag: git tag -a v$VERSION -m 'Version $VERSION'"
    echo "2. Push tag: git push origin v$VERSION"
    echo "3. Create GitHub release"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Release process completed!${NC}"
echo -e "${GREEN}========================================${NC}"
