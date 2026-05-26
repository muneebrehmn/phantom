#!/bin/bash
# Phantom Installation Script
# One-command setup for the Phantom framework

set -e  # Exit on error

echo "╔════════════════════════════════════════════════╗"
echo "║   Phantom - Prompt Injection Framework Setup  ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check Python version
echo -e "${BLUE}[1/5]${NC} Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python 3 not found. Please install Python 3.10 or higher.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
REQUIRED_VERSION="3.10"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}✗ Python $PYTHON_VERSION found. Phantom requires Python 3.10 or higher.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Python $PYTHON_VERSION detected${NC}"

# Create virtual environment
echo -e "\n${BLUE}[2/5]${NC} Creating virtual environment..."
if [ -d "venv" ]; then
    echo -e "${YELLOW}! Virtual environment already exists, skipping creation${NC}"
else
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
fi

# Activate virtual environment
echo -e "\n${BLUE}[3/5]${NC} Activating virtual environment..."
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment activated${NC}"

# Install dependencies
echo -e "\n${BLUE}[4/5]${NC} Installing dependencies..."
pip install --upgrade pip > /dev/null 2>&1

if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    echo -e "${GREEN}✓ Core dependencies installed${NC}"
else
    echo -e "${YELLOW}! requirements.txt not found, installing minimal dependencies${NC}"
    pip install httpx python-dotenv rich pytest pytest-asyncio
    echo -e "${GREEN}✓ Minimal dependencies installed${NC}"
fi

# Run tests
echo -e "\n${BLUE}[5/5]${NC} Running test suite..."
if [ -d "tests" ]; then
    if pytest tests/ -q --tb=line; then
        echo -e "${GREEN}✓ All tests passed${NC}"
    else
        echo -e "${YELLOW}! Some tests failed, but installation complete${NC}"
    fi
else
    echo -e "${YELLOW}! Test directory not found, skipping tests${NC}"
fi

# Create .env from example
if [ -f ".env.example" ] && [ ! -f ".env" ]; then
    echo -e "\n${BLUE}Creating .env file...${NC}"
    cp .env.example .env
    echo -e "${GREEN}✓ .env file created (edit it to add API keys)${NC}"
fi

# Success message
echo -e "\n╔════════════════════════════════════════════════╗"
echo -e "║           ${GREEN}Installation Complete!${NC}              ║"
echo -e "╚════════════════════════════════════════════════╝"
echo ""
echo -e "Next steps:"
echo -e "  ${BLUE}1.${NC} Activate the virtual environment:"
echo -e "     ${YELLOW}source venv/bin/activate${NC}"
echo ""
echo -e "  ${BLUE}2.${NC} Run a quick test:"
echo -e "     ${YELLOW}python phantom.py --help${NC}"
echo ""
echo -e "  ${BLUE}3.${NC} Start scanning:"
echo -e "     ${YELLOW}python phantom.py scan https://your-target.com${NC}"
echo ""
echo -e "Documentation: ${BLUE}README.md${NC}"
echo -e "Examples: ${BLUE}examples/${NC}"
echo ""
echo -e "${GREEN}Happy hunting! 🎯${NC}"