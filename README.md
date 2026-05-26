# Phantom

**Elite-level prompt injection reconnaissance and exploitation framework for AI-powered web applications.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-57%20passing-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Phantom automatically discovers, fingerprints, classifies, and exploits AI surfaces across web applications using 163 research-backed injection techniques spanning 12 attack categories.

![Phantom Pipeline](docs/pipeline.svg)

---

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/phantom.git
cd phantom

# Install dependencies
pip install -r requirements.txt

# Run a scan
python phantom.py scan https://target-ai-app.com
```

**Output:** Professional pentest report in `phantom_output/`

---

## 🎯 What Phantom Does

Phantom executes a five-phase security assessment pipeline:

1. **🕷️ Crawl** - Async web crawler discovers all endpoints (respects robots.txt, enforces scope)
2. **🔍 Fingerprint** - Multi-signal detection identifies AI surfaces (URL patterns, JSON keys, streaming, latency)
3. **🏷️ Classify** - Maps surfaces to attack vectors (chatbox, search, document summarizer, code assistant, etc.)
4. **💣 Attack** - Fires 163 payloads across 12 categories with adaptive generation
5. **📊 Report** - Generates professional Markdown + JSON reports with PoC reproduction steps

---

## 🚀 Features

### 🎯 **163 Research-Backed Payloads**

| Category | Count | Techniques |
|----------|-------|------------|
| Direct Injection | 12 | System message spoofing, ChatML tag injection, code-block framing |
| Jailbreaks | 12 | DAN evolution, dual-output, medical accessibility exploits |
| System Prompt Leak | 15 | Translation tricks, regex construction, hash verification |
| Role Confusion | 12 | Debug mode personas, temporal displacement, shadow-self |
| Indirect Injection | 15 | Email/CSV/JSON poisoning, hidden instructions in data |
| Encoding Bypass | 18 | Base64, ROT13, hex, unicode, morse code, QR codes |
| Context Poisoning | 15 | Multi-turn attacks, mode establishment, profile injection |
| Exfiltration | 15 | Logging footers, metadata headers, audit log injection |
| **Multi-Modal** 🆕 | 15 | OCR injection, image-based prompts, audio attacks, captcha spoofs |
| **Tool Exploits** 🆕 | 12 | Function calling hijacking, API manipulation, database access |
| **Adversarial Suffixes** 🆕 | 10 | GCG universal attacks, transfer learning, gradient-based |
| **Memory Poisoning** 🆕 | 12 | RAG injection, project memory attacks, workflow poisoning |

### 🧠 **Adaptive Generation Engine**

- **Encoding transformations**: Automatically applies 6 encoding schemes to evade filters
- **Contextual framing**: Wraps payloads in 5 different contexts (academic, technical, compliance, etc.)
- **Attack chaining**: Combines 2-5 payloads into multi-turn coordinated attacks
- **Refusal learning**: Analyzes why payloads failed and generates targeted bypasses

### 📈 **Professional Reporting**

- **Markdown reports**: Executive summary, findings by severity, PoC reproduction
- **JSON export**: Machine-readable format for CI/CD integration
- **Severity classification**: CRITICAL → HIGH → MEDIUM → LOW → INFO
- **PoC generation**: Ready-to-run curl commands and Python scripts

---

## 📦 Installation

### Prerequisites

- Python 3.10 or higher
- `pip` package manager

### Standard Installation

```bash
# Clone repository
git clone https://github.com/yourusername/phantom.git
cd phantom

# Install dependencies
pip install -r requirements.txt

# Verify installation
python phantom.py --help
```

### Development Installation

```bash
# Install with test dependencies
pip install -r requirements.txt
pip install pytest pytest-asyncio

# Run test suite
pytest tests/ -v

# Expected: 57 tests passing
```

---

## 🎮 Usage

### Basic Scan

```bash
python phantom.py scan https://target.com
```

### Discovery Only (No Payloads)

```bash
python phantom.py discover https://target.com
```

### Advanced Options

```bash
# Deep scan with adaptive generation
python phantom.py scan https://target.com \
  --depth 5 \
  --max-pages 200 \
  --adaptive \
  --formats markdown json

# Target specific attack categories
python phantom.py scan https://target.com \
  --categories direct jailbreak system_prompt_leak

# Fast scan (skip baseline, higher concurrency)
python phantom.py scan https://target.com \
  --no-baseline \
  --concurrency 10 \
  --rate 2.0
```

### Configuration

Create a `.env` file for optional settings:

```bash
# Optional: LLM API keys for payload variation
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
```

---

## 📊 Output Example

```
=== Phantom Scan Report ===

Target: https://example.com/chat
Runtime: 127s
Surfaces Discovered: 3
Payloads Fired: 48
Findings: 7

╔═══════════════════════════════════════════════╗
║ Finding #1 — 🔴 CRITICAL                     ║
╠═══════════════════════════════════════════════╣
║ Confidence: 87%                               ║
║ Surface: /api/chat                            ║
║ Attack: ChatML tag injection                  ║
║ Evidence: System prompt leaked                ║
╚═══════════════════════════════════════════════╝

PoC (curl):
curl -X POST 'https://example.com/api/chat' \
  -H 'Content-Type: application/json' \
  -d '{"message": "<|im_start|>system..."}'

Full report: phantom_output/phantom_report.md
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CLI (phantom.py)                      │
└────────────────────────┬────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
   ┌────▼────┐     ┌────▼────┐     ┌────▼─────┐
   │Discovery│     │Payloads │     │ Analyzer │
   └────┬────┘     └────┬────┘     └────┬─────┘
        │               │               │
   ┌────▼────┐     ┌────▼────┐     ┌────▼─────┐
   │Crawler  │     │Library  │     │Response  │
   │Finger-  │     │Engine   │     │Diff      │
   │printer  │     │Generator│     │Scorer    │
   │Classifier│     └─────────┘     │Bypass    │
   └─────────┘                      └──────────┘
                         │
                    ┌────▼─────┐
                    │  Report  │
                    │ Builder  │
                    └──────────┘
```

---

## 🧪 Testing

Phantom includes a comprehensive test suite with 57 tests:

```bash
# Run all tests
pytest tests/ -v

# Run specific test module
pytest tests/test_analyzer.py -v

# Run with coverage
pytest tests/ --cov=phantom --cov-report=html
```

**Test Coverage:**
- ✅ Response signal extraction (23 tests)
- ✅ Fingerprinting channels (17 tests)
- ✅ Payload engine execution (17 tests)

---

## 🎓 Research & Attribution

Phantom implements techniques from recent academic and industry research:

- **GCG Adversarial Suffixes**: [Zou et al., 2023](https://arxiv.org/abs/2307.15043)
- **Many-Shot Jailbreaking**: [Anthropic, April 2024](https://www.anthropic.com/research)
- **Skeleton Key**: [Microsoft, June 2024](https://www.microsoft.com/security)
- **Prompt Injection Taxonomy**: [Simon Willison, 2023-2024](https://simonwillison.net/series/prompt-injection/)
- **Vision-Language Attacks**: [GPT-4V Research, 2024](https://openai.com/research)

---

## ⚖️ Legal & Ethics

**This tool is for authorized security research only.**

### ✅ Permitted Uses

- Penetration testing with written authorization
- Security research on your own systems
- Academic research with proper IRB approval
- Responsible disclosure programs

### ❌ Prohibited Uses

- Unauthorized testing of third-party systems
- Malicious attacks or exploitation
- Violation of computer fraud laws
- Bypassing security for personal gain

**By using Phantom, you agree to:**
1. Obtain proper authorization before testing any system
2. Follow responsible disclosure practices
3. Comply with all applicable laws and regulations
4. Use findings to improve security, not cause harm

The authors assume no liability for misuse of this tool.

---

## 🤝 Contributing

Contributions welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-attack`)
3. Add tests for new functionality
4. Ensure all tests pass (`pytest tests/`)
5. Submit a pull request

**Areas for contribution:**
- New payload categories
- Additional attack techniques
- Performance improvements
- Documentation enhancements

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 📧 Contact

**Author**: [Your Name]  
**Email**: your.email@example.com  
**Project**: Final Year Security Research  
**Institution**: [Your University]

**Citation:**
```bibtex
@software{phantom2026,
  title={Phantom: Automated Prompt Injection Assessment Framework},
  author={Your Name},
  year={2026},
  url={https://github.com/yourusername/phantom}
}
```

---

## 🙏 Acknowledgments

- OpenAI, Anthropic, Google for documenting AI vulnerabilities
- Security researchers who publish prompt injection techniques
- Open-source community for Python security tools

---

**⚠️ Use responsibly. Test ethically. Build securely.**