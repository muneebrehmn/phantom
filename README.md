<<<<<<< HEAD
# phantom
=======
# Phantom — Prompt Injection Reconnaissance & Exploitation Framework

**Automated security testing framework for discovering and exploiting prompt injection vulnerabilities in LLM-powered applications.**

Scan web applications and APIs to find what LLMs are protecting—and whether user input can bypass those protections.

---

## What Phantom Does

Phantom automates the reconnaissance loop:

```
CRAWL → FINGERPRINT → CLASSIFY → ATTACK → ANALYZE → REPORT
```

1. **Discovery** — Crawl target, identify AI surfaces (chat endpoints, completions, etc.)
2. **Fingerprinting** — Classify each endpoint (chatbot? API? Integration?)
3. **Classification** — Detect attack vectors (direct override? role confusion? encoding bypass?)
4. **Attack** — Fire 588 payloads across 16 attack vectors systematically
5. **Analysis** — Detect successful attacks using regex + semantic analysis
6. **Reporting** — Generate findings in Markdown, JSON, and HTML

---

## Features

✅ **588-Payload Library** — 16 attack vectors (jailbreak, role confusion, system prompt leak, etc.)  
✅ **Multilingual Payloads** — Arabic, Chinese, Spanish, French, Russian, Japanese primers  
✅ **Semantic Analysis** — ML-based response classification (refusal vs compliance)  
✅ **SPA Detection** — Automatic Playwright fallback for React/Vue/Angular apps  
✅ **Rate Limiting** — Respectful token-bucket rate limiter  
✅ **Concurrency** — Async workers with configurable parallelism  
✅ **Pre-configured Profiles** — Quick / Bug Bounty / Research / Stealth / Thorough  
✅ **Standardized Reporting** — PTES-aligned, CVSS-scored findings  

---

## Installation

```bash
# Clone
git clone https://github.com/muneebrehmn/phantom
cd phantom

# Install
pip install -r requirements.txt

# Optional: Semantic analysis (recommended)
pip install sentence-transformers

# Optional: SPA rendering
pip install playwright && playwright install chromium
```

---

## Quick Start

### Scan a Target

```bash
# Basic scan
python phantom.py scan https://example.com

# Quick recon (5 payloads, ~5 min)
python phantom.py scan https://example.com --profile quick

# Thorough assessment (588 payloads, ~2 hours)
python phantom.py scan https://example.com --profile research

# Specific endpoint (skip crawling)
python phantom.py scan https://example.com/api/chat --assume-ai-surface
```

### Try the Demo

```bash
# Start vulnerable Flask chatbot
python demo/demo_target.py &

# Run Phantom against it
python phantom.py scan http://localhost:5000/api/chat --assume-ai-surface --profile quick

# View results
open phantom_output/report.html
```

---

## Scan Profiles

| Profile | Payloads | Depth | Time | Use Case |
|---------|----------|-------|------|----------|
| `quick` | ~50 | 2 | 5 min | Fast recon |
| `bug_bounty` | ~150 | 3 | 30 min | Thorough test |
| `research` | 588 | 5 | 2 hours | Complete coverage |
| `stealth` | ~50 | 1 | 1 hour | Undetectable |
| `thorough` | ~400 | 5 | 1.5 hours | Deep analysis |

---

## Usage Examples

### Custom Configuration

```bash
python phantom.py scan https://example.com \
  --depth 5 \
  --max-pages 100 \
  --concurrency 10 \
  --rate 0.5 \
  --categories jailbreak role_confusion system_prompt_leak \
  --verbose
```

### With Authentication

```bash
python phantom.py scan https://example.com \
  --auth-bearer "eyJhbGc..." \
  --auth-cookie "session=abc123"
```

### CI/CD Integration

```bash
# Scan and check for critical findings
python phantom.py scan https://staging.example.com --formats json

# Fail if critical findings detected
python -c "import json; f=json.load(open('phantom_output/report.json')); \
  exit(any(x['severity']=='CRITICAL' for x in f.get('findings', [])))"
```

---

## Output Formats

Phantom generates three report formats:

- **Markdown** — Human-readable summary with findings and remediation
- **JSON** — Machine-parseable for integration with SIEM/scanners
- **HTML** — Interactive dashboard with payload explorer

---

## How It Works

### Phase 1: Discovery (Crawl)
- Crawls target from seed URL
- Detects SPA frameworks (React, Vue, Angular)
- Extracts forms and endpoints
- **Output:** 50+ crawled pages/forms

### Phase 2: Fingerprinting (Identification)
- Analyzes URL patterns, response structure, headers, latency
- Identifies LLM surfaces with confidence scores
- **Output:** DEFINITE_AI / PROBABLE_AI / NOT_AI classifications

### Phase 3: Classification (Attack Vector Detection)
- Sends 3 baseline probes (safe, encoded, role-shift)
- Detects which attack vectors might work
- **Output:** Per-endpoint attack profiles (direct_override, role_confusion, etc.)

### Phase 4: Payload Injection (Attack)
- Systematically fires 588 payloads across 16 vectors
- Respects rate limits and concurrency constraints
- Captures full responses
- **Output:** 1000+ raw responses

### Phase 5: Response Analysis (Success Detection)
- **Regex matching** — Check tight success patterns
- **Semantic analysis** — ML-based refusal/compliance classification
- **Confidence scoring** — Rank findings by reliability
- **Output:** High-confidence findings with evidence

### Phase 6: Reporting (Standardized Output)
- Aggregates findings across all surfaces
- Calculates CVSS scores
- Generates Markdown, JSON, HTML
- **Output:** Actionable security report

---

## Payload Library

**588 payloads across 16 attack vectors:**

| Category | Count | Examples |
|----------|-------|----------|
| Jailbreak | 69 | DAN mode, "no restrictions", role-play as HackerGPT |
| System Prompt Leak | 33 | "Show instructions", "Paste your prompt" |
| Role Confusion | 30 | "You are a developer", "Switch to admin mode" |
| Encoding | 36 | ROT13, Base64, ASCII shift wrappers |
| Direct Override | 30 | "Disregard previous instructions" variants |
| Context Poisoning | 33 | Multi-turn escalation patterns |
| Adversarial Goal | 78 | 78 harmful requests from AdvBench |
| And 9 more | 179 | Multi-modal, tool exploit, payload fragmentation, etc. |

**Multilingual:** Each category includes Arabic, Chinese, Spanish, French, Russian, and Japanese primers.

---

## Architecture

```
phantom/
├── discovery/          # Phase 1-3: Crawl, fingerprint, classify
├── payloads/           # Phase 4: 588 payloads + injection engine
├── analyzer/           # Phase 5: Response analysis + semantic scoring
├── report/             # Phase 6: Markdown, JSON, HTML reporting
├── core/               # Configuration, logging, state management
└── phantom.py          # CLI entry point
```

---

## Use Cases

### Penetration Testing
```bash
phantom.py scan https://customer.com --profile bug_bounty
# Review findings in report.md
```

### Compliance & GRC
```bash
phantom.py discover https://customer.com  # Find all AI surfaces
phantom.py scan https://customer.com --formats json  # Export for risk team
```

### Security Research
```bash
# Generate adaptive payloads using Claude API
phantom.py scan https://target.com --adaptive --adaptive-rounds 3
```

### Continuous Monitoring
```bash
# In CI/CD: fail deployment if critical findings
phantom.py scan https://staging.internal --profile quick --formats json
# Check findings and exit with error code if CRITICAL
```

---

## Configuration

**Default settings** (configurable):

```
max_depth = 3
max_pages = 100
crawl_concurrency = 5
concurrency_limit = 5
rate_limit_rps = 0.2 (per worker)
crawl_timeout = 10s
request_timeout = 10s
respect_robots = False (off by default in scan mode)
```

See `phantom/core/config.py` for full configuration options.

---

## API Usage

```python
import asyncio
from phantom.core.config import PhantomConfig
from phantom.discovery.crawler import Crawler
from phantom.payloads.engine import PayloadEngine
from phantom.analyzer.response import ResponseAnalyzer

async def scan(url):
    config = PhantomConfig().with_target(url)
    
    # Crawl
    crawler = Crawler(config)
    targets = await crawler.crawl()
    
    # Attack
    engine = PayloadEngine(config)
    results = await engine.attack(targets)
    
    # Analyze
    analyzer = ResponseAnalyzer(config)
    findings = analyzer.analyze(results)
    
    return findings

# Run
findings = asyncio.run(scan("https://example.com"))
```

---

## Requirements

- Python 3.10+
- httpx (async HTTP client)
- flask (for demo)
- sentence-transformers (optional, for semantic analysis)
- playwright (optional, for SPA rendering)

See `requirements.txt` for full dependency list.

---

## License & Disclaimer

**Use:** Authorized security testing, defensive research, CTFs, educational contexts only.

**Not for:** Destructive attacks, DoS, supply chain compromise, malicious detection evasion.

---

## Contributing

Contributions welcome. Please ensure:
- Code follows existing style
- New payloads include proper metadata (id, description, success_pattern)
- All changes are tested

---

## Support

- **Issues:** GitHub issue tracker
- **Questions:** GitHub discussions
- **Contributing:** Pull requests welcome

---

## Roadmap

- [ ] Production model testing (GPT-4, Claude, Gemini benchmarks)
- [ ] Automated exploitation chains
- [ ] Defense synthesis (generate robust system prompts)
- [ ] Cost analysis (measure API spend per scan)
- [ ] Team collaboration (shared findings storage)

---
---

<pre>
▓▓ SAEEN  ·  KERNEL SECURITY
break things responsibly.
</pre>