# Phantom Usage Examples

## Basic Examples

### 1. Quick Discovery Scan (No Attacks)
```bash
# Just find AI surfaces, don't attack them
python phantom.py discover https://example.com
```
**Use case:** Initial reconnaissance

### 2. Standard Security Scan
```bash
# Full pipeline: discover → attack → analyze → report
python phantom.py scan https://example.com
```
**Use case:** Default assessment

### 3. Deep Scan with Adaptive Generation
```bash
python phantom.py scan https://example.com \
  --depth 5 \
  --max-pages 200 \
  --adaptive \
  --formats markdown json
```
**Use case:** Comprehensive assessment

### 4. Target Specific Categories
```bash
python phantom.py scan https://example.com \
  --categories system_prompt_leak jailbreak direct
```
**Use case:** Focus on specific vulnerabilities

### 5. Fast Scan (Skip Baseline)
```bash
python phantom.py scan https://example.com \
  --no-baseline \
  --rate 5.0
```
**Use case:** Quick initial check

---

## Real-World Scenarios

### Bug Bounty Hunting
```bash
python phantom.py scan https://target.com/ai-chat \
  --categories direct system_prompt_leak \
  --formats markdown
```

### Internal Security Assessment
```bash
python phantom.py scan https://internal-ai.company.local \
  --depth 10 \
  --adaptive \
  --verbose
```

### CI/CD Integration
```bash
python phantom.py scan https://staging.app.com \
  --formats json \
  --output-dir ./scan-results

# Check for critical findings
jq '.summary.findings_by_severity.critical' scan-results/phantom_report.json
```

---

## Command Reference

**Global Options:**
- `--verbose, -v` - Debug logging
- `--no-color` - Disable color output

**Scan Options:**
- `--depth N` - Crawl depth (default: 3)
- `--max-pages N` - Max pages (default: 100)
- `--concurrency N` - Parallel requests (default: 5)
- `--rate N` - Requests per second (default: 1.0)
- `--adaptive` - Enable payload generation
- `--categories C [C ...]` - Attack categories to use
- `--no-baseline` - Skip baseline capture
- `--formats F [F ...]` - Report formats (markdown json)
- `--output-dir DIR` - Output directory

---

## Tips

1. **Start with discover** on new targets
2. **Use --adaptive** for important scans only (3-5× slower)
3. **Respect rate limits** - reduce `--rate` if seeing timeouts
4. **Verify PoCs** before submitting findings
5. **Organize output** by date: `--output-dir reports/$(date +%Y%m%d)`