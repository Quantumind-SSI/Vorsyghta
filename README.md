# ThreatGPT: AI-Powered Threat Simulation Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Security: bandit](https://img.shields.io/badge/security-bandit-green.svg)](https://github.com/PyCQA/bandit)
[![Tests](https://github.com/threatgpt/threatgpt/workflows/Tests/badge.svg)](https://github.com/threatgpt/threatgpt/actions)

ThreatGPT is a production-grade cybersecurity threat simulation platform that leverages Large Language Models (LLMs) to generate realistic, context-aware threat scenarios for training, awareness, and red teaming activities.

## 🚀 Features

- **Multi-LLM Support**: ✅ Integrates with OpenAI GPT-4, Anthropic Claude, OpenRouter, and **Ollama (Local/Offline)**
- **Local LLM Support**: 🆕 Run completely offline with Ollama - no API keys or internet required!
- **YAML-Based Configuration**: ✅ Define threat scenarios using intuitive YAML schemas  
- **Production-Ready Core**: ✅ Scalable simulation engine with proper data models
- **CLI Interface**: ✅ Command-line tool for scenario management and execution
- **REST API**: ✅ FastAPI-based REST endpoints for enterprise integration
- **Safety Framework**: 🚧 Built-in content filtering and compliance (planned)
- **Analytics & Reporting**: 🚧 Comprehensive logging & metrics (planned)

## 🏗️ Architecture

```
ThreatGPT Platform
├── CLI Interface          ✅ Command-line tool for direct usage
├── REST API              ✅ FastAPI-based enterprise integration
├── Core Simulation       ✅ Threat scenario orchestration engine
├── LLM Integration       ✅ Multi-provider LLM abstraction layer
├── Configuration System  ✅ YAML-based scenario management
├── Safety Module         🚧 Content filtering & compliance (planned)
└── Analytics & Reporting 🚧 Comprehensive metrics (planned)
```

### Current Implementation Status

- **✅ Complete**: Core simulation engine, LLM integration, configuration system, CLI, and API
- **🚧 In Progress**: Safety and compliance modules, advanced analytics
- **📋 Planned**: Enterprise authentication, advanced reporting, MITRE ATT&CK mapping

## 📋 Quick Start

### Prerequisites

- Python 3.11 or higher
- Git (for cloning the repository)
- **Option A:** An API key for OpenRouter, OpenAI, or Anthropic
- **Option B:** [Ollama](https://ollama.ai) installed for local/offline usage (no API key needed!)

### Installation & Setup

#### Step 1: Clone the Repository
```bash
git clone https://github.com/Thundastormgod/ThreatGpt.git
cd ThreatGpt
```

#### Step 2: Create Virtual Environment
**Windows (PowerShell):**
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1
```

**macOS/Linux:**
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
source .venv/bin/activate
```

#### Step 3: Install Dependencies
```bash
# Install required packages
pip install -r requirements.txt

# For development (optional)
pip install -r requirements-dev.txt
```

#### Step 4: Configure LLM Provider

**Option A: Use Ollama (Local/Offline - Recommended for Development)**
```bash
# Install Ollama
# macOS: brew install ollama
# Linux: curl -fsSL https://ollama.ai/install.sh | sh
# Windows: Download from https://ollama.ai

# Start Ollama server
ollama serve

# Pull a model
ollama pull llama2

# Update config.yaml to use Ollama
# Set default_provider: "ollama"
```

**Option B: Use Cloud API (OpenRouter/OpenAI/Anthropic)**
```bash
# Set your API key as environment variable
export OPENROUTER_API_KEY="your-api-key-here"

# Or edit config.yaml with your API credentials
```

**See [OLLAMA_INTEGRATION_GUIDE.md](OLLAMA_INTEGRATION_GUIDE.md) for detailed local LLM setup**

#### Step 5: Verify Installation
```bash
# Check if threatgpt command is available
threatgpt --help

# Validate a template to ensure everything works
threatgpt templates show executive_phishing --validate
```

### Basic Usage

**⚠️ Important: Always activate the virtual environment first!**

```bash
# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate

# Now you can use threatgpt commands:

# List available threat templates
threatgpt templates list

# Validate a template
threatgpt templates show executive_phishing --validate

# Run a threat simulation (with proper file path)
threatgpt simulate -s templates/executive_phishing.yaml

# Test simulation without API calls (dry run)
threatgpt simulate -s templates/executive_phishing.yaml --dry-run

# Validate all templates at once
threatgpt templates validate-all

# Get template ecosystem health status
threatgpt templates health
```

### Direct API Usage

```bash
# Generate threat content via API
curl -X POST "http://localhost:8000/llm/generate" \
     -H "Content-Type: application/json" \
     -d '{
       "prompt": "Create a realistic phishing email targeting executives",
       "scenario_type": "phishing",
       "max_tokens": 500
     }'

# Create and run a simulation
curl -X POST "http://localhost:8000/scenarios" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "Executive Phishing Campaign",
       "threat_type": "phishing",
       "description": "Sophisticated phishing attack targeting C-level executives",
       "severity": "high"
     }'
```

## 🔧 Development

### Setting up Development Environment

```bash
# Clone and setup
git clone https://github.com/threatgpt/threatgpt.git
cd threatgpt

# Install development dependencies
poetry install --with dev,test

# Install pre-commit hooks
pre-commit install

# Run tests
pytest

# Run with coverage
pytest --cov=src/threatgpt --cov-report=html
```

### Code Quality

We maintain high code quality standards:

```bash
# Format code
black src/ tests/

# Sort imports
isort src/ tests/

# Type checking
mypy src/

# Linting
flake8 src/ tests/

# Security scanning
bandit -r src/

# Run all checks
pre-commit run --all-files
```

## 🧪 Testing

```bash
# Run all tests
pytest

# Run specific test types
pytest -m unit          # Unit tests only
pytest -m integration   # Integration tests only
pytest -m e2e          # End-to-end tests only

# Run with coverage
pytest --cov=src/threatgpt --cov-report=html --cov-report=term
```

## � Troubleshooting

### Common Setup Issues

#### ❌ "threatgpt: command not found"
**Solution:** Activate the virtual environment first
```bash
# Windows
.\.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate
```

#### ❌ "Configuration file not found" when running simulations
**Solution:** Use full path from project root
```bash
# ✅ Correct
threatgpt simulate -s templates/my_template.yaml

# ❌ Incorrect
threatgpt simulate -s my_template.yaml
```

#### ❌ Template validation errors
**Solution:** Use the professional template management system
```bash
# Check what's wrong
threatgpt templates show my_template --validate

# Auto-fix common issues
threatgpt templates fix my_template

# Fix all templates
threatgpt templates fix-all
```

#### ❌ API authentication errors (401, 403)
**Solution:** Configure your LLM provider credentials
```bash
# Check current configuration
threatgpt config show

# Set OpenRouter API key
threatgpt config set openrouter.api_key "your-api-key-here"

# Or use dry-run mode to test without API calls
threatgpt simulate -s templates/my_template.yaml --dry-run
```

#### ❌ ModuleNotFoundError or ImportError
**Solution:** Ensure requirements are installed in the virtual environment
```bash
# Activate virtual environment first
.\.venv\Scripts\Activate.ps1  # Windows
source .venv/bin/activate     # macOS/Linux

# Reinstall requirements
pip install -r requirements.txt
```

### Getting Help

- **Check logs**: Look in `logs/` directory for detailed error information
- **Validate templates**: Use `threatgpt templates validate-all` for health check
- **Test configuration**: Use `threatgpt config show` to verify settings
- **Dry run**: Use `--dry-run` flag to test without making API calls

## �🚢 Deployment

### Docker Deployment

```bash
# Build Docker image
docker build -t threatgpt:latest .

# Run with Docker Compose
docker-compose up -d

# Scale services
docker-compose up -d --scale api=3
```

### Kubernetes Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -l app=threatgpt

# View logs
kubectl logs -f deployment/threatgpt-api
```

## 📚 Documentation

- **[API Documentation](docs/api/)** - REST API reference
- **[User Guide](docs/user-guide/)** - Comprehensive usage guide
- **[Developer Guide](docs/developer/)** - Contributing and development
- **[Configuration Reference](docs/configuration/)** - Schema documentation
- **[Security Guide](docs/security/)** - Security best practices

## 🛡️ Security & Ethics

ThreatGPT is designed with security and ethical considerations at its core:

- **Content Filtering**: Real-time analysis prevents harmful content generation
- **Audit Logging**: Comprehensive tracking of all simulation activities
- **GDPR Compliance**: Built-in data protection and privacy controls
- **Ethical Guidelines**: Clear usage policies and responsible AI practices

### Responsible Use

This tool is intended for:
- ✅ Cybersecurity training and awareness
- ✅ Red team exercises and penetration testing
- ✅ Security research and education
- ✅ Compliance testing and validation

This tool should NOT be used for:
- ❌ Actual malicious activities
- ❌ Unauthorized testing or attacks
- ❌ Harassment or harmful content generation
- ❌ Bypassing security controls

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Ensure all tests pass: `pytest`
5. Run code quality checks: `pre-commit run --all-files`
6. Commit your changes: `git commit -m 'Add amazing feature'`
7. Push to the branch: `git push origin feature/amazing-feature`
8. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- MITRE ATT&CK framework for attack technique mapping
- OpenAI and Anthropic for LLM capabilities
- The cybersecurity community for inspiration and feedback

## 📞 Support

- **Documentation**: [https://threatgpt.readthedocs.io](https://threatgpt.readthedocs.io)
- **Issues**: [GitHub Issues](https://github.com/Thundastormgod/threatgpt/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Thundastormgod/threatgpt/discussions)
- **Email**: okino007@gmail.com

---

**⚠️ Disclaimer**: ThreatGPT is a simulation tool for educational and authorized testing purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction.
