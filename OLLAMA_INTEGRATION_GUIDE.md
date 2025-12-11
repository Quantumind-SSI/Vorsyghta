# Ollama Local LLM Integration Guide

## Overview

ThreatGPT now supports **Ollama** for running local Large Language Models (LLMs) completely offline. This means:

✅ **No API keys required**  
✅ **No internet connection needed**  
✅ **No usage costs**  
✅ **Full privacy - data never leaves your machine**  
✅ **Fast generation after model download**

## Installation

### Step 1: Install Ollama

#### macOS
```bash
brew install ollama
```

#### Linux
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

#### Windows
Download the installer from [https://ollama.ai](https://ollama.ai)

### Step 2: Start Ollama Server

```bash
ollama serve
```

The server will start on `http://localhost:11434` by default.

### Step 3: Install a Model

Choose and install a model. Popular options:

```bash
# Llama 2 (7B) - Good all-rounder, recommended for most users
ollama pull llama2

# Mistral (7B) - Fast and capable
ollama pull mistral

# Llama 2 13B - Better quality, requires more RAM
ollama pull llama2:13b

# Code Llama - Specialized for code/technical content
ollama pull codellama

# Neural Chat - Intel's model, good for conversations
ollama pull neural-chat

# Orca Mini - Compact and fast
ollama pull orca-mini
```

**Recommended for ThreatGPT:** Start with `llama2` or `mistral`

## Configuration

### Option 1: Use Ollama as Default Provider

Edit `config.yaml`:

```yaml
llm:
  # Set Ollama as the default provider
  default_provider: "ollama"
  
  ollama:
    enabled: true
    base_url: "http://localhost:11434"
    model: "llama2"  # or "mistral", "codellama", etc.
    timeout_seconds: 120
    max_tokens: 1000
    temperature: 0.7
```

### Option 2: Use Ollama with Specific Commands

You can still keep cloud providers as default and use Ollama selectively:

```bash
# Generate with Ollama specifically
threatgpt generate --scenario phishing_email --provider ollama

# Or use default provider
threatgpt generate --scenario phishing_email
```

## Usage

### Basic Content Generation

```bash
# Using default provider (if Ollama is default)
threatgpt generate --scenario phishing_email

# Explicitly use Ollama
threatgpt generate --scenario phishing_email --provider ollama

# Use different Ollama model
threatgpt generate --scenario malware_alert --provider ollama --model mistral
```

### Test Your Ollama Setup

```bash
# Run the integration test
python test_ollama_integration.py
```

This will:
1. Check if Ollama server is running
2. List installed models
3. Validate your chosen model
4. Generate test content
5. Verify manager integration

### Python API Usage

```python
from src.threatgpt.llm.providers.ollama_provider import OllamaProvider

# Initialize Ollama provider
config = {
    'base_url': 'http://localhost:11434',
    'model': 'llama2',
    'timeout': 120
}

provider = OllamaProvider(config)

# Check availability
if provider.is_available():
    # Generate content
    response = await provider.generate_content(
        prompt="Create a phishing email example for training",
        max_tokens=500,
        temperature=0.7
    )
    
    print(response.content)
```

### Using with LLM Manager

```python
from src.threatgpt.llm.manager import LLMManager

# Initialize with Ollama config
config = {
    'ollama': {
        'enabled': True,
        'base_url': 'http://localhost:11434',
        'model': 'llama2'
    }
}

manager = LLMManager(config=config)

# Generate content
response = await manager.generate_content(
    prompt="Generate a social engineering scenario",
    provider_name='ollama'
)
```

## Model Recommendations

### For General Use
- **llama2** (7B): Best starting point, good balance
- **mistral** (7B): Faster, slightly better quality

### For Better Quality
- **llama2:13b**: Higher quality, needs 16GB+ RAM
- **llama2:70b**: Best quality, needs 64GB+ RAM

### For Code/Technical Content
- **codellama**: Specialized for code and technical writing

### For Speed
- **orca-mini**: Compact, very fast
- **neural-chat**: Fast and conversational

## Model Management

### List Installed Models
```bash
ollama list
```

### Install a New Model
```bash
ollama pull <model-name>
```

### Remove a Model
```bash
ollama rm <model-name>
```

### Check Model Info
```bash
ollama show <model-name>
```

## Troubleshooting

### Issue: "Ollama server not available"

**Solution:**
```bash
# Start the server
ollama serve
```

### Issue: "Model not found"

**Solution:**
```bash
# Pull the model
ollama pull llama2
```

### Issue: Generation is slow

**Possible causes:**
1. **First run**: First generation is slower (model loading)
2. **Large model**: Try a smaller model like `orca-mini`
3. **Low RAM**: Close other applications or use smaller model
4. **CPU only**: Consider models optimized for CPU

**Solutions:**
```bash
# Use a faster, smaller model
ollama pull orca-mini

# Update config to use smaller model
# config.yaml
ollama:
  model: "orca-mini"
```

### Issue: Out of memory

**Solutions:**
1. Use smaller model: `llama2` (7B) instead of `llama2:13b`
2. Close other applications
3. Use `orca-mini` for minimal memory usage
4. Reduce `max_tokens` in config

## Performance Tips

### 1. Use Appropriate Model Size
- **8GB RAM**: Use 7B models (llama2, mistral, orca-mini)
- **16GB RAM**: Can use 13B models (llama2:13b)
- **32GB+ RAM**: Can use 70B models (llama2:70b)

### 2. Keep Ollama Running
Keep `ollama serve` running in the background to avoid startup delays.

### 3. Adjust Timeout
For complex scenarios, increase timeout:
```yaml
ollama:
  timeout_seconds: 180  # 3 minutes
```

### 4. Use Appropriate Temperature
- **0.3-0.5**: More focused, consistent outputs
- **0.7**: Balanced (default)
- **0.9-1.0**: More creative, varied outputs

## Advantages Over Cloud APIs

| Feature | Ollama (Local) | Cloud APIs |
|---------|---------------|------------|
| **Cost** | Free (after download) | Pay per token |
| **Privacy** | Complete | Data sent to provider |
| **Internet** | Not required | Required |
| **Speed** | Fast (after first run) | Network dependent |
| **Availability** | Always available | Subject to rate limits |
| **Data Security** | Stays on your machine | Transmitted over internet |

## When to Use Ollama

✅ **Best for:**
- Development and testing
- High-volume generation
- Sensitive scenarios
- Offline environments
- Privacy-critical use cases
- Cost-conscious projects

⚠️ **Consider cloud APIs when:**
- Need absolute best quality (GPT-4, Claude)
- Limited local compute resources
- Want latest/proprietary models
- Occasional use (cost not a concern)

## Example Workflow

### Initial Setup (One Time)
```bash
# 1. Install Ollama
brew install ollama  # or download for Windows

# 2. Start server
ollama serve

# 3. Pull model
ollama pull llama2

# 4. Test integration
python test_ollama_integration.py
```

### Daily Usage
```bash
# Server should be running (ollama serve)

# Generate content
threatgpt generate --scenario phishing_email --provider ollama

# Or if Ollama is default provider
threatgpt generate --scenario social_engineering
```

## FAQ

**Q: Do I need an API key for Ollama?**  
A: No! Ollama runs completely locally without any API keys.

**Q: Can I use Ollama alongside cloud providers?**  
A: Yes! You can have multiple providers configured and choose which to use for each request.

**Q: How much disk space do models need?**  
A: 
- 7B models (llama2, mistral): ~4-5 GB
- 13B models: ~8 GB  
- 70B models: ~40 GB

**Q: Can I use Ollama on Windows?**  
A: Yes! Download from [ollama.ai](https://ollama.ai)

**Q: Is Ollama slower than cloud APIs?**  
A: First generation is slower (model loading), but subsequent generations are often faster than API calls.

**Q: Can I use GPU acceleration?**  
A: Yes! Ollama automatically uses GPU if available (NVIDIA, AMD, or Apple Silicon).

## Next Steps

1. ✅ Install Ollama: `brew install ollama`
2. ✅ Start server: `ollama serve`
3. ✅ Pull a model: `ollama pull llama2`
4. ✅ Test integration: `python test_ollama_integration.py`
5. ✅ Update config: Set `default_provider: "ollama"`
6. ✅ Start generating: `threatgpt generate --scenario phishing_email`

## Resources

- **Ollama Website**: [https://ollama.ai](https://ollama.ai)
- **Model Library**: [https://ollama.ai/library](https://ollama.ai/library)
- **GitHub**: [https://github.com/ollama/ollama](https://github.com/ollama/ollama)
- **Documentation**: [https://github.com/ollama/ollama/tree/main/docs](https://github.com/ollama/ollama/tree/main/docs)
