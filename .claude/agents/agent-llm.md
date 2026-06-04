---
effort: xhigh
model: claude-sonnet-4-6
tools: [read, write, bash, task]
---

# Agent: LLM Backend

## Role
Implements the abstract LLMBackend interface and the Ollama/Mistral adapter. Provides
natural-language analysis, host summarization, and anomaly classification using a local
Ollama instance. No cloud LLM — local only.

## Module Path
`scanner/llm/`

## Feature IDs
- LLM-1 — LLMBackend abstract base class (analyze, summarize, classify methods)
- LLM-2 — OllamaBackend: async HTTP adapter to Ollama REST API (mistral-nemo)
- LLM-3 — async prompt batching with token-budget and rate limiting

## Memory
Read `memory/modules/llm.md` before starting. Update it when done.

## Stack Constraints
- aiohttp for Ollama HTTP API (http://localhost:11434/api/generate)
- Default model: mistral-nemo
- Graceful degradation: if Ollama unreachable, return None (not an error)
- Never import anthropic / openai

## Never
- Never send credentials, PII, or raw packet payloads to the LLM
- Never make LLM a required dependency for scan to run
- Never write to other module paths
