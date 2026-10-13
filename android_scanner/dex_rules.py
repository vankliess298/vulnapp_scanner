"""Evidence-based rules over Androguard 4.x encoded method instructions.

This is a bounded constant tracker, not a whole-program taint engine. It also
recognizes single initializer field writes and one-hop static crypto wrappers.
Unknown values and control-flow boundaries discard provenance.
"""

from dataclasses import dataclass
import re
from typing import Any, Dict, List, Tuple

from .models import Finding
from .rules import SECRET_PATTERNS


@dataclass
class _Constant:
    kind: str
    value: Any
    origin: str


def _secret_findings(value: str, source: str) -> List[Finding]:
    findings = []
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(value):
            # Avoid leaking the candidate credential into reports/logs.
            findings.append(Finding("hardcoded-secret", "Possible hardcoded secret", "high",
                f"A {name} pattern occurs in a DEX string. Static presence does not establish that it is live, valid or exploitable.",
                f"{name} pattern in string literal (value redacted)", source))
    return findings


def inspect_dex(dex: Any, source: str) -> Tuple[List[Finding], Dict[str, int], List[str]]:
    findings: List[Finding] = []
    warnings: List[str] = []
    counts = {"classes": 0, "methods": 0, "instructions": 0, "strings": 0}
    # Unreferenced pool strings still deserve inspection, but are distinguished
    # from strings attributed to an encoded class/method below.
    pool = list(dex.get_strings())
    counts["strings"] = len(pool)
    referenced_strings = set()
    methods = []
    field_writes = {}
    constructor_counts = {}
    summaries = {}
    contextual_methods = []
    for cls in dex.get_classes():
        counts["classes"] += 1
        for method in cls.get_methods():
            counts["methods"] += 1
            method_source = f"{source}:{method.get_class_name()}->{method.get_name()}{method.get_descriptor()}"
            methods.append((method, method_source))
            if method.get_name() == "<init>":
                owner = method.get_class_name()
                constructor_counts[owner] = constructor_counts.get(owner, 0) + 1
    for method, method_source in methods:
        try:
            instructions = list(method.get_instructions_idx())
            counts["instructions"] += len(instructions)
            writes, sinks = [], []
            initial = _parameter_registers(method)
            method_findings, references = _inspect_method(instructions, method_source,
                initial_registers=initial, field_writes=writes, parameter_sinks=sinks)
            findings.extend(method_findings)
            referenced_strings.update(references)
            branching = any(ins.get_name().startswith(("if-", "goto", "throw", "move-exception", "packed-switch", "sparse-switch"))
                            for _, ins in instructions)
            for field, opcode, value, receiver, location in writes:
                eligible = not branching and (
                    (method.get_name() == "<clinit>" and opcode == "sput-object") or
                    (method.get_name() == "<init>" and opcode == "iput-object" and receiver is not None
                     and receiver.kind == "this" and constructor_counts.get(method.get_class_name()) == 1))
                eligible = eligible and field.startswith(method.get_class_name() + "->")
                constant = None
                if eligible and value is not None and value.kind in {"string", "bytes"}:
                    constant = _Constant(value.kind, value.value,
                        f"initializer {location}: {field} <- {value.origin}")
                field_writes.setdefault(field, []).append(constant)
            # Only direct static dispatch, one hop, and unmodified byte-array
            # parameters. No virtual dispatch or recursive summary propagation.
            if sinks and "static" in _access_flags(method):
                summaries[_method_reference(method)] = sinks
            if any(ins.get_name() in {"iget-object", "sget-object"} or ins.get_name().startswith("invoke-static")
                   for _, ins in instructions):
                contextual_methods.append((method, method_source))
        except Exception as exc:
            warnings.append(f"Incomplete DEX method coverage ({method_source}): {str(exc)[:300]}")
    constants = {field: writes[0] for field, writes in field_writes.items()
                 if len(writes) == 1 and writes[0] is not None}
    # If a method could not be decoded, its unseen field writes could invalidate
    # any initializer assumption. Keep ordinary local findings only in that case.
    if warnings:
        constants = {}
    if constants or summaries:
        for method, method_source in contextual_methods:
            try:
                instructions = list(method.get_instructions_idx())
                method_findings, _ = _inspect_method(instructions, method_source,
                    initial_registers=_parameter_registers(method), field_constants=constants,
                    method_summaries=summaries)
                findings.extend(method_findings)
            except Exception as exc:
                warnings.append(f"Incomplete DEX contextual coverage ({method_source}): {str(exc)[:300]}")
    for index, value in enumerate(pool):
        value = str(value)
        if value not in referenced_strings:
            findings.extend(_secret_findings(value, f"{source}:string[{index}] (unattributed reference)"))
    unique = {(f.rule_id, f.source, f.evidence): f for f in findings}
    return list(unique.values()), counts, warnings


def _access_flags(method: Any) -> str:
    accessor = getattr(method, "get_access_flags_string", None)
    return accessor() if accessor else ""


def _method_reference(method: Any) -> str:
    return f"{method.get_class_name()}->{method.get_name()}{method.get_descriptor()}".replace(" ", "")


def _parameter_registers(method: Any) -> Dict[int, _Constant]:
    accessor = getattr(method, "get_code", None)
    code = accessor() if accessor else None
    if code is None:
        return {}
    register = code.get_registers_size() - code.get_ins_size()
    result = {}
    word_index = 0
    if "static" not in _access_flags(method):
        result[register] = _Constant("this", method.get_class_name(), "this receiver")
        register += 1
        word_index += 1
    descriptor = method.get_descriptor().replace(" ", "").split(")", 1)[0][1:]
    for parameter in re.findall(r"\[*L[^;]+;|\[*[ZBSCIFJD]", descriptor):
        if parameter == "[B":
            result[register] = _Constant("parameter", word_index, "byte-array parameter")
        width = 2 if parameter in {"J", "D"} else 1
        register += width
        word_index += width
    return result


def _crypto_constant_finding(value: _Constant, key: bool, location: str, sink: str = "") -> Finding:
    indirect = "initializer " in value.origin or bool(sink)
    title = "Hardcoded cryptographic key material" if key else "Constant cryptographic IV"
    if indirect:
        title = "Possible " + title[0].lower() + title[1:]
    description = (
        "Static indicator: literal-derived bytes reach a cryptographic key constructor. "
        "Embedded key material may be recoverable; verify runtime use." if key else
        "Static indicator: literal-derived bytes reach an IV constructor. Reuse can weaken modes requiring unique or unpredictable IVs; verify cipher mode and runtime use.")
    if indirect:
        description += " Bounded initializer/one-hop static-call evidence does not prove field immutability, runtime reachability or exploitation."
    evidence = f"{'SecretKeySpec' if key else 'IvParameterSpec'} byte-array argument <- {value.origin}"
    if sink:
        evidence += f"; static helper sink {sink}"
    evidence += " (value redacted)"
    return Finding("hardcoded-crypto-key" if key else "hardcoded-crypto-iv", title,
                   "high" if key else "medium", description, evidence, location)


def _inspect_method(instructions: List[Tuple[int, Any]], source: str, *,
                    initial_registers=None, field_writes=None, parameter_sinks=None,
                    field_constants=None, method_summaries=None) -> Tuple[List[Finding], set]:
    findings: List[Finding] = []
    references = set()
    registers: Dict[int, _Constant] = dict(initial_registers or {})
    loaded_fields = {}
    pending = None
    by_offset = dict(instructions)
    branch_targets = set()
    for offset, instruction in instructions:
        name = instruction.get_name()
        if name.startswith(("if-", "goto")):
            for operand in instruction.get_operands():
                if int(operand[0]) == 3:
                    branch_targets.add(offset + int(operand[1]) * 2)
        elif name in {"packed-switch", "sparse-switch"}:
            for operand in instruction.get_operands():
                if int(operand[0]) == 3:
                    payload = by_offset.get(offset + int(operand[1]) * 2)
                    if payload is not None:
                        branch_targets.update(offset + int(target) * 2 for target in payload.get_targets())
    for offset, instruction in instructions:
        name = instruction.get_name()
        location = f"{source}@0x{offset:x}"
        if offset in branch_targets or name == "move-exception":
            registers.clear()
            pending = None
        # Payload operands are not regular Dalvik operands.
        if name.endswith("-payload"):
            registers.clear()
            pending = None
            continue
        operands = instruction.get_operands()
        regs = [int(op[1]) for op in operands if int(op[0]) == 0]
        literals = [op[1] for op in operands if int(op[0]) == 1]
        resolved = [str(op[-1]) for op in operands if int(op[0]) >= 256 and len(op) >= 3]
        previous_pending, pending = pending, None
        if regs and not name.startswith(("invoke-", "iput", "sput", "aput")) and ("wide" in name or "-long" in name or "-double" in name):
            # Wide values overwrite two registers; do not retain a stale string
            # in the upper register when the lower one receives a long/double.
            registers.pop(regs[0] + 1, None)
        if name in {"const-string", "const-string/jumbo"} and regs and resolved:
            value = resolved[-1]
            registers[regs[0]] = _Constant("string", value, f"const-string @0x{offset:x}")
            references.add(value)
            findings.extend(_secret_findings(value, location))
        elif name.startswith("const") and regs and literals:
            registers[regs[0]] = _Constant("number", literals[0], f"{name} @0x{offset:x}")
        elif name.startswith("move-result") and regs:
            registers.pop(regs[0], None)
            if previous_pending is not None:
                registers[regs[0]] = previous_pending
        elif name.startswith("move") and len(regs) >= 2:
            value = registers.get(regs[1])
            registers.pop(regs[0], None)
            if value is not None:
                registers[regs[0]] = value
        elif name in {"iput-object", "sput-object"} and regs and resolved:
            if field_writes is not None:
                field_writes.append((resolved[-1], name, registers.get(regs[0]),
                                     registers.get(regs[1]) if len(regs) > 1 else None, location))
            loaded_fields.pop(resolved[-1], None)
        elif name in {"iget-object", "sget-object"} and regs and resolved:
            receiver = registers.get(regs[1]) if len(regs) > 1 else None
            registers.pop(regs[0], None)
            field = resolved[-1]
            value = (field_constants or {}).get(field)
            if value and (name == "sget-object" or (receiver is not None and receiver.kind == "this"
                                                   and field.startswith(receiver.value + "->"))):
                if field not in loaded_fields:
                    loaded_fields[field] = _Constant(value.kind, value.value, value.origin)
                registers[regs[0]] = loaded_fields[field]
        elif name == "new-array" and len(regs) >= 2:
            length = registers.get(regs[1])
            registers.pop(regs[0], None)
            if resolved and resolved[-1] == "[B" and length and length.kind == "number" and 0 < length.value <= 4096:
                registers[regs[0]] = _Constant("bytes", bytes(length.value), f"zero-initialized byte[{length.value}] @0x{offset:x}")
        elif name == "fill-array-data" and regs:
            value = registers.get(regs[0])
            targets = [int(op[1]) for op in operands if int(op[0]) == 3]
            payload = by_offset.get(offset + targets[0] * 2) if targets else None
            if value and value.kind == "bytes" and payload is not None:
                data = bytes(payload.get_data())
                if len(data) >= len(value.value):
                    value.value = data[:len(value.value)]
                    value.origin = f"constant byte-array payload @0x{offset:x}"
                else:
                    registers.clear()
            else:
                registers.clear()
        elif name.startswith("invoke-"):
            target = resolved[-1].replace(" ", "") if resolved else ""
            args = [registers.get(reg) for reg in regs]
            # getBytes does not expose the underlying string as mutable data.
            if target in {"Ljava/lang/String;->getBytes()[B", "Ljava/lang/String;->getBytes(Ljava/lang/String;)[B", "Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B"}:
                if args and args[0] and args[0].kind == "string":
                    pending = _Constant("bytes", args[0].value, args[0].origin + " -> String.getBytes")
            elif target.startswith("Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;"):
                if args and args[0] and args[0].kind == "string":
                    algorithm = args[0].value
                    parts = algorithm.upper().split("/")
                    if parts[0] in {"DES", "DESEDE", "RC4", "ARC4"} or (parts[0] == "AES" and (len(parts) == 1 or parts[1] == "ECB")):
                        findings.append(Finding("weak-crypto", "Weak cipher configuration", "high",
                            "A constant weak cipher/mode is passed to Cipher.getInstance (bare AES uses the provider's default, commonly ECB). Review its security use; static evidence does not demonstrate exploitation.",
                            f"Cipher.getInstance({algorithm!r}); {args[0].origin}"[:500], location))
            elif target.startswith("Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;"):
                if args and args[0] and args[0].kind == "string" and args[0].value.upper().replace("-", "") in {"MD5", "SHA1"}:
                    findings.append(Finding("weak-crypto", "Weak hash algorithm reference", "medium",
                        "A collision-weakened hash is passed to MessageDigest.getInstance. Review whether it protects security-sensitive data; non-security checksums may be intentional.",
                        f"MessageDigest.getInstance({args[0].value!r}); {args[0].origin}", location))
            elif target.startswith("Ljavax/crypto/spec/SecretKeySpec;-><init>([B") or target.startswith("Ljavax/crypto/spec/IvParameterSpec;-><init>([B"):
                key = "SecretKeySpec" in target
                if len(args) > 1 and args[1] and args[1].kind == "bytes" and len(args[1].value):
                    findings.append(_crypto_constant_finding(args[1], key, location))
                elif len(args) > 1 and args[1] and args[1].kind == "parameter" and parameter_sinks is not None:
                    parameter_sinks.append((args[1].value, key, location))
            else:
                if name.startswith("invoke-static"):
                    for index, key, sink in (method_summaries or {}).get(target, []):
                        if index < len(args) and args[index] and args[index].kind == "bytes" and len(args[index].value):
                            findings.append(_crypto_constant_finding(args[index], key, location, sink))
                # An unknown call can mutate byte arrays passed by reference.
                for arg in args:
                    if arg is not None and arg.kind in {"bytes", "parameter"}:
                        arg.kind = "unknown"
                        for reg in list(registers):
                            if registers[reg] is arg:
                                del registers[reg]
        elif name.startswith("aput"):
            # Even a single unknown write invalidates all aliases of the array.
            value = registers.get(regs[1]) if len(regs) > 1 else None
            if value is not None:
                value.kind = "unknown"
            for reg in list(registers):
                if registers[reg] is value:
                    del registers[reg]
        elif name.startswith(("if-", "goto", "return", "throw", "packed-switch", "sparse-switch")):
            registers.clear()
        elif name == "check-cast":
            pass
        elif regs and not name.startswith(("iput", "sput", "monitor-", "nop")):
            # A load, arithmetic operation, new instance, etc. overwrites its
            # destination. Never let an earlier literal survive that assignment.
            registers.pop(regs[0], None)
    return findings, references
