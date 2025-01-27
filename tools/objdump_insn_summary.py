#!/usr/bin/env python3

import argparse
from dataclasses import dataclass
from typing import Optional
import subprocess
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)

# NOQA - mostly generated by LLM.

# Function for running shell commands
def run_shell(cmd: str) -> tuple[str, str]:
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
    stdout, stderr = process.communicate()
    if (ecode := process.returncode):
        raise ValueError(f"Command <{cmd}> exited with {ecode}")
    return stdout, stderr

# Dataclass for storing parsed instruction information
@dataclass
class ObjdumpInsnParsed:
    insn_name: str
    full_line: str
    offset_from_section_start: int

# Function to parse objdump output and map sections to instructions
def parse_objdump_output(objdump_output: str) -> dict[str, list[ObjdumpInsnParsed]]:
    sections = {}
    current_section = None
    section_shift = 0

    for line in objdump_output.splitlines():
        if not line.strip() or "file format " in line:
            continue

        tokens = line.split()

        # Case 1: Section Header
        # Expected format: "Disassembly of section .text:"
        if line.startswith("Disassembly of section "):
            # Extract the section name (e.g., ".text")
            current_section = line.split()[-1][:-1]  # Remove the trailing colon
            sections[current_section] = []
            continue

        # Case 2: Function Header (not relevant for section processing)
        # Expected format: "0000000000001050 <function_name> (File Offset: 0x1050):"
        if len(tokens) >= 5 and tokens[2].startswith("<") and tokens[2].endswith(">") and tokens[-1].endswith("):"):
            vma = int(tokens[0], 16)
            file_offset = int(tokens[4][:-2], 16)
            section_shift = vma - file_offset
            continue

        # Case 3: Instruction Line
        # Expected format: "  402000: push"
        if len(tokens) >= 2 and tokens[0].endswith(":"):
            insn_vma = int(tokens[0][:-1], 16)  # Remove the trailing ':' from the address
            offset_from_section_start = insn_vma - section_shift

            # Instruction name is the second token
            insn_name = tokens[1]

            sections[current_section].append(
                ObjdumpInsnParsed(
                    insn_name=insn_name,
                    full_line=line.strip(),
                    offset_from_section_start=offset_from_section_start
                )
            )

    return sections

# Function to summarize instructions within a given range
def summarize_instructions(sections: dict[str, list[ObjdumpInsnParsed]], range_start: int, range_end: int):
    instruction_count = {}
    total_instructions = 0

    for section_name, instructions in sections.items():
        for insn in instructions:
            if range_start <= insn.offset_from_section_start < range_end:
                instruction_count[insn.insn_name] = instruction_count.get(insn.insn_name, 0) + 1
                total_instructions += 1

    print(f"range: (0x{range_start:x}, 0x{range_end:x})")
    print(f"num_instructions: {total_instructions}")
    print("instructions summary:")
    for insn_name, count in sorted(instruction_count.items(), key=lambda x: x[1], reverse=True):
        print(f"{insn_name.ljust(10)} {count}")

def get_build_id_if_present(elf: Path) -> Optional[str]:
    assert elf.exists()
    stdout, _ = run_shell(f"file {elf}")
    words = stdout.split()
    starswith_magic = "BuildID[sha1]="
    matches = [x for x in words if x.startswith(starswith_magic)]
    if len(matches) != 1:
        raise ValueError(f"Was expecting a single match for word starting with {starswith_magic}, got {len(matches)} instead")
    # strip everything before '=' and a trailing comma
    res = matches[0].split("=")[-1][:-1]
    return res

# Main function to parse arguments and run the script
def main():
    hex_or_min = lambda _val: 0 if _val == "-" else int(_val, 16)
    hex_or_max = lambda _val: 0xffffffff_ffffffff if _val == "-" else int(_val, 16)
    parser = argparse.ArgumentParser(description="Parse ELF file and summarize CPU instructions.")
    parser.add_argument("elf_file", type=Path, help="Path to the ELF file.")
    parser.add_argument("range_start", type=hex_or_min, help="Start of the file offset range (inclusive, in hex) or '-' if RANGE_MIN should be used.")
    parser.add_argument("range_end", type=hex_or_max, help="End of the file offset range (exclusive, in hex)  or '-' if RANGE_MAX should be used.")
    parser.add_argument("-d", "--objdump-executable", type=Path, help="path to 'objdump' executable, useful if using one from cross-toolchain (e.g. RISC-V)", default="objdump")
    args = parser.parse_args()

    if build_id := get_build_id_if_present(args.elf_file):
        cache_fname = f"objdump_buildid_{build_id}"
    else:
        import hashlib
        hash = hashlib.md5(args.elf_file.read_bytes()).hexdigest()
        cache_fname = f"objdump_md5_{hash}"

    cache_dir = Path(__file__).parent.absolute()
    cache_file = cache_dir / cache_fname

    if not cache_file.exists():
        logging.info(f"cache not yet there (missing {cache_file})")
        cmd = f"{args.objdump_executable}  -M no-aliases --no-show-raw-insn -Fd {args.elf_file} > {cache_file}"
        run_shell(cmd)
    else:
        logging.info(f"cache will be reused ({cache_file})")

    sections = parse_objdump_output(cache_file.read_text())
    summarize_instructions(sections, args.range_start, args.range_end)


if __name__ == "__main__":
    main()
