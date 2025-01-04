#!/usr/bin/env python3

import argparse
from typing import Optional
import logging
import binascii
from pathlib import Path
import re
from dataclasses import dataclass
from enum import Enum

from elftools.elf.elffile import ELFFile
from elftools.dwarf.die import DIE
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.dwarf.constants import *
from elftools.dwarf.compileunit import CompileUnit

logging.basicConfig(level=logging.INFO)


class CodeBlockInstanceType(Enum):
    REGULAR_FUNCTION = "REGULAR_FUNCTION"
    OUT_OF_LINE = "OUT_OF_LINE"
    INLINE_EXPANSION = "INLINE_EXPANSION"


@dataclass(frozen=True)
class CodeBlockInstance:
    owner_cu: Path  # compilation unit that the code block belongs to
    expansion_cu: Path  # compilation unit that expands inline
    function_name : str
    first_insn_file_offset: int # offset inside ELF file that contains first instruction
    last_insn_excl_file_offset: int # first byte that does *not* belong to a function
    type: CodeBlockInstanceType

    def __post_init__(self):
        assert isinstance(self.owner_cu, Path)
        assert self.first_insn_file_offset >= 0
        assert self.last_insn_excl_file_offset > self.first_insn_file_offset
        assert isinstance(self.type, CodeBlockInstanceType)
        assert (self.expansion_cu is not None) == (self.type == CodeBlockInstanceType.INLINE_EXPANSION)

    def to_csv(self, simplified_cu_path: bool = True) -> str:
        cu = self.owner_cu if not simplified_cu_path else self.owner_cu.relative_to(self.owner_cu.parent.parent.parent)
        return f"{self.type.value},{hex(self.first_insn_file_offset)},{hex(self.last_insn_excl_file_offset)},{self.function_name},{cu}"

    @staticmethod
    def csv_header() -> str:
        return "ENTRY_TYPE,FILE_START_OFFSET,FILE_END_OFFSET,SYMBOL_NAME,COMPILATION_UNIT_PATH"

def get_build_id_if_present(elf: Path|ELFFile) -> Optional[str]:
    """
    We return 'str' instead of bytes, to easily strcmp with a string returned by `file` command,
    or by a 'bpf_get_stack(flags=BPF_F_USER_BUILD_ID)' (see https://man7.org/linux/man-pages/man7/bpf-helpers.7.html).
    """
    if not isinstance(elf, ELFFile):
        elf = ELFFile.load_from_path(str(elf))

    if not (section := elf.get_section_by_name(".note.gnu.build-id")):
        return
    data = section.data()
    assert len(data) == 36
    build_id: bytes = data[16:]
    return binascii.hexlify(bytearray(build_id)).decode("ascii")


def handle_elf(elf_file: Path, exclude_regex: Optional[str], include_regex: Optional[str], cu_infix: Optional[str], detailed_inline_expansion: bool, verbose: bool):
    with open(str(elf_file), 'rb') as f:
        elf = ELFFile(f)
        if verbose and (build_id := get_build_id_if_present(elf)):
            print(f"# BuildID={build_id}")
        if not elf.has_dwarf_info():
            raise ValueError("No DWARF information found in the file.")
        if elf.get_dwarf_info().debug_info_sec is None:
            raise ValueError("No DWARF information found in the file.")
        print(CodeBlockInstance.csv_header())
        for i, cu in enumerate(elf.get_dwarf_info().iter_CUs()):
            die = cu.get_top_DIE()
            source_path = die.get_full_path()
            if cu_infix:
                # user limited the filename scope from command line
                if not cu_infix in source_path:
                    continue
                logging.info(f"cu-infix match: {source_path}")
            dump_symbols_recursive(die=die, exclude_regex=exclude_regex, include_regex=include_regex, detailed_inline_expansion=detailed_inline_expansion)

def die_try_get_name(die: DIE) -> Optional[str]:
    """
    NOTE: sometimes both DW_AT_name and DW_AT_linkage_name are defined, let the latter take priority.
    """
    name = die.attributes.get('DW_AT_linkage_name') or die.attributes.get('DW_AT_name')
    if not name:
        return None
    return name.value.decode('utf-8')


def dwarf_find_code_block_start_end(dwarfinfo: DWARFInfo, die: DIE) -> Optional[tuple[int, int]]:
    """
    returned value forms [start, end] ('end' is *not* included in the 'die').

    from specs:

    The value of the DW_AT_low_pc attribute is the address of the first instruction associated with the entity.
    If the value of the DW_AT_high_pc is of class address, it is the address of the first location past the
    last instruction associated with the entity; if it is of class constant, the value is an unsigned integer
    offset which when added to the low PC gives the address of the first location past the last instruction
    associated with the entity.

    see also https://stackoverflow.com/questions/20097138/dwarf-info-seem-to-be-wrong-for-dw-at-high-pc-with-gcc-4-8-2
    """

    if not (start := die.attributes.get("DW_AT_low_pc") or die.attributes.get("DW_AT_entry_pc")):
        assert die.attributes.get("DW_AT_ranges") is None
        return None

    # we expect either 'DW_AT_high_pc' or 'DW_AT_ranges' present.

    start_addr = start.value
    del start

    if (end := die.attributes.get("DW_AT_high_pc")):
        if not (form := end.form).startswith("DW_FORM_"):
            raise NotImplementedError(form)

        if "data" in form:
            end_addr = start_addr + end.value
        elif "addr" in form:
            end_addr = end.value
            assert end_addr >= 0
        else:
            raise NotImplementedError(form)

        # check if possibly function was optimized out, but the DIE is still there.
        # https://github.com/llvm/llvm-project/blob/02b30128e8e87795b9262035a48990648cbec586/llvm/lib/DebugInfo/DWARF/DWARFVerifier.cpp#L616
        if start_addr == end_addr:
            return None

        return start_addr, end_addr

    if not (ranges_die := die.attributes.get("DW_AT_ranges")):
        raise NotImplementedError()

    del start_addr

    allranges = dwarfinfo.range_lists()
    ranges = allranges.get_range_list_at_offset(ranges_die.value)


    variant_with_base_address_entry : bool = hasattr(ranges[0], "base_address")
    #
    # [
    #  BaseAddressEntry(entry_offset=12, base_address=4196),
    #  RangeEntry(entry_offset=21, entry_length=3, begin_offset=0, end_offset=0, is_absolute=False),
    #  RangeEntry(entry_offset=24, entry_length=3, begin_offset=0, end_offset=3, is_absolute=False)
    # ]
    #
    # or
    #
    # [
    #  RangeEntry(entry_offset=352, entry_length=16, begin_offset=12622992, end_offset=12622994, is_absolute=False),
    #  RangeEntry(entry_offset=368, entry_length=16, begin_offset=12622998, end_offset=12623012, is_absolute=False)
    # ]


    # NOTE: for ranges we discard chunking/gaps information, as we don't need it at the moment.

    if variant_with_base_address_entry:
        assert len(ranges) > 1
        assert not hasattr(ranges[1], "base_address")

        start_addr = ranges[0].base_address
        ranges = ranges[1:]

        end_addr = start_addr
        for x in ranges:
            if x.begin_offset == x.end_offset:
                # range was invalidated (probably optimized out) during linking
                # https://github.com/llvm/llvm-project/blob/02b30128e8e87795b9262035a48990648cbec586/llvm/lib/DebugInfo/DWARF/DWARFVerifier.cpp#L616
                continue
            end_addr = max(end_addr, end_addr + x.end_offset)
    else:
        assert not any(hasattr(x, "base_address") for x in ranges)
        start_addr, end_addr = 0xffff_ffff_ffff_ffff, -1
        for x in ranges:
            try:
                start_addr = min(start_addr, x.end_offset)
            except:
                raise ValueError(ranges)
            end_addr = max(end_addr, x.end_offset)

    if start_addr == end_addr:
        return None

    assert end_addr >= start_addr

    return start_addr, end_addr

def handle_inline_subroutine(die: DIE, include_regex: Optional[str], exclude_regex: Optional[str]):
    assert die.tag == "DW_TAG_inlined_subroutine"

    assert die.attributes.get("DW_AT_abstract_origin")
    origin_die : DIE = die.get_DIE_from_attribute("DW_AT_abstract_origin")

    name = die_try_get_name(origin_die)
    if not name:
        specs_die : DIE = origin_die.get_DIE_from_attribute("DW_AT_specification")
        name = die_try_get_name(specs_die)

    if not (maybe_start_end := dwarf_find_code_block_start_end(dwarfinfo=die.cu.dwarfinfo, die=die)):
        logging.debug(f"discarding symbol '{name}' as it's missing code start/end address info")
        return

    start, end = maybe_start_end
    assert end >= start

    if (exclude_regex and re.search(exclude_regex, name)) or (include_regex and not re.search(include_regex, name)):
        return

    entry = CodeBlockInstance(
        function_name=name,
        type=CodeBlockInstanceType.INLINE_EXPANSION,
        owner_cu=get_source_path(die=origin_die),
        expansion_cu=get_source_path(die=die),
        first_insn_file_offset=start,
        last_insn_excl_file_offset=end,
    )

    print(entry.to_csv())

def get_source_path(die: DIE) -> Path:
    return Path(die.cu.get_top_DIE().get_full_path())

def handle_subprogram(die: DIE, include_regex: Optional[str], exclude_regex: Optional[str]):
    assert die.tag == "DW_TAG_subprogram"

    name = die_try_get_name(die)
    if not name:
        logging.debug("discarding unnamed symbol")
        return

    if (exclude_regex and re.search(exclude_regex, name)) \
    or (include_regex and not re.search(include_regex, name)):
        logging.debug(f"discarding symbol '{name}' on user request (regex mismatch)")
        return

    assert not die.attributes.get("DW_AT_ranges") # should be only valid for inline expansions.
    maybe_addr_pair = dwarf_find_code_block_start_end(dwarfinfo=die.cu.dwarfinfo, die=die)
    if not maybe_addr_pair:
        logging.debug(f"discarding '{name}' as it corresponds to an external symbol")
        return

    start_addr, end_addr = maybe_addr_pair

    # check if the given subprogram is a concrete function, not the abstract one (due to inlining - see section 3.3.8 from https://dwarfstd.org/doc/DWARF5.pdf)

    # for more details grep 'out-of-line instance' in https://dwarfstd.org/doc/DWARF5.pdf
    is_out_of_line_instance = (die.attributes.get("DW_AT_abstract_origin") is not None)

    is_regular_function = (not is_out_of_line_instance) and ( (inline_attr := die.attributes.get("DW_AT_inline") is None) or inline_attr != DW_INL_not_inlined)

    if not (is_out_of_line_instance or is_regular_function):
        raise NotImplementedError()

    code_block_type = CodeBlockInstanceType.OUT_OF_LINE if is_out_of_line_instance else CodeBlockInstanceType.REGULAR_FUNCTION

    entry = CodeBlockInstance(
        owner_cu=get_source_path(die),
        expansion_cu=None,
        function_name=name,
        first_insn_file_offset=start_addr,
        last_insn_excl_file_offset=end_addr,
        type=code_block_type,
    )

    print(entry.to_csv())
    del entry


def dump_symbols_recursive(die: DIE, include_regex: Optional[str], exclude_regex: Optional[str], detailed_inline_expansion: bool):

    if die.tag == "DW_TAG_subprogram":
        handle_subprogram(die=die, include_regex=include_regex, exclude_regex=exclude_regex)
    elif detailed_inline_expansion and (die.tag == "DW_TAG_inlined_subroutine"):
        handle_inline_subroutine(die=die, include_regex=include_regex, exclude_regex=exclude_regex)

    for child in die.iter_children():
        dump_symbols_recursive(die=child, include_regex=include_regex, exclude_regex=exclude_regex, detailed_inline_expansion=detailed_inline_expansion)

def main():
    parser = argparse.ArgumentParser(description="Extract function definitions and inline expansions file offsets, based on DWARF debug info.")
    parser.add_argument("elf_file", type=Path, help="Path to an ELF file. It must contain debug info.")
    parser.add_argument("-c", "--cu-infix", help="Infix of compilation unit to dump debug info from, e.g. filename.cc")
    parser.add_argument("-d", "--detailed-inline-expansion", action="store_true", help="Proper inline expansion dump. Can cause an order of magnitude more lines printed.")
    parser.add_argument("-v", "--verbose", action="store_true", help="output will contain additional metadata lines, they all start from '# ' mark.")

    # NOTE: 're.search' should be faster than demangling every single symbol.
    parser.add_argument("-e", "--exclude-regex", help="Infix of symbol name to be excluded (should not be dismangled!)")
    parser.add_argument("-i", "--include-regex", help="Infix of symbol name to be included (should not be dismangled!)")
    parser.add_argument("--no-std", action="store_true", help="Specialized version of '--exclude-regex' that excludes all 'std::' things.")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output")

    args = parser.parse_args()
    if args.no_std:
        if args.exclude_regex:
            raise RuntimeError("'--exclude-regex' and '--no-std' are mutually exclusive!")
        args.exclude_regex = '_ZNRSt|_ZSt|_ZNSt|_ZNKSt|_ZNSa|_ZZNSt|_ZN4base|_ZN9__gnu_cxx'

    del args.no_std

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, force=True)
    del args.debug

    handle_elf(**vars(args))
    
if __name__ == "__main__":
    main()
