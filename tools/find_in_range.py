#!/usr/bin/env python3

import subprocess
from pathlib import Path
import logging
from bisect import bisect_right
from typing import Optional
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)

def run_shell(cmd: str) -> tuple[str, str]:
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
    stdout, stderr = process.communicate()
    if (ecode := process.returncode):
        raise ValueError(f"Command <{cmd}> exited with {ecode}")
    return stdout, stderr

@dataclass
class InputFmtCsvDsl:
    start_field: int
    end_field: Optional[int]
    size_field: Optional[int]
    fmt: str

    def __post_init__(self):
        assert len([x for x in [self.end_field, self.size_field] if x is not None]) == 1
        assert isinstance(self.end_field, int) or isinstance(self.size_field, int)
    
    def from_str(s: str) -> "InputFmtCsvDsl":
        tokens = s.split(",")
    
        assert all([x in ["", "start", "end", "size"] for x in tokens])
    
        nonempty_tokens = [x for x in tokens if x != ""]
        assert len(set(nonempty_tokens)) == len(nonempty_tokens)
    
        assert "start" in tokens

        if "end" in tokens:
            size_field = None
            end_field = tokens.index("end")
            assert "size" not in tokens
        elif "size" in tokens:
            size_field = tokens.index("size")
            end_field = None
            assert "end" not in tokens

        return InputFmtCsvDsl(
            fmt=s,
            start_field=tokens.index("start"),
            size_field=size_field,
            end_field=end_field,
        )

    def csv_min_num_of_tokens(self) -> int:
        """
        sanity check for csv input to be possibly supported by this DSL
        """
        return 1 + max([x for x in [self.start_field, self.end_field, self.size_field] if x is not None])


def parse_line(fmt: InputFmtCsvDsl, line: str) -> tuple[int, int, str]:
    """
    returns (start, end, full_line)
    """
    tokens = line.split(",")
    if len(tokens) < (min_num_tokens := fmt.csv_min_num_of_tokens()):
        raise RuntimeError(f"format '{fmt.fmt}' requires at least {min_num_tokens} comma-separated fields, however input line '{line}' has {len(tokens)}")
    start = int(tokens[fmt.start_field], 16)
    if fmt.end_field is not None:
        end = int(tokens[fmt.end_field], 16)
    elif fmt.size_field is not None:
        end = start + int(tokens[fmt.size_field], 16)
    else:
        assert False

    return start, end, line


def main(input: Path, value: int, fmt: str, exclude_comments: bool, skip_header: bool, raise_on_overlap: bool = False, raise_on_duplicate: bool = False):

    # NOTE: otherwise membership check logic (and probably data structure) needs to be changed.
    if not raise_on_overlap:
        logging.warning("raise_on_overlap=False, however current implementation does *not* handle correctly overlapping regions (will not return all matches, will return a random one instead)")

    lines = input.read_text().splitlines()

    if not lines:
        raise ValueError("Expected at least one line")

    # create structured data.
    data = dict()
    fmt_cls = InputFmtCsvDsl.from_str(fmt)
    header_skipped = False
    for i, l in enumerate(lines):
        if l.startswith("#") and exclude_comments:
            continue
        if skip_header and not header_skipped:
            header_skipped = True
            continue
        try:
            start, end, full_line = parse_line(fmt=fmt_cls, line=l)
        except:
            print(f"ERR: line '{l}' cannot be parsed with fmt={fmt} ({fmt_cls})")
            exit(1)
        # if not (start.startswith("0x") and end.startswith("0x")):
        #     raise ValueError(f"Line {i}: ({start}, {end}) should start with '0x' to avoid confusion with decimal values.")
        # start, end = int(start, 16), int(end, 16)
        # if raise_on_duplicate and data.get(start):
        #     raise ValueError(f"Key duplicated: {hex(start)}")
        # assert end > start
        data[start] = ((size := end - start), full_line)
    data = sorted([(k, *v) for k, v in data.items()])

    # do sanity check.
    if raise_on_overlap:
        for d1, d2 in zip(data, data[1:]):
            if d2[0] in range(d1[0], d1[0] + d1[1]):
                raise ValueError(f"Overlap for keys {hex(d1[0])} and {hex(d2[0])}")

    # find matching region.
    # NOTE: the the big const is to properly handle value == data[0].key
    idx = bisect_right(data, (value, 0x999999999999999))
    if idx == 0:
        raise ValueError(f"Range not found: too small searched value. Lowest (key, size) = {data[0][:2]}")
    
    candidate = data[idx - 1]
    candidate_full_line = candidate[-1]

    if value >= candidate[0] + candidate[1]:
        raise ValueError(f"Range not found. Closest match was '{candidate_full_line}'")

    start, end, *rest = candidate

    print(candidate_full_line)


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(usage="""
Find @value in given @input CSV file.
Each @input file's line must contain following information:
* start:int
* either end:int or size:int
* rest of information, irrelevant for algorithm.
Each @input file's line represents a range [start, end) or [start, start+size).

The script finds range that includes @value, and once found it prints the full line to stdout.
The script can be considered as 'addr2line' but for 'dwarfseeker.py' output (probably with '--exclude-comments' and '--skip-header' set)
""")
    parser.add_argument("input", type=Path)
    parser.add_argument("value", type=lambda x: int(x, 16))
    parser.add_argument("-nc", "--exclude-comments", action="store_true", help="skip lines starting with '#' symbol.")
    parser.add_argument("-nh", "--skip-header", action="store_true", help="skip first header line")
    parser.add_argument("--fmt", type=str, default=",start,end")
    main(**vars(parser.parse_args()))
