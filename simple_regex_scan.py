#!/usr/bin/env python3

import argparse
import glob
import os
import re
import textwrap
from termcolor import colored, cprint
from terminaltables import AsciiTable
import chardet

# Definition of predefined regexes
UNSAFE_FUNCTIONS = ["system", "shell_exec", "exec", "passthru", "eval", "popen", "unserialize", "file_put_contents"]
UNSAFE_FUNCTION_REGEX = re.compile(r"([ \t]*(%s)\s*\(.*\$.*\).*)" % "|".join(UNSAFE_FUNCTIONS))
UNSAFE_FUNCTION_REGEX_DIRECT_INPUT = re.compile(r"([ \t]*(%s)\s*\(.*\$_(GET|POST|COOKIE)\[.*\].*\).*)" % "|".join(UNSAFE_FUNCTIONS))
FILE_INCLUSION_FUNCTIONS = ["include", "include_once", "require", "require_once"]
FILE_INCLUSION_REGEX = re.compile(r"([ \t]*(%s)[\( ][^=\n]*\$.*)" % "|".join(FILE_INCLUSION_FUNCTIONS))
COOKIE_REGEX = re.compile(r"([ \t]*(\$_COOKIE\[.*\]))")
SQLI_REGEX = re.compile(r"(SELECT.*FROM.*WHERE.*(\$\S+).*)")
XSS_REGEX = re.compile(r".*(echo.*(\$_(GET|POST|COOKIE|REQUEST)\[\s*\S*\s*\]).*;?)")


def crawl(paths, extension, use_color):
    """
    Crawl the given list of paths and return a list of all discovered files.
    Directory paths are traversed recursively and every found file ending
    with the given extension is returned.
    """

    discoverd_files = []
    full_paths = set()

    my_print("[+] Started scanning ...", "green", use_color)
    # undo globbing to get paths without wildcards
    for path in paths:
        if "*" in path:
            full_paths |= set(glob.glob(path))
        else:
            full_paths.add(path)

    # crawl every path
    for path in full_paths:
        if not os.path.exists(path):
            my_print("[-] Directory / File does not exist: %s" % path, "red", use_color)

        if os.path.isfile(path):
            # append files
            discoverd_files.append(path)
        else:
            # search directories recursively for new files
            for root, _, files in os.walk(path):
                for file in files:
                    if not file.endswith(extension):
                        continue
                    absfile = os.path.join(root, file)
                    discoverd_files.append(absfile)

    filetype = extension.replace(".", "").upper()
    my_print("[+] Scanning complete: %d %s files found" % (len(discoverd_files), filetype), "blue", use_color)
    return discoverd_files


def scan(files, regexes, use_color):
    """
    Scan the given files for code patterns specified by the given regexes.
    Return all occurences as list of (file, re_type, code_str, lineno) tuples.
    """

    results = []
    my_print("[+] Started analysis ...", "green", use_color)
    for file in files:
        with open(file, "rb") as f:
            # read binary file content, determine encoding and decode appropriately
            content = f.read()
            encoding = chardet.detect(content)["encoding"]
            if encoding:
                content = content.decode(encoding)
            else:
                try:
                    content = content.decode()
                except UnicodeDecodeError:
                    # if content cannot be decoded, skip the file
                    continue

        # match all used regexes against the file contents
        findings = {}
        for title, regex in regexes.items():
            finding = regex.findall(content, re.DOTALL | re.MULTILINE)
            if finding:
                findings[title] = finding

        # iterate over every match and find corresponding line in code
        for type_, finding_set in findings.items():
            # stores how many times the same match was found across iterations
            found_counts = {}
            for match in finding_set.copy():
                # extract the broad finding of the regex match ...
                if isinstance(match, (list, tuple)):
                    # ... which is the first group in a mutli-element match
                    finding = match[0]
                else:
                    # ... which is the match itself if it is atomic
                    finding = match

                if finding not in found_counts:
                    found_counts[finding] = 0

                # stores the lines that have the longest string match with the finding
                longest_line_matches = {}

                # iterate over all lines in the file and find the longest string matches
                for i, line in enumerate(content.splitlines()):
                    line_match_length = None
                    if line and line in finding:
                        line_match_length = len(line)
                    elif line and finding in line:
                        line_match_length = len(finding)

                    if line_match_length:
                        if not longest_line_matches or list(longest_line_matches.values())[0] == line_match_length:
                            longest_line_matches[i] = line_match_length
                        elif list(longest_line_matches.values())[0] < line_match_length:
                            longest_line_matches = {i: line_match_length}

                # if the regex match was found in the code, add it to the results
                if longest_line_matches:
                    # determine on what line the match was found, skip already matched lines
                    sorted_line_matches = sorted(longest_line_matches.keys())
                    lineno = sorted_line_matches[found_counts[finding]] + 1
                    found_counts[finding] += 1

                    # textwrap the finding to better fit terminal size
                    code_simple_whitespace = " ".join(finding.strip().split())
                    code = "\n".join(textwrap.wrap(code_simple_whitespace, 80))

                    # if there is a second group in the match, highlight it
                    if use_color and isinstance(match, tuple) or isinstance(match, list):
                        code = code.replace(match[1], colored(match[1], "red"))

                    # append the finding to the results
                    results.append((file, type_, code, lineno))

    return results


def get_regexes(args):
    """ Return all regexes that are to be used for the scan """

    # include predefined regexes as specified by the user
    if args.all_regexes:
        regexes = {
            "function usage": UNSAFE_FUNCTION_REGEX,
            "file inclusion": FILE_INCLUSION_REGEX,
            "cookie usage": COOKIE_REGEX,
            "sqli": SQLI_REGEX,
            "xss": XSS_REGEX
        }
    else:
        regexes = {}
        if args.unsafe_func:
            regexes["function usage"] = UNSAFE_FUNCTION_REGEX
        if args.file_inclusion:
            regexes["file inclusion"] = FILE_INCLUSION_REGEX
        if args.cookie_usage:
            regexes["cookie usage"] = COOKIE_REGEX
        if args.sqli:
            regexes["sqli"] = SQLI_REGEX
        if args.xss:
            regexes["xss"] = XSS_REGEX

    # include user-custom regexes if any
    if args.custom_regex:
        for i, regex in enumerate(args.custom_regex):
            regexes["custom regex %d" % i] = regex

    return regexes


def parse_args():
    """ Parse the supplied command line arguments and return the result """

    # create arg parser and add 'normal' arguments
    parser = argparse.ArgumentParser(description="Search files for insecure code patterns via regular expressions", epilog="Example: %(prog)s -ufs -i /var/www/html/mycms")
    parser.add_argument("-c", "--custom-regex", nargs="+", help="Specify custom regexes to use in addition to the default ones")
    parser.add_argument("-e", "--extension", default="php", help="Specify the file extension of files to search (php by default)")
    parser.add_argument("--no-color", action="store_true", help="Do not color the output")
    parser.add_argument("-i", "--input", nargs="+", help="Input one or more files or directories to search", required=True)

    # add arguments for the usage of the predefined regexes
    predef_regexes = parser.add_argument_group("predefined regexes", "predefined regexes that can be used")
    predef_regexes.add_argument("-A", "--all-regexes", default=True, action="store_true", help="Use all predefined regexes (default if no predefined regex is explicitly specified)")
    predef_regexes.add_argument("-N", "--no-regexes", default=False, action="store_true", help="Use none of the predefined regexes")
    predef_regexes.add_argument("-u", "--unsafe-func", action="store_true", help="Regex that indicates unsafe function usage with a variable, e.g. \"%s\"" % colored("eval($_REQUEST['cmd'])", "yellow"))
    predef_regexes.add_argument("-f", "--file-inclusion", action="store_true", help="Regex that indicates file inclusion via a variable, e.g. \"%s\"" % colored("include 'modules/'.$_REQUEST['module']", "yellow"))
    predef_regexes.add_argument("-k", "--cookie-usage", action="store_true", help="Regex that indicates usage of a cookie, e.g. \"%s\"" % colored("$_COOKIE['ID']", "yellow"))
    predef_regexes.add_argument("-s", "--sqli", action="store_true", help="Regex that indicates an SQL Injection code pattern, e.g. \"%s\"" % colored(".. WHERE ID = \\''.$_REQUEST['ID'].'\\''", "yellow"))
    predef_regexes.add_argument("-x", "--xss", action="store_true", help="Regex that indicates an XSS code pattern, e.g. \"%s\"" % colored("echo 'Username: '.$_REQUEST['user']", "yellow"))

    # parse the given command line arguments
    args = parser.parse_args()
    if not args.extension.startswith("."):
        args.extension = "." + args.extension
    if args.no_regexes:
        args.all_regexes = False
    if args.unsafe_func or args.file_inclusion or args.cookie_usage or args.sqli or args.xss:
        args.all_regexes = False
    if args.custom_regex:
        for i, regex in enumerate(args.custom_regex):
            # compile custom regexes before use
            args.custom_regex[i] = re.compile(regex)

    return args


def print_results(results, use_color):
    """ Print the given scan results """

    table = AsciiTable([["File", "Type", "Code", "Line Number"]] + results)
    table.justify_columns = {0: "center", 1: "center", 2: "left", 3: "center"}
    table.inner_row_border = True
    table.inner_footing_row_border = True
    table.inner_heading_row_border = True
    table.outer_border = True
    output = table.table.split("\n")
    output[2] = output[2].replace("-", "=")
    print("\n".join(output))
    my_print("[+] Analysis complete: %d suspicious code fragments found" % len(results), "blue")


def my_print(text, color=None, use_color=True):
    """ Print given text with or without color """
    if use_color:
        cprint(text, color)
    else:
        print(text)


def banner():
    """ Print banner """
    print("""
    _____            __      ___                     ____            
   / __(_)_ _  ___  / /__   / _ \___ ___ ______ __  / __/______ ____ 
  _\ \/ /  ' \/ _ \/ / -_) / , _/ -_) _ `/ -_) \ / _\ \/ __/ _ `/ _ \\
 /___/_/_/_/_/ .__/_/\__/ /_/|_|\__/\_, /\__/_\_\ /___/\__/\_,_/_//_/
            /_/                    /___/                             
    """)


if __name__ == "__main__":
    # Entry point
    banner()
    args = parse_args()
    files = crawl(args.input, args.extension, not args.no_color)
    if files:
        results = scan(files, get_regexes(args), not args.no_color)
        print_results(results, not args.no_color)
