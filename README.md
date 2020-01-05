# Simple Regex Scan
A small script that searches files for insecure code patterns via regular expressions.

<p>
<a href="#"><img src="https://img.shields.io/badge/python-3.6%2B-red" alt="Python 3.6+"></a>
<a href="#"><img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS-%23557ef6" alt="Platform: linux, macOS"></a>
<a href="https://github.com/DustinBorn/SimpleRegexScan/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"></a>
</p>

## About
Simple Regex Scan is a Python 3 script that uses regular expressions to statically search code for insecure coding patterns. As such, not every discovered code fragment has to be indeed insecure. This tool **does not** analyze the information flow within code and consequently a fair amount of false positives may occur. This tool was primarily made for PHP code, but can also be used for other types of code. The tool can also accept custom Regexes as input that help to identify user-defined code patterns within the analyzed code. For performance reasons, files greater than 50 KiB are skipped during the scan.

## Installation
To install the required Python packages and create a symlink, run:
```
./install.sh
```
The installation script needs to be run as root user to create a symlink in "/usr/local/bin". Alternatively, you can run the installation commands directly:
```
pip3 install -r requirements.txt
ln -sf "$(pwd)/simple_regex_scan.py" /usr/local/bin/simple_regex_scan
```
Make sure you use your correct pip for Python 3.

## Usage
The usage information can be viewed with the command ``simple_regex_scan -h`` and is as follows:
```

    _____            __      ___                     ____
   / __(_)_ _  ___  / /__   / _ \___ ___ ______ __  / __/______ ____
  _\ \/ /  ' \/ _ \/ / -_) / , _/ -_) _ `/ -_) \ / _\ \/ __/ _ `/ _ \
 /___/_/_/_/_/ .__/_/\__/ /_/|_|\__/\_, /\__/_\_\ /___/\__/\_,_/_//_/
            /_/                    /___/

usage: simple_regex_scan [-h] [-c CUSTOM_REGEX [CUSTOM_REGEX ...]]
                         [-e EXTENSION] [--no-color] -i INPUT [INPUT ...]
                         [-o OUTPUT] [-A] [-N] [-u] [-f] [-k] [-s] [-S] [-x]

Search files for insecure code patterns via regular expressions

optional arguments:
  -h, --help            show this help message and exit
  -c CUSTOM_REGEX [CUSTOM_REGEX ...], --custom-regex CUSTOM_REGEX [CUSTOM_REGEX ...]
                        Specify custom regexes to use in addition to the
                        default ones
  -e EXTENSION, --extension EXTENSION
                        Specify the file extension of files to search (php by
                        default)
  --no-color            Do not color the output
  -i INPUT [INPUT ...], --input INPUT [INPUT ...]
                        Input one or more files or directories to search
  -o OUTPUT, --output OUTPUT
                        A file to save the final results to

predefined regexes:
  predefined regexes that can be used

  -A, --all-regexes     Use all predefined regexes (default if no predefined
                        regex is explicitly specified)
  -N, --no-regexes      Use none of the predefined regexes (defaults to true
                        if one of the predefined regexes is explicitly
                        specified)
  -u, --unsafe-func     Regex that indicates unsafe function usage with a
                        variable, e.g. "eval($_REQUEST['cmd'])"
  -f, --file-inclusion  Regex that indicates file inclusion via a variable,
                        e.g. "include 'modules/'.$_REQUEST['module']"
  -k, --cookie-usage    Regex that indicates usage of a cookie, e.g.
                        "$_COOKIE['ID']"
  -s, --sqli            Regex that indicates an SQL Injection code pattern
                        with direct usage of HTTP params, e.g. "... WHERE
                        ID = \''.$_REQUEST['ID'].'\''"
  -S, --sqli-all        Regex that indicates an SQL Injection code pattern
                        with or without direct usage of HTTP params, e.g.
                        "... WHERE ID = \''$id.'\''"
  -x, --xss             Regex that indicates an XSS code pattern with direct
                        usage of HTTP params, e.g. "echo 'Username:
                        '.$_REQUEST['user']"

Example: simple_regex_scan -ufs -i /var/www/html/mycms
```

Simple Regex Scan provides six predefined regexes that are used by default. If any flag out of ``{-u, -f, -k, -s, -S, -x}`` is specified, all non predefined regexes that are not explicitly specified are not used.

**Example call:**
```
simple_regex_scan -f -c "(eval.*(.*\\\$.*);)" /var/www/html/mycms
```
This has the tool scan all PHP files within the directory "/var/www/html/mycms" for file inclusions and the use of the ``eval(...)`` function with a variable. Note the triple backslash to properly escape the dollar sign in a shell environment. Also, because the output text can be a bit wide, be sure to stretch your terminal if you get output that is difficult to read. Alternatively you can disable colored output and output the results to a file via the ``-o`` parameter.

## Contribution &amp; Bugs
If you want to contribute, or have any questions or suggestions, use GitHub or directly contact me via Email <a href="mailto:dustin.born@gmx.de">here</a>. If you found a bug or have other troubles, feel free to open an issue.

## License
Simple Regex Scan is licensed under the MIT license, see [here](https://github.com/DustinBorn/SimpleRegexScan/blob/master/LICENSE).
