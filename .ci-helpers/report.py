#!/usr/bin/env python

import argparse
import json
import pandas as pd


def score_to_severity(score: float) -> str:
    """
    This function converts a score value to a string indicating its severity level based on the Common Vulnerability Scoring System (CVSS) standard.

    Args:
        score (float): A score value ranging from 0.0 to 10.0 (inclusive).

    Returns:
        str: A string representing the severity level of the score, which can be one of the following values: 'none', 'low', 'medium', 'high', or 'critical'.

    Raises:
        ValueError: If the score value is outside the valid range of 0.0 to 10.0.

    References:
        More information about the CVSS standard can be found at https://nvd.nist.gov/vuln-metrics/cvss.
    """
    if score == 0.0:
        return "none"

    elif 0.1 <= score <= 3.9:
        return "low"

    elif 4.0 <= score <= 6.9:
        return "medium"

    elif 7.0 <= score <= 8.9:
        return "high"

    elif 9.0 <= score <= 10.0:
        return "critical"

    else:
        raise ValueError(f"Score {score} is out of bounds")


def create_badge(cve: str, severity: str, BADGE_URL: str = "https://img.shields.io/static/v1?label={0}&message={1}&color={2}&style=flat") -> str:
    """
    Returns the URL of a static shields.io badge for a given vulnerability.

    Args:
        cve (str): The CVE identifier for the vulnerability.
        severity (str): The severity of the vulnerability, must be one of "critical", "high", "medium", "low", "none", or "unknown".
        BADGE_URL (str, optional): The URL pattern for the badge image. Defaults to "https://img.shields.io/static/v1?label={0}&message={1}&color={2}&style=flat".

    Returns:
        str: The URL of the generated badge.

    Raises:
        ValueError: If the severity is not one of the allowed values.
    """
    if severity == "critical":
        return BADGE_URL.format(cve, "critical", "red")

    elif severity == "high":
        return BADGE_URL.format(cve, "high", "orange")

    elif severity == "medium":
        return BADGE_URL.format(cve, "medium", "brightgreen")

    elif severity == "low":
        return BADGE_URL.format(cve, "low", "blue")

    elif severity == "none":
        return BADGE_URL.format(cve, "none", "lightgrey")

    else:
        raise ValueError(f"Unknown severity: '{severity}'")


def main(input_file, output_file, ignore_file):
    """
    Reads vulnerability data from a JSON file produced by `jake ddt`, processes it, and generates an issue body in Markdown format.

    Args:
        input_file (str): Path to the JSON file containing the vulnerability data produced by `jake ddt`.
        output_file (str): Path to the Markdown file where the issue body will be written.
        ignore_file (str): Path to a text file containing a list of CVEs to ignore.

    Returns:
        None.
    """
    with open(input_file, "r") as f:
        data = json.load(f)

    try:
        with open(ignore_file, "r") as f:
            ignore_cves = [line.strip() for line in f if not line.startswith("#")]

    except FileNotFoundError:
        ignore_cves = []

    vulns_list = []
    for vuln in data:
        channel_name, version = vuln.get("package").split("@")
        channel,name = channel_name.split("/")
        cve = vuln.get("cve")
        score = vuln.get("cvss_score")
        url = f"https://ossindex.sonatype.org/vulnerability/{cve}?component-type=conda&component-name={name}"

        if cve not in ignore_cves:
            vulns_list.append({"name": name,
                            "version": version,
                            "cve": cve,
                            "severity": score_to_severity(score),
                            "url": url
                            })

    vulns = pd.DataFrame.from_records(vulns_list)
    vulns["vulnerability"] = vulns.apply(lambda row: f"[![{row['cve']}]({create_badge(row['cve'], row['severity'])})]({row['url']})", axis=1)

    table = vulns[["name", "version", "vulnerability"]].groupby(["name", "version"]).agg(lambda x: " ".join(x)).reset_index()
    table["name"] = table["name"].apply(lambda x: f"`{x}`")
    table["version"] = table["version"].apply(lambda x: f"_{x}_")
    table.columns = table.columns.map(mapper={"name": "Package", "version": "Version", "vulnerability": "Vulnerabilities"})

    message = "## Vulnerability Report\n\n  _This is an automated issue opened by the [Conda dependency checker workflow](https://github.com/epassaro/conda-deps-check)._\n\n<br>\n\n"
    body = message + table.reset_index(drop=True).to_markdown(index=False)

    with open(output_file, "w") as f:
        f.write(body)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="report")
    parser.add_argument("-i", "--infile", help="input JSON file")
    parser.add_argument("-o", "--outfile", help="output Markdown file")
    parser.add_argument("--ignore-file", default=".jake-ignore-cves", help="text file with CVEs to ignore")
    args = parser.parse_args()

    main(args.infile, args.outfile, args.ignore_file)
