"""Gate supported injection regressions while retaining context-dependent cases."""

import json
import pathlib
import sys


def main():
    report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    if report["TransportErrors"] or report["Unavailable"] or report["Count"] != 10000:
        raise SystemExit("invalid live WAF measurement")
    supported = {"java", "ldap", "lfi", "nosql", "php", "protocol", "prototype",
                 "rce", "regression", "scanner", "sqli", "ssi", "ssrf", "ssti",
                 "wordpress", "xpath", "xss", "xxe"}
    categories = {row["Category"]: row for row in report["CategoryResults"]}
    if not supported.issubset(categories):
        raise SystemExit("missing required attack categories")
    for name in sorted(supported):
        row = categories[name]
        if row["Errors"] or row["Unavailable"] or row["AttackOrigin"] or row["AdmittedAttackCases"]:
            raise SystemExit("supported injection reached the origin: " + name)
    controls = [row for row in report["Results"] if not row["Attack"]
                and row["Name"].split("/")[0] in {"search", "json"}]
    if not controls or any(row["Requests"] <= 0 or row["OriginReached"] != row["Requests"] for row in controls):
        raise SystemExit("ordinary search/JSON controls refused or not exercised")
    print("Supported injection regressions blocked; ordinary search/JSON controls passed")
    print("Context-dependent admissions and other benign refusals remain in the artifact")


if __name__ == "__main__":
    main()
