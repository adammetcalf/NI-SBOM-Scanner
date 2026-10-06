# NI-SBOM-Scanner
This is a bit of code designed to scan a CycloneDX SBOM against NI's published public CSAF feed

The code is developed in Python, and uses urllib to scan an NIPM components from an SBOM against NI's public CSAF feed. Currently, it does not yet scan for VIPM components (pull requests welcome).

## Usage
It may be called from the command line:
```
python ni_csaf_scan.py <sbom.json>
```

It may be called from the command line and generate a report:
```
python ni_csaf_scan.py <sbom.json> --json report.json
```

It may be called from the command line and configured to show possible NI product matches where the relationship cannot yet be considered definitive:
```
python ni_csaf_scan.py <sbom.json> --show-candidates
```


## Exit codes:
    0 = no definite affected components
    1 = one or more definite affected components
    2 = scanner/input/network error

Reporting has defined that "definite" means this NIPM package is treated as the CSAF product itself. "candidate" means the package is related to the CSAF product, but the package name alone does not prove that the vulnerable runtime/product is actually present.
