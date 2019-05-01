from cve_analyser.nvd_parser import NVDJsonParser

cve_2018 = "../test/data/nvdcve-1.0-2018.json"

parser = NVDJsonParser()
cves = parser.parse(cve_2018)
print(cves.keys())