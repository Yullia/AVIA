import json

from cve_analyser.cve_model import CVE, Vendor, Product, Reference


class NVDJsonParser:

    def parse(self, filename):
        cves = {}
        with open(filename, "r") as f:
            data = json.load(f)
            for item in data["CVE_Items"]:
                cve = self.parse_cve(item)
                cves[cve.id] = cve
        return cves

    def parse_cve(self, item):
        cve = CVE(item['cve']['CVE_data_meta']['ID'])
        cve.published_date = item['publishedDate']
        cve.last_modified = item['lastModifiedDate']
        cve.cwes = self.parse_cwe(item)
        cve.vendors = self.parse_vendors(item)
        cve.references = self.parse_references(item)
        cve.description = self.parse_description(item)
        self.parse_cvss(item, cve)
        return cve

    def parse_vendors(self, item):
        vendor_data = item['cve']['affects']['vendor']['vendor_data']
        vendors = {}
        for item in vendor_data:
            vendor = Vendor(item['vendor_name'])
            vendor.products = self.parse_products(item)
            vendors[vendor.name] = vendor
        return vendors

    def parse_products(self, item):
        products = {}
        product_data = item['product']['product_data']
        for item in product_data:
            product = Product(item['product_name'])
            product.versions = self.parse_versions(item)
            products[product.name] = product
        return products

    @staticmethod
    def parse_versions(product):
        versions = {}
        version_data = product['version']['version_data']
        for version in version_data:
            versions[version['version_value']] = version['version_affected']
        return versions

    @staticmethod
    def parse_references(item):
        references = []
        ref_data = item['cve']['references']['reference_data']
        for i in ref_data:
            ref = Reference(i['url'])
            ref.tags = i['tags']
            references.append(ref)
        return references

    @staticmethod
    def parse_cwe(item):
        cwes = []
        problemtype_data = item['cve']['problemtype']['problemtype_data']
        for datatype in problemtype_data:
            for descr in datatype['description']:
                cwes.append(descr['value'])
        return cwes

    @staticmethod
    def parse_description(item):
        return item['cve']['description']['description_data'][0]['value']

    @staticmethod
    def parse_cvss(item, cve):
        try:
            v3 = item['impact']['baseMetricV3']
            cve.exploitability = v3['exploitabilityScore']
            cve.impact = v3['impactScore']
            cve.base = v3['cvssV3']['baseScore']
        except  KeyError:
            print(cve.id)