import requests
import re
from bs4 import BeautifulSoup
from bs4.element import Comment

popular_sites = ["cxsecurity.com", "rapid7.com/db/modules", "legalhackers.com",
                 "exploit-db.com", "0day.today", "circl.lu", "exploitbox.io"]


class LinkAnalyser:

    """
    1. check for patch
    2. check for exploit
    """
    def analyse_link(self, reference):
        self.exploit_verification(reference)
        self.patch_verification(reference)

    """
    0. check in tagging "Patch"
    1. if contains - verify if url contains commit pattern
    2. if no - get all links from url and check them. save result in reference.patch_url
    """
    def patch_verification(self, reference):
        html = self.get_url_content(reference.url)
        text = self.text_from_html(html)
        if self.is_commit(text):
            reference.is_patch_by_content = True
            reference.is_patch = True
        if "Patch" in reference.tags:
            reference.is_patch = True

    @staticmethod
    def is_commit(text):
        if text is None:
            return False
        regex = r"(@*\s*)-([0-9]*),([0-9]*)\s*.([0-9]*),([0-9]*)\s*(@*)"
        if re.search(regex, text, re.MULTILINE) is not None:
            return True
        return False

    def text_from_html(self, text):
        try:
            soup = BeautifulSoup(text, 'html.parser')
        except TypeError:
            return None
        texts = soup.findAll(text=True)
        visible_texts = filter(self.tag_visible, texts)
        return u" ".join(t.strip() for t in visible_texts)

    @staticmethod
    def tag_visible(element):
        if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
            return False
        if isinstance(element, Comment):
            return False
        return True

    @staticmethod
    def get_url_content(url):
        res = ""
        try:
            resp = requests.get(url)
            if resp.status_code is 200:
                res = resp.text
        except (requests.exceptions.ConnectionError,
                requests.exceptions.InvalidSchema,
                requests.exceptions.ChunkedEncodingError):
            res = ""
        return res

    @staticmethod
    def exploit_verification(reference):
        if "Exploit" in reference.tags or any(tag in reference.url for tag in popular_sites):
            reference.is_exploit = True
