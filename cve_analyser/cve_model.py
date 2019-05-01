from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, ForeignKey, Integer, String, Float, Text, Boolean, Table
from sqlalchemy.orm import relationship

Base = declarative_base()


class CVE():
    """__tablename__ = "cves"

    id = Column(String, primary_key=True, unique=True)
    published_date = Column(String)
    last_modified = Column(String)
    exploitability = Column(Float)
    impact = Column(Float)
    base = Column(Float)
    description = Column(Text)
    trend = Column(Text)
"""

    def __init__(self, cve_id):

        self.id = cve_id
        self.published_date = ""
        self.last_modified = ""
        self.vendors = {}
        self.cwes = []
        self.references = []
        self.exploitability = None
        self.impact = None
        self.base = None
        self.trend = []

"""
tags_references_table = Table('association', Base.metadata,
                              Column('tag_id', Integer, ForeignKey('tags.id')),
                              Column('ref_id', Integer, ForeignKey("references.id")))
"""

class Reference():

    """
    __tablename__ = "references"

    id = Column(Integer, primary_key=True)
    url = Column(String)
    cve_id = Column(String, ForeignKey('cves.id'))
    is_patch_by_content = Column(Boolean, default=False)
    is_patch = Column(Boolean, default=False)
    is_exploit = Column(Boolean, default=False)
    tags = relationship("Tags", secondary=tags_references_table, back_populates="references")
"""

    def __init__(self, url):
        self.url = url
        self.tags = []
        self.is_patch_by_content = False
        self.is_patch = False
        self.is_exploit = False


class Tag():
    """
    __tablename__ = "tags"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    """

class Vendor():
    """
    __tablename__ = "vendors"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    products = relationship("Products", backref="vendors", order_by="products.id")
    """

    def __init__(self, name):
        self.name = name


class Product():
    """
    __tablename__ = "products"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    type = Column(String)
    versions = relationship("Versions", backref="products",
                            order_by="versions.id")
    vendor_id = Column(ForeignKey('vendors.id'))

    """
    def __init__(self, name):
        self.name = name


class Version():
    """
    __tablename__ = 'versions'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    affected = Column(String)
    product_id = Column(ForeignKey('products.id'))

    """