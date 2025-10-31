# app/xml/dmarc.py
from __future__ import annotations
from typing import Dict, Iterable, Optional, List
from defusedxml import ElementTree as ET  # use defusedxml everywhere for safety

DMARC_NS_URIS = {
    "1.0": "urn:ietf:params:xml:ns:domain:dmarc:aggregate:1.0",   # older
    "2.0": "urn:ietf:params:xml:ns:dmarc-2.0",                    # dmarc-bis
}


def parse(xml_bytes: bytes) -> ET.Element:
    """Parse bytes and return root element (defused)."""
    return ET.fromstring(xml_bytes)


def detect_default_ns(root: ET.Element) -> Dict[str, str]:
    """
    If the document uses a default ns (e.g., <feedback xmlns="...">),
    return a prefix mapping like {"d": "<ns-uri>"}; else {}.
    """
    tag = root.tag or ""
    if tag.startswith("{"):
        uri = tag[1:].split("}", 1)[0]
        return {"d": uri}
    return {}


def _try_paths(elem: ET.Element, paths: Iterable[str], ns: Dict[str, str]) -> Optional[ET.Element]:
    for p in paths:
        hit = elem.find(p, ns) if ns else elem.find(p)
        if hit is not None:
            return hit
    return None


def _try_paths_all(elem: ET.Element, paths: Iterable[str], ns: Dict[str, str]) -> List[ET.Element]:
    for p in paths:
        hits = elem.findall(p, ns) if ns else elem.findall(p)
        if hits:
            return hits
    return []


def q(local: str) -> List[str]:
    """
    Build candidate XPath fragments for one local name.
    Order matters: try namespaced first, then non-ns.
    Example: q("report_metadata") -> [".//d:report_metadata", ".//report_metadata"]
    """
    return [f".//d:{local}", f".//{local}"]


def find(elem: ET.Element, local: str, ns: Dict[str, str]) -> Optional[ET.Element]:
    return _try_paths(elem, q(local), ns)


def findall(elem: ET.Element, local: str, ns: Dict[str, str]) -> List[ET.Element]:
    return _try_paths_all(elem, q(local), ns)


def text(elem: Optional[ET.Element]) -> Optional[str]:
    return (elem.text or "").strip() if elem is not None and elem.text is not None else None


def localname(tag: str) -> str:
    """Return the local part of a tag, stripping '{ns}' if present."""
    return tag.split('}', 1)[-1]
