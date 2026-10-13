#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CTI Auto Collector 4.0 — feed-driven, read-only, Python 3.11+ / no pip.

Run: py -3.11 CTI_Auto_Collector.py
Fetches PUBLIC threat-intelligence reports automatically; asks for NO indicators.
Optionally enriches with APIs if the caller has valid API credentials in environment.
Never visits reported phishing URLs, scans systems, submits malware, or imports IOC to MISP.
An IOC observed in an external feed is NOT proof of compromise of any organization.

Data providers:
  OpenPhish community phishing feed (opt-in; governed by its Terms of Use)
  Feodo Tracker recommended botnet C2 IP feed (no key)
  Emerging Threats compromised hosts and Block IPs (no key)
  IPsum aggregated IPs (at least 3 upstream lists; no key)
  CERT Polska public domain warning list (no key)
  Phishing.Database new URLs and domains (no key)
  Phishunt aggregate domain feed (no key; NOT independent upstream confirmation)
  CISA Known Exploited Vulnerabilities catalog (separate CVE data, no key)
  FIRST EPSS probability and percentile enrichment for selected CISA CVEs (no key)
  GreyNoise Community contextual IP enrichment (limited unauthenticated lookups)
  ThreatFox recent IOC API (ABUSECH_AUTH_KEY required)
  MalwareBazaar recent additions (ABUSECH_AUTH_KEY required)
  VirusTotal passive lookup (VT_API_KEY optional, for a small sample)

API keys must never be committed to a public repository.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import csv
import ipaddress
import json
import os
import re
import ssl
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler
from xml.etree import ElementTree as ET
import zipfile
import struct
import zlib

VERSION = "4.0.0"
OPENPHISH = "https://openphish.com/feed.txt"
FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
BAZAAR = "https://mb-api.abuse.ch/api/v1/"
VT = "https://www.virustotal.com/api/v3"
ET_COMPROMISED = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
ET_BLOCK = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
IPSUM = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
CISA_KEV = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
GREYNOISE = "https://api.greynoise.io/v3/community"
FIRST_EPSS = "https://api.first.org/data/v1/epss"
BLOCKLIST = "https://lists.blocklist.de/lists/all.txt"
SPAMHAUS = "https://www.spamhaus.org/drop/drop_v4.json"
RIPESTAT = "https://stat.ripe.net/data/network-info/data.json"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
URL_RE = re.compile(r"^https?://", re.I)
HASH_RE = re.compile(r"^[a-f0-9]{64}$", re.I)
HASH_LENGTHS = {"md5":32, "sha1":40, "sha256":64, "sha512":128}
IOC_TYPES = ("ip", "cidr", "domain", "url", "ip_port", "domain_port", "md5", "sha1", "sha256", "sha512")
CERT_PL = "https://hole.cert.pl/domains/v2/domains.txt"
PHISHUNT = "https://raw.githubusercontent.com/0xDanielLopez/phishunt-feed/main/feed.txt"
PHISHING_DB_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-NEW-today.txt"
PHISHING_DB_DOMAIN = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-NEW-today.txt"
# A publisher family is NOT a claim of independent verification. Aggregators must be explicitly marked.
PUBLISHER = {"Emerging Threats Compromised":"Emerging Threats", "Emerging Threats Block":"Emerging Threats",
             "Spamhaus DROP":"Spamhaus/abuse.ch", "Feodo Tracker":"Spamhaus/abuse.ch",
             "MalwareBazaar":"Spamhaus/abuse.ch", "ThreatFox":"Spamhaus/abuse.ch",
             "IPsum":"IPsum (aggregator)", "Phishunt":"Phishunt (aggregator)",
             "Phishing.Database URLs":"Phishing.Database", "Phishing.Database Domains":"Phishing.Database"}
AGGREGATORS = {"IPsum", "Phishunt"}

MAX_RESPONSE = 12_000_000
TIMEOUT = 22
HEADERS = {"User-Agent": "CTI-Auto-Collector/4.0 (read-only research)", "Accept": "application/json, text/plain"}

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
WP = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
PIC = "http://schemas.openxmlformats.org/drawingml/2006/picture"
REL = "http://schemas.openxmlformats.org/package/2006/relationships"
CT = "http://schemas.openxmlformats.org/package/2006/content-types"
S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
for prefix, uri in (("w",W),("r",R),("wp",WP),("a",A),("pic",PIC)):
    ET.register_namespace(prefix,uri)

def q(ns, local): return "{%s}%s" % (ns,local)
def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def only_dict(x): return x if isinstance(x,dict) else {}
def only_list(x): return x if isinstance(x,list) else []

class SourceFailure(RuntimeError): pass

class SafeRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old=urlsplit(req.full_url)
        target=urlsplit(newurl)
        # OpenPhish currently redirects to its official public_feed GitHub distribution.
        permitted=(target.scheme=="https" and target.hostname==old.hostname) or (
            old.hostname=="openphish.com" and target.scheme=="https"
            and target.hostname=="raw.githubusercontent.com"
            and target.path.startswith("/openphish/public_feed/")
        )
        if not permitted:raise SourceFailure("Redirect verso host non autorizzato")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

class HTTPClient:
    def __init__(self, cafile=None, transport=None):
        self.context = ssl.create_default_context(cafile=cafile or None)
        self.opener=build_opener(HTTPSHandler(context=self.context),SafeRedirects())
        self.transport = transport  # only for deterministic offline tests
    def request(self, url, *, headers=None, form=None, json_body=None):
        parts=urlsplit(url)
        allowed = {"openphish.com", "feodotracker.abuse.ch", "threatfox-api.abuse.ch", "mb-api.abuse.ch", "www.virustotal.com",
                   "rules.emergingthreats.net", "raw.githubusercontent.com", "api.greynoise.io", "api.first.org",
                   "lists.blocklist.de", "www.spamhaus.org", "stat.ripe.net", "hole.cert.pl"}
        if parts.scheme!="https" or parts.hostname not in allowed or parts.username or parts.password:
            raise SourceFailure("Host/protocollo non autorizzato")
        # All endpoints are fixed by the program; avoid accidental credential leakage
        # or open-ended network fetches if a caller supplies an unexpected URL.
        if parts.hostname == "raw.githubusercontent.com" and parts.path not in (
            "/stamparm/ipsum/master/ipsum.txt",
            "/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
            "/0xDanielLopez/phishunt-feed/main/feed.txt",
            "/Phishing-Database/Phishing.Database/master/phishing-links-NEW-today.txt",
            "/Phishing-Database/Phishing.Database/master/phishing-domains-NEW-today.txt"):

            raise SourceFailure("Percorso GitHub non autorizzato")
        if parts.hostname == "api.greynoise.io" and not parts.path.startswith("/v3/community/"):
            raise SourceFailure("Endpoint GreyNoise non autorizzato")
        if parts.hostname == "lists.blocklist.de" and parts.path != "/lists/all.txt":
            raise SourceFailure("Percorso Blocklist.de non autorizzato")
        if parts.hostname == "www.spamhaus.org" and parts.path != "/drop/drop_v4.json":
            raise SourceFailure("Percorso Spamhaus non autorizzato")
        if parts.hostname == "stat.ripe.net" and parts.path != "/data/network-info/data.json":
            raise SourceFailure("Endpoint RIPEstat non autorizzato")
        if parts.hostname == "hole.cert.pl" and parts.path != "/domains/v2/domains.txt":
            raise SourceFailure("Percorso CERT Polska non autorizzato")
        if parts.hostname == "api.first.org" and parts.path != "/data/v1/epss":
            raise SourceFailure("Endpoint FIRST non autorizzato")
        extra=HEADERS.copy(); extra.update(headers or {})
        body=None
        if form is not None:
            body=urlencode(form).encode("utf-8")
            extra["Content-Type"]="application/x-www-form-urlencoded"
        elif json_body is not None:
            body=json.dumps(json_body).encode("utf-8")
            extra["Content-Type"]="application/json"
        # API token always in header; never appear in paths, files or error messages.
        if self.transport:
            return self.transport(url, body, extra)
        req=Request(url,headers=extra,data=body,method="POST" if body is not None else "GET")
        for attempt in range(2):
            try:
                with self.opener.open(req,timeout=TIMEOUT) as resp:
                    content=resp.read(MAX_RESPONSE+1)
                    if len(content)>MAX_RESPONSE: raise SourceFailure("Risposta oltre limite dimensionale (12 MB)")
                    if str(resp.headers.get("Content-Encoding", "")).lower()=="gzip":
                        try:content=gzip.decompress(content)
                        except (OSError, EOFError):raise SourceFailure("Risposta gzip non valida") from None
                        if len(content)>MAX_RESPONSE:raise SourceFailure("Risposta decompressa oltre limite (12 MB)")
                    return content
            except HTTPError as exc:
                if exc.code==429 and attempt==0:
                    try: delay=min(30,max(2,int(exc.headers.get("Retry-After","5"))))
                    except (TypeError,ValueError): delay=5
                    time.sleep(delay); continue
                if exc.code in (401,403): raise SourceFailure(f"HTTP {exc.code}: chiave non valida, accesso negato o piano API insufficiente") from None
                raise SourceFailure(f"HTTP {exc.code} dalla fonte") from None
            except (URLError,TimeoutError,ssl.SSLError) as exc:
                # Network failure is explicit; do NOT fabricate fallback indicators.
                msg=str(exc)
                if "CERTIFICATE_VERIFY_FAILED" in msg or "certificate verify failed" in msg:
                    raise SourceFailure("Certificato TLS non attendibile: configura REQUESTS_CA_BUNDLE con la CA approvata") from None
                raise SourceFailure("Errore rete o timeout: " + msg[:130]) from None
        raise SourceFailure("Tentativi esauriti")
    def json(self,url,**kw):
        try: value=json.loads(self.request(url,**kw).decode("utf-8-sig"))
        except (ValueError,UnicodeDecodeError) as exc:raise SourceFailure("Risposta JSON non valida") from exc
        if not isinstance(value,dict): raise SourceFailure("Risposta JSON con struttura inattesa")
        return value

# Records keep each source's own claim, without merging unrelated threat types.
def parse_indicator(kind, raw):
    raw=str(raw).strip()
    if kind=="ip":
        try:
            ip=ipaddress.ip_address(raw)
            return ("ip",str(ip)) if ip.is_global else None
        except ValueError:return None
    if kind=="cidr":
        try:
            network=ipaddress.ip_network(raw,strict=True)
            if not network.is_global:return None
            if network.prefixlen==network.max_prefixlen:return ("ip",str(network.network_address))
            return ("cidr",str(network))
        except ValueError:return None
    if kind in HASH_LENGTHS:
        return (kind,raw.lower()) if re.fullmatch(r"[a-fA-F0-9]{%d}" % HASH_LENGTHS[kind], raw) else None
    if kind=="ip_port":
        try:
            host,port=raw.rsplit(":",1)
            if host.startswith("[") and host.endswith("]"):host=host[1:-1]
            ip=ipaddress.ip_address(host)
            if not ip.is_global or not port.isdigit() or not (1<=int(port)<=65535):return None
            name=f"[{ip}]" if ip.version==6 else str(ip)
            return ("ip_port",f"{name}:{int(port)}")
        except ValueError:return None
    if kind in ("domain", "domain_port"):
        if kind=="domain_port":
            try:
                host_raw,port=raw.rsplit(":",1)
                if not port.isdigit() or not 1<=int(port)<=65535:return None
            except ValueError:return None
        else:host_raw=raw
        if len(host_raw)>253 or len(host_raw)<4 or "." not in host_raw or any(ch in host_raw for ch in "/@ :?#"):
            return None
        try:host=host_raw.rstrip(".").lower().encode("idna").decode("ascii")
        except UnicodeError:return None
        labels=host.split(".")
        if not all(0<len(t)<=63 and not t.startswith("-") and not t.endswith("-") for t in labels):return None
        if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+",host):return None
        try:ipaddress.ip_address(host);return None
        except ValueError:pass
        return ("domain_port",f"{host}:{int(port)}") if kind=="domain_port" else ("domain",host)
    if kind=="url":
        if len(raw)>2048 or any(ord(c)<32 for c in raw) or not URL_RE.match(raw):return None
        try:
            u=urlsplit(raw)
            if u.scheme.lower() not in ("http","https") or not u.hostname or u.username or u.password or (u.port is not None and not 1<=u.port<=65535):return None
        except ValueError:return None
        return ("url",raw)
    return None

def publisher_group(source):
    return PUBLISHER.get(source, source)

def indicator_sort_key(row):
    # Favor analyst-usable items over broad networks; type-specific lists are also exported.
    order={"sha256":0,"md5":1,"sha1":2,"url":3,"domain":4,"ip_port":5,"domain_port":6,"ip":7,"cidr":8,"sha512":9}
    return (order.get(row["type"],20),str(row["indicator"]),str(row.get("source","")))

class Collector:
    def __init__(self,client,limit=2000,abuse_key="",vt_key="",vt_limit=4,gn_limit=5,kev_limit=50,ripe_limit=30,openphish=False,spamhaus_cache=None):
        self.client=client;self.limit=limit;self.abuse_key=abuse_key;self.vt_key=vt_key;self.vt_limit=vt_limit
        self.gn_limit=gn_limit;self.kev_limit=kev_limit;self.ripe_limit=ripe_limit;self.openphish=openphish
        self.spamhaus_cache=Path(spamhaus_cache) if spamhaus_cache else None
        self.records=[];self.checks=[];self.enrichment=[];self.vulnerabilities=[];self.seen=set();self.last_vt=0.0
    def add(self,kind,value,source,category,source_ref="",first_seen="",context=""):
        parsed=parse_indicator(kind,value)
        if not parsed:return False
        kind,value=parsed
        key=(kind,value,source)
        if key in self.seen:return False
        self.seen.add(key)
        self.records.append({"type":kind,"indicator":value,"source":source,"classification":category,
             "reported_first_seen":str(first_seen or ""),"source_reference":str(source_ref or ""),
             "context":str(context or "")[:200],"collected_utc":self.start})
        return True
    def run_source(self,name,operation):
        start=len(self.records)
        before_enrichment=len(self.enrichment)
        before_kev=len(self.vulnerabilities)
        before_epss=sum(bool(r.get("epss")) for r in self.vulnerabilities)
        print("[+] Interrogazione:",name,flush=True)
        try:
            detail=operation()
            if name in ("VirusTotal", "GreyNoise", "RIPEstat"):
                new=sum(x.get("status")=="ok" for x in self.enrichment[before_enrichment:])
            elif name=="CISA KEV":
                new=len(self.vulnerabilities)-before_kev
            elif name=="FIRST EPSS":
                new=sum(bool(r.get("epss")) for r in self.vulnerabilities)-before_epss
            else:
                new=len(self.records)-start
            status="ok" if new else "no_data"
            self.checks.append({"source":name,"status":status,"count":new,"detail":str(detail or "")[:220]})
            print(f"    -> {new} indicatori validi ({status})",flush=True)
        except (SourceFailure,ValueError,KeyError,TypeError,UnicodeDecodeError, OSError) as exc:
            if name in ("VirusTotal", "GreyNoise", "RIPEstat"):
                new=sum(x.get("status")=="ok" for x in self.enrichment[before_enrichment:])
            elif name=="CISA KEV":new=len(self.vulnerabilities)-before_kev
            elif name=="FIRST EPSS":new=sum(bool(r.get("epss")) for r in self.vulnerabilities)-before_epss
            else:new=len(self.records)-start
            self.checks.append({"source":name,"status":"partial_error" if new else "error","count":new,"detail":str(exc)[:220]})
            print("    -> ERRORE:",str(exc)[:220],flush=True)
    def collect_openphish(self):
        content=self.client.request(OPENPHISH).decode("utf-8-sig")
        if "<html" in content[:500].lower():raise SourceFailure("Risposta HTML inattesa: feed non disponibile")
        lines=[x.strip() for x in content.splitlines() if x.strip() and not x.startswith("#")]
        bad=0; accepted=0
        for link in lines[:self.limit*3]:
            if accepted>=self.limit:break
            if self.add("url",link,"OpenPhish","phishing URL reported",OPENPHISH):accepted+=1
            else:bad+=1
        if lines and bad==len(lines[:max(self.limit*3,self.limit)]):raise SourceFailure("Formato feed inatteso o nessun URL valido")
        return f"righe_feed={len(lines)}; selezionate fino a {self.limit}; altri URL non scaricati automaticamente"
    def collect_text_feed(self,url,label,kind,category):
        response=self.client.request(url).decode("utf-8-sig")
        if "<html" in response[:500].lower():raise SourceFailure("Il feed ha restituito HTML, non testo")
        accepted=0; rejected=0; scanned=0
        for line in response.splitlines():
            item=line.strip()
            if not item or item.startswith("#"):continue
            scanned+=1
            if self.add(kind,item,label,category,url):accepted+=1
            else:rejected+=1
            if accepted>=self.limit:break
        if scanned and accepted==0:raise SourceFailure(f"Feed {label}: formato inatteso, {rejected} righe non valide")
        return f"record_esaminati={scanned}; validi={accepted}; invalidi={rejected}; non verificati localmente"

    def collect_feodo(self):
        text=self.client.request(FEODO).decode("utf-8-sig")
        if "<html" in text[:500].lower():raise SourceFailure("Risposta HTML inattesa")
        lines=[x.strip() for x in text.splitlines() if x.strip() and not x.lstrip().startswith("#")]
        bad=0
        for ip in lines[:self.limit]:
            if not self.add("ip",ip,"Feodo Tracker","reported botnet C2",FEODO):bad+=1
        if lines and bad==len(lines[:self.limit]):raise SourceFailure("Formato Feodo inatteso")
        return f"righe_feed={len(lines)}; possono esserci zero C2 attivi"
    def collect_et(self,url,label,category):
        text=self.client.request(url).decode("utf-8-sig")
        if "<html" in text[:500].lower():raise SourceFailure("Feed ET restituisce HTML")
        lines=[x.strip().split()[0] for x in text.splitlines() if x.strip() and not x.lstrip().startswith(("#",";"))]
        if not lines:raise SourceFailure("Feed ET vuoto o formato inatteso")
        accepted=0;cidrs=0;ips=0;rejected=0
        for value in lines:
            if accepted>=self.limit:break
            kind="cidr" if "/" in value else "ip"
            parsed=parse_indicator(kind,value)
            if not parsed:
                rejected+=1;continue
            if self.add(kind,value,label,category,url):
                accepted+=1
                if parsed[0]=="cidr":cidrs+=1
                else:ips+=1
        if not accepted:raise SourceFailure(f"Feed ET senza IP/CIDR validi: righe={len(lines)}")
        return f"righe_feed={len(lines)}; importati={accepted} (ip={ips}, cidr={cidrs}); invalidi={rejected}; limite={self.limit}; CIDR non espansi"

    def collect_blocklist(self):
        text=self.client.request(BLOCKLIST).decode("utf-8-sig")
        if "<html" in text[:500].lower():raise SourceFailure("Blocklist.de restituisce HTML")
        count=0;examined=0
        for line in text.splitlines():
            value=line.strip()
            if not value or value.startswith("#"):continue
            examined+=1
            if self.add("ip",value,"Blocklist.de","IP reported attacking monitored services (last 48h)",BLOCKLIST):count+=1
            if count>=self.limit:break
        if examined and not count:raise SourceFailure("Blocklist.de senza IP validi")
        return f"righe_valutate={examined}; importati={count}; segnalazioni esterne, non prove di malevolenza permanente"

    def collect_spamhaus(self):
        # Cache downloads for at least one day per Spamhaus public DROP fair use guidance.
        cached=False
        cache=self.spamhaus_cache
        if cache and cache.is_file() and time.time()-cache.stat().st_mtime<86400:
            content=cache.read_bytes();cached=True
        else:
            content=self.client.request(SPAMHAUS)
        lines=content.decode("utf-8-sig").splitlines()
        accepted=0;parsed=0;copyright_text=""
        for line in lines:
            if not line.strip():continue
            try:row=json.loads(line)
            except ValueError:raise SourceFailure("Spamhaus DROP non e' formato JSONL previsto") from None
            if not isinstance(row,dict):continue
            if "copyright" in row:copyright_text=str(row["copyright"])[:150]
            if "cidr" not in row:continue
            parsed+=1
            if accepted>=self.limit:continue
            cidr=row.get("cidr","")
            if self.add("cidr",cidr,"Spamhaus DROP","DROP network block report",SPAMHAUS,
                        context=f"sblid={row.get('sblid','')}; The Spamhaus Project; (c) Spamhaus; access_date={self.start[:10]}"):
                accepted+=1
        if not parsed:raise SourceFailure("Spamhaus DROP privo di record cidr")
        if cache and not cached:
            cache.parent.mkdir(parents=True,exist_ok=True)
            cache.write_bytes(content)
        return f"record_cidr={parsed}; importati={accepted}; cache_24h={cached}; attribution=The Spamhaus Project; {copyright_text}"

    def collect_ipsum(self):
        text=self.client.request(IPSUM).decode("utf-8-sig")
        if "<html" in text[:500].lower():raise SourceFailure("Feed IPsum restituisce HTML")
        good=0;total=0
        # IPsum: one IP and aggregate occurrence count per line, separated by whitespace.
        for line in text.splitlines():
            line=line.strip()
            if not line or line.startswith("#"):continue
            parts=line.split()
            if len(parts)<2:continue
            total+=1
            try:count=int(parts[1])
            except ValueError:continue
            if count<3:continue
            if self.add("ip",parts[0],"IPsum","aggregated suspicious IP (3+ upstream lists)",
                        IPSUM,context=f"upstream_list_occurrences={count}; aggregated source, not independent verification"):
                good+=1
            if good>=self.limit:break
        if total and not good:raise SourceFailure("IPsum senza righe valide con 3+ liste")
        return f"righe_valutate={total}; soglia_presenze>=3; records={good}; conteggio non prova compromissione"

    def collect_cisa_kev(self):
        doc=self.client.json(CISA_KEV)
        items=doc.get("vulnerabilities")
        if not isinstance(items,list):raise SourceFailure("Schema CISA KEV inatteso: manca vulnerabilities")
        ordered=sorted((only_dict(x) for x in items),key=lambda x:str(x.get("dateAdded", "")),reverse=True)
        for item in ordered:
            cve=str(item.get("cveID", "")).upper()
            if not CVE_RE.fullmatch(cve):continue
            self.vulnerabilities.append({
                "cve":cve,"date_added":str(item.get("dateAdded", "")),
                "vendor":str(item.get("vendorProject", "")),"product":str(item.get("product", "")),
                "name":str(item.get("vulnerabilityName", "")),
                "ransomware_use":str(item.get("knownRansomwareCampaignUse", "")),
                "due_date":str(item.get("dueDate", "")),
                "epss":"", "epss_percentile":"", "epss_date":"",
                "source":"CISA KEV","source_reference":CISA_KEV})
            if len(self.vulnerabilities)>=self.kev_limit:break
        if not self.vulnerabilities:raise SourceFailure("CISA KEV senza CVE validi")
        return f"catalogo_CISA={len(items)}; CVE_piu_recenti={len(self.vulnerabilities)}; CVE non equivalgono a IOC"

    def collect_first_epss(self):
        if not self.vulnerabilities:return "Nessuna CVE CISA disponibile; EPSS non interrogato"
        updated=0
        lookup={r["cve"]:r for r in self.vulnerabilities}
        keys=list(lookup)
        for offset in range(0,len(keys),35):
            batch=keys[offset:offset+35]
            url=FIRST_EPSS+"?"+urlencode({"cve":",".join(batch)})
            doc=self.client.json(url)
            items=doc.get("data")
            if not isinstance(items,list):raise SourceFailure("Schema FIRST EPSS inatteso")
            for row in items:
                row=only_dict(row)
                cve=str(row.get("cve", "")).upper()
                if cve not in lookup:continue
                try:
                    score=float(row.get("epss"));percentile=float(row.get("percentile"))
                except (ValueError,TypeError):continue
                if not (0.0<=score<=1.0 and 0.0<=percentile<=1.0):continue
                lookup[cve]["epss"]=format(score,".8f")
                lookup[cve]["epss_percentile"]=format(percentile,".8f")
                lookup[cve]["epss_date"]=str(row.get("date", ""))
                updated+=1
        return f"CVE richieste={len(keys)}, valori EPSS restituiti={updated}; probabilita' predittiva, non prova di attacco"

    def candidate_ips(self,limit):
        # 1) Overlaps across named sources, 2) C2 feeds, 3) reported compromised,
        # 4) other reported IPs. This is a query ORDER, never a maliciousness score.
        records={}
        for row in self.records:
            if row["type"]!="ip":continue
            value=row["indicator"]
            records.setdefault(value,set()).add(row["source"])
        priority={"Feodo Tracker":0,"ThreatFox":1,"Emerging Threats Compromised":2,
                  "Emerging Threats Block":3,"Blocklist.de":4,"IPsum":5}
        def rank(entry):
            ip,sources=entry
            # Do not treat IPsum aggregation as a separate independent confirmation.
            independent={s for s in sources if s!="IPsum"}
            return (-len(independent),min((priority.get(s,10) for s in sources),default=10),ip)
        return [ip for ip,_ in sorted(records.items(),key=rank)[:limit]]

    def ripe_lookup(self):
        # Routing context, NOT maliciousness or attribution. No credentials necessary.
        selected=self.candidate_ips(self.ripe_limit)
        ok=0;failed=0
        for ip in selected:
            try:
                url=RIPESTAT+"?"+urlencode({"resource":ip,"sourceapp":"cti-auto-collector"})
                doc=self.client.json(url)
                if doc.get("status") not in ("ok",None):raise SourceFailure("RIPEstat: status non ok")
                details=only_dict(doc.get("data"))
                if not details:raise SourceFailure("RIPEstat: dati assenti")
                prefix=details.get("prefix") or ""
                asns=details.get("asns")
                if not isinstance(asns,list):asns=[]
                self.enrichment.append({"indicator":ip,"type":"ip","source":"RIPEstat","status":"ok",
                    "prefix":str(prefix),"asn":"; ".join(str(int(a)) for a in asns if str(a).isdigit()),
                    "source_reference":url,
                    "note":"BGP announcing ASN and prefix; routing context only; not evidence of malicious activity"})
                ok+=1
            except SourceFailure as exc:
                failed+=1
                self.enrichment.append({"indicator":ip,"type":"ip","source":"RIPEstat","status":"error",
                    "prefix":"","asn":"","note":str(exc)[:130]})
                if any(code in str(exc) for code in ("429","401","403")) or (failed>=3 and ok==0):break
        if failed and not ok:raise SourceFailure(f"RIPEstat: {failed} interrogazioni fallite (interrotte per evitare richieste ripetitive)")
        return f"IP esaminati={ok+failed}; risposte valide={ok}; informazioni BGP, non reputazione"

    def greynoise_lookup(self):
        selected=self.candidate_ips(self.gn_limit)
        if not selected:return "Nessun IP pubblico disponibile da arricchire"
        ok=0;errors=0
        for i,ip in enumerate(selected):
            if i:time.sleep(1.1)  # Respect limited community access.
            try:
                doc=self.client.json(f"{GREYNOISE}/{ip}")
                if doc.get("ip")!=ip or not isinstance(doc.get("noise"),bool) or not isinstance(doc.get("riot"),bool):
                    raise SourceFailure("Risposta GreyNoise inattesa: campi principali mancanti")
                self.enrichment.append({"indicator":ip,"type":"ip","source":"GreyNoise","status":"ok",
                  "noise":doc.get("noise", ""),"riot":doc.get("riot", ""),
                  "classification":str(doc.get("classification", "")),"name":str(doc.get("name", "")),
                  "last_seen":str(doc.get("last_seen", "")),
                  "source_reference":str(doc.get("link", "")),
                  "note":"GreyNoise community observations; not proof of local compromise",
                  "malicious":"","suspicious":"","harmless":"","undetected":"","as_owner":"","country":""})
                ok+=1
            except SourceFailure as exc:
                code404="HTTP 404" in str(exc)
                self.enrichment.append({"indicator":ip,"type":"ip","source":"GreyNoise",
                  "status":"not_found" if code404 else "error","note":str(exc)[:180],
                  "noise":"","riot":"","classification":"","name":"","last_seen":"",
                  "source_reference":"","malicious":"","suspicious":"","harmless":"",
                  "undetected":"","as_owner":"","country":""})
                if not code404:errors+=1
                if "429" in str(exc) or "403" in str(exc) or "401" in str(exc):
                    # Stop after quota/access failure; do not multiply requests.
                    break
        if errors and not ok:raise SourceFailure(f"GreyNoise: {errors} richieste fallite su {len(selected)}")
        return f"IP esaminati={len(selected)}; record trovati={ok}; 404=non presente; limiti API community"

    def collect_threatfox(self):
        data=self.client.json(THREATFOX,headers={"Auth-Key":self.abuse_key},json_body={"query":"get_iocs","days":1})
        if data.get("query_status") not in ("ok","no_result","no_results"):
            raise SourceFailure("ThreatFox query_status="+str(data.get("query_status")))
        rows=only_list(data.get("data"))
        for row in rows[:self.limit]:
            row=only_dict(row);kind=str(row.get("ioc_type","")).lower();raw=row.get("ioc","")
            if kind in ("ip:port", "ip_port"):
                # Preserve the port: a reported endpoint does not imply all services on that IP are malicious.
                kind="ip_port"
            kind={"sha256_hash":"sha256","sha1_hash":"sha1","md5_hash":"md5",
                  "ip_address":"ip","hostname":"domain","hostname:port":"domain_port",
                  "domain:port":"domain_port","ip:port":"ip_port","sha256":"sha256"}.get(kind,kind)
            self.add(kind,raw,"ThreatFox",str(row.get("threat_type","reported IOC")),
                     "https://threatfox.abuse.ch/",row.get("first_seen_utc",""),str(row.get("malware_printable","")))
        return f"API rows={len(rows)}; query=last 1 day"
    def collect_bazaar(self):
        data=self.client.json(BAZAAR,headers={"Auth-Key":self.abuse_key},form={"query":"get_recent","selector":"100"})
        if data.get("query_status") not in ("ok","no_results"):
            raise SourceFailure("MalwareBazaar query_status="+str(data.get("query_status")))
        rows=only_list(data.get("data"))
        for row in rows[:self.limit]:
            row=only_dict(row); hashv=row.get("sha256_hash","")
            sig=str(row.get("signature","") or "")
            for digest in ("sha256","sha1","md5"):
                value=row.get(f"{digest}_hash","")
                if digest=="sha256":value=hashv
                self.add(digest,value,"MalwareBazaar","reported malware sample digest",
                         "https://bazaar.abuse.ch/",row.get("first_seen",""),
                         f"sample_sha256={hashv}; signature={sig}"[:195])
        return f"API rows={len(rows)}; selector=last 100"
    def vt_lookup(self):
        # Passive VT lookup only; does NOT submit samples or visit URLs.
        # Ensure multiple indicator types get sampled instead of only IPs.
        by_type={}
        for r in self.records:
            by_type.setdefault(r["type"],set()).add(r["indicator"])
        selected=[];seen=set()
        choices={"ip":self.candidate_ips(self.vt_limit),
                 "sha256":sorted(by_type.get("sha256",[])),
                 "md5":sorted(by_type.get("md5",[])),
                 "sha1":sorted(by_type.get("sha1",[])),
                 "domain":sorted(by_type.get("domain",[])),
                 "url":sorted(by_type.get("url",[]))}
        # Breadth-first sampling by observable type; not a threat severity ranking.
        for typ in ("sha256","domain","url","ip","md5","sha1"):
            if choices[typ]:
                selected.append((typ,choices[typ].pop(0)))
        for typ in ("ip","sha256","domain","url","md5","sha1"):
            for val in choices[typ]:selected.append((typ,val))
        targets=[]
        for typ,val in selected:
            if (typ,val) not in seen:
                targets.append((typ,val));seen.add((typ,val))
            if len(targets)>=self.vt_limit:break
        if not targets:return "Nessun IOC idoneo per lookup passivo"
        for idx,(typ,value) in enumerate(targets):
            if idx:time.sleep(16.0)  # Conservative free-tier pacing.
            if typ=="ip":part="ip_addresses";identifier=value
            elif typ=="domain":part="domains";identifier=value
            elif typ=="url":
                part="urls"
                identifier=base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
            else:part="files";identifier=value
            try:
                data=self.client.json(f"{VT}/{part}/{identifier}",headers={"x-apikey":self.vt_key})
                attrs=only_dict(only_dict(data.get("data")).get("attributes"))
                counts=only_dict(attrs.get("last_analysis_stats"))
                if not attrs:raise SourceFailure("VT: attributi mancanti")
                self.enrichment.append({"indicator":value,"type":typ,"source":"VirusTotal","status":"ok",
                    "malicious":counts.get("malicious",""),"suspicious":counts.get("suspicious",""),
                    "harmless":counts.get("harmless",""),"undetected":counts.get("undetected",""),
                    "as_owner":attrs.get("as_owner",""),"country":attrs.get("country",""),
                    "source_reference":f"https://www.virustotal.com/gui/{'ip-address' if typ=='ip' else 'file' if part=='files' else part[:-1]}/{identifier}",
                    "note":"VT vendor detections; not proof of local compromise"})
            except SourceFailure as exc:
                self.enrichment.append({"indicator":value,"type":typ,"source":"VirusTotal","status":"error",
                    "malicious":"","suspicious":"","harmless":"","undetected":"","as_owner":"","country":"","note":str(exc)[:130]})
                if any(code in str(exc) for code in ("429","401","403")):break
        return f"lookup effettuati={len([x for x in self.enrichment if x.get('source')=='VirusTotal'])}; intervallo=16s tra richieste"

    def build_unique(self):
        groups={}
        for r in self.records:
            key=(r["type"],r["indicator"])
            g=groups.setdefault(key,{"type":key[0],"indicator":key[1],"sources":set(),
                "publisher_groups":set(),"classifications":set(),"source_references":set(),
                "first_seen_values":[],"collected_utc":self.start})
            g["sources"].add(r["source"])
            g["publisher_groups"].add(publisher_group(r["source"]))
            g["classifications"].add(r["classification"])
            if r["source_reference"]:g["source_references"].add(r["source_reference"])
            if r["reported_first_seen"]:g["first_seen_values"].append(r["reported_first_seen"])
        result=[]
        for g in groups.values():
            feeds=sorted(g["sources"])
            non_aggregate=sorted({publisher_group(n) for n in feeds if n not in AGGREGATORS})
            result.append({"type":g["type"],"indicator":g["indicator"],"source_count":len(feeds),
                "sources":"; ".join(feeds),"publisher_count":len(g["publisher_groups"]),
                "publisher_groups":"; ".join(sorted(g["publisher_groups"])),
                "direct_publisher_count":len(non_aggregate),
                "correlation_level":("multiple_nonaggregator_publishers" if len(non_aggregate)>1
                                     else "multiple_feeds_shared_or_aggregated" if len(feeds)>1 else "single_feed"),
                "classifications":"; ".join(sorted(g["classifications"])),
                "reported_first_seen":min(g["first_seen_values"]) if g["first_seen_values"] else "",
                "source_references":"; ".join(sorted(g["source_references"])),
                "collected_utc":self.start})
        return sorted(result,key=lambda r:(-r["direct_publisher_count"],-r["source_count"],*indicator_sort_key(r)))

    def build_correlations(self):
        return [{**r,"note":"Same exact IOC; publisher groups and aggregator dependency shown. NOT proof of compromise."}
                for r in self.build_unique() if r["source_count"]>=2]

    def build_relations(self):
        # Contextual relationships are NOT independent corroboration, and are not added to indicator counts.
        unique=self.build_unique()
        ips=[r for r in unique if r["type"]=="ip"]
        domains={r["indicator"]:r for r in unique if r["type"]=="domain"}
        networks={}
        for row in unique:
            if row["type"]!="cidr":continue
            try: net=ipaddress.ip_network(row["indicator"],strict=True)
            except ValueError:continue
            networks[(net.version,net.prefixlen,int(net.network_address))]=row
        relations=[]
        for row in ips:
            ip=ipaddress.ip_address(row["indicator"])
            integer=int(ip)
            bits=ip.max_prefixlen
            for prefix in range(bits+1):
                mask=(2**bits-1)^((1<<(bits-prefix))-1) if prefix else 0
                found=networks.get((ip.version,prefix,integer&mask))
                if found:
                    relations.append({"relation":"ip_within_reported_cidr","left_type":"ip","left_indicator":row["indicator"],
                        "right_type":"cidr","right_indicator":found["indicator"],"left_sources":row["sources"],
                        "right_sources":found["sources"],"meaning":"Range membership only, NOT proof of host compromise"})
        for row in unique:
            if row["type"]!="url":continue
            try:hostname=urlsplit(row["indicator"]).hostname
            except ValueError:hostname=None
            if not hostname:continue
            try:host=hostname.encode("idna").decode("ascii").lower().rstrip('.')
            except UnicodeError:continue
            if host not in domains:continue
            relations.append({"relation":"url_host_matches_reported_domain","left_type":"url",
                "left_indicator":row["indicator"],"right_type":"domain","right_indicator":host,
                "left_sources":row["sources"],"right_sources":domains[host]["sources"],
                "meaning":"URL host association only; not an independent feed sighting"})
        return sorted(relations,key=lambda x:(x["relation"],x["left_indicator"],x["right_indicator"]))

    def execute(self):
        self.start=now()
        if self.openphish:
            self.run_source("OpenPhish",self.collect_openphish)
        else:self.checks.append({"source":"OpenPhish","status":"skipped","count":0,"detail":"opt-in necessario: --enable-openphish; termini uso personale/ricerca, non redistribuire dati"})
        # Public, no-credential domain and URL feeds; no browsing of reported links.
        self.run_source("CERT Polska Warning List",lambda:self.collect_text_feed(
            CERT_PL,"CERT Polska Warning List","domain","dangerous website domain on current warning list"))
        self.run_source("Phishunt",lambda:self.collect_text_feed(PHISHUNT,"Phishunt","domain","suspected phishing domain (aggregated)"))
        self.run_source("Phishing.Database URLs",lambda:self.collect_text_feed(
            PHISHING_DB_URL,"Phishing.Database URLs","url","phishing URL reported today"))
        self.run_source("Phishing.Database Domains",lambda:self.collect_text_feed(
            PHISHING_DB_DOMAIN,"Phishing.Database Domains","domain","phishing domain reported today"))
        self.run_source("Feodo Tracker",self.collect_feodo)
        self.run_source("Emerging Threats Compromised",lambda: self.collect_et(
          ET_COMPROMISED,"Emerging Threats Compromised","reported compromised host"))
        self.run_source("Emerging Threats Block",lambda: self.collect_et(
          ET_BLOCK,"Emerging Threats Block","reported suspicious/block IP"))
        self.run_source("IPsum",self.collect_ipsum)
        self.run_source("Blocklist.de",self.collect_blocklist)
        self.run_source("Spamhaus DROP",self.collect_spamhaus)
        self.run_source("CISA KEV",self.collect_cisa_kev)
        if self.vulnerabilities:self.run_source("FIRST EPSS",self.collect_first_epss)
        else:self.checks.append({"source":"FIRST EPSS","status":"skipped","count":0,"detail":"CISA KEV assente"})
        if self.abuse_key:
            self.run_source("ThreatFox",self.collect_threatfox)
            self.run_source("MalwareBazaar",self.collect_bazaar)
        else:
            for s in ("ThreatFox","MalwareBazaar"):
                self.checks.append({"source":s,"status":"skipped","count":0,"detail":"ABUSECH_AUTH_KEY non configurata"})
        if self.ripe_limit>0:
            before=len(self.enrichment)
            self.run_source("RIPEstat",self.ripe_lookup)
            self._fix_enrich_status("RIPEstat",self.enrichment[before:])
        else:self.checks.append({"source":"RIPEstat","status":"skipped","count":0,"detail":"--ripe-limit 0"})
        if self.gn_limit>0:
            before=len(self.enrichment)
            self.run_source("GreyNoise",self.greynoise_lookup)
            vals=self.enrichment[before:]
            self._fix_enrich_status("GreyNoise",vals)
        else:self.checks.append({"source":"GreyNoise","status":"skipped","count":0,"detail":"--gn-limit 0"})
        if self.vt_key and self.vt_limit>0:
            before=len(self.enrichment)
            self.run_source("VirusTotal",self.vt_lookup)
            self._fix_enrich_status("VirusTotal",self.enrichment[before:])
        else:self.checks.append({"source":"VirusTotal","status":"skipped","count":0,"detail":"VT_API_KEY assente o --vt-limit 0"})
        self.records.sort(key=indicator_sort_key)
        return {"generated_utc":self.start,"run_mode":"LIVE_FEEDS_ONLY","sources":self.checks,
          "indicators":self.records,"unique_indicators":self.build_unique(),
          "relations":self.build_relations(),"enrichment":self.enrichment,
          "vulnerabilities":self.vulnerabilities,"correlations":self.build_correlations(),
          "disclaimer":"Feed-listed indicators do not prove local compromise. CISA KEV entries are vulnerabilities, not IOCs. GreyNoise is contextual, not local detection. Source overlaps can reflect shared feeds. Manual verification required before blocking or MISP import."}

    def _fix_enrich_status(self,name,values):
        check=next((x for x in reversed(self.checks) if x["source"]==name),None)
        if check is None or check["status"]=="skipped":return
        if not values:return
        ok=sum(x.get("status")=="ok" for x in values)
        failures=sum(x.get("status")=="error" for x in values)
        check["count"]=ok
        if failures and ok:check["status"]="partial_error"
        elif failures and not ok:check["status"]="error"
        elif ok:check["status"]="ok"
        else:check["status"]="no_data"

# Native Office generators copied from previous verified build: no third-party libs required.
# Inline records are always plain text: never formulas or active hyperlinks.
def xml_bytes(root):
    uri=root.tag.partition("}")[0].lstrip("{")
    if uri in (CT,REL,S):ET.register_namespace("",uri)
    return ET.tostring(root,encoding="utf-8",xml_declaration=True)

def xcol(i):
    result=""
    while i:i,r=divmod(i-1,26);result=chr(65+r)+result
    return result

def sheet_xml(headers, rows):
    root=ET.Element(q(S,"worksheet"))
    views=ET.SubElement(root,q(S,"sheetViews"));v=ET.SubElement(views,q(S,"sheetView"),{"workbookViewId":"0"})
    ET.SubElement(v,q(S,"pane"),{"ySplit":"1","topLeftCell":"A2","activePane":"bottomLeft","state":"frozen"})
    widths=ET.SubElement(root,q(S,"cols"))
    for ci,title in enumerate(headers,1):
        width=54 if title in ("indicator","left_indicator","right_indicator","sources","classifications","source_references","source_reference") else (34 if title in ("context","detail","note","meaning") else 20)
        ET.SubElement(widths,q(S,"col"),{"min":str(ci),"max":str(ci),"width":str(width),"customWidth":"1"})
    data=ET.SubElement(root,q(S,"sheetData"))
    for ri,items in enumerate([headers]+list(rows),1):
        row=ET.SubElement(data,q(S,"row"),{"r":str(ri)})
        for ci,value in enumerate(items,1):
            c=ET.SubElement(row,q(S,"c"),{"r":xcol(ci)+str(ri),"t":"inlineStr","s":"1" if ri==1 else "0"})
            n=ET.SubElement(c,q(S,"is"));t=ET.SubElement(n,q(S,"t"))
            t.text=str(value if value is not None else "")[:31000].replace("\x00","")
    ET.SubElement(root,q(S,"autoFilter"),{"ref":f"A1:{xcol(len(headers))}{max(1,len(rows)+1)}"})
    return xml_bytes(root)

OBS_COLUMNS=["type","indicator","source","classification","reported_first_seen","source_reference","context","collected_utc"]
UNIQUE_COLUMNS=["type","indicator","source_count","sources","publisher_count","publisher_groups",
                "direct_publisher_count","correlation_level","classifications","reported_first_seen","source_references","collected_utc"]
CORR_COLUMNS=UNIQUE_COLUMNS+["note"]
REL_COLUMNS=["relation","left_type","left_indicator","right_type","right_indicator","left_sources","right_sources","meaning"]
ENR_COLUMNS=["indicator","type","source","status","malicious","suspicious","harmless","undetected",
             "as_owner","country","prefix","asn","noise","riot","classification","name","last_seen","source_reference","note"]
KEV_COLUMNS=["cve","date_added","vendor","product","name","ransomware_use","due_date","epss","epss_percentile","epss_date","source","source_reference"]

def workbook_sheets(data):
    unique=data.get("unique_indicators",[])
    # First sheet is the analyst's IOC index, not the raw feed rows.
    source_total=len({r["source"] for r in data["indicators"]})
    types=Counter(r["type"] for r in unique)
    summary=[{"metric":"Collected UTC","value":data.get("generated_utc","")},
             {"metric":"Observation rows","value":len(data["indicators"])},
             {"metric":"Unique typed IOCs","value":len(unique)},
             {"metric":"IOC feed names with records","value":source_total},
             {"metric":"Exact IOC source overlaps","value":len(data["correlations"])},
             {"metric":"Contextual relations - NOT independent matches","value":len(data.get("relations",[]))},
             {"metric":"CISA KEV (separate)","value":len(data["vulnerabilities"])}]
    summary.extend({"metric":"Unique "+typ.upper(),"value":types.get(typ,0)} for typ in IOC_TYPES)
    summary.extend({"metric":"Source: "+r["source"],"value":r["status"]+" / "+str(r["count"])} for r in data["sources"])
    sheets=[("Dashboard",["metric","value"],summary), ("IOC_INDEX",UNIQUE_COLUMNS,unique)]
    for typ in IOC_TYPES:
        rows=[r for r in unique if r["type"]==typ]
        sheets.append((f"IOC_{typ.upper()}",UNIQUE_COLUMNS,rows))
    sheets.extend([("Observations",OBS_COLUMNS,data["indicators"]),
                   ("Correlations",CORR_COLUMNS,data["correlations"]),
                   ("Relations",REL_COLUMNS,data.get("relations",[])),
                   ("Enrichment",ENR_COLUMNS,data["enrichment"]),
                   ("Sources",["source","status","count","detail"],data["sources"]),
                   ("CISA_KEV",KEV_COLUMNS,data["vulnerabilities"])])
    return sheets

def write_xlsx(path,data):
    sheets=workbook_sheets(data)
    ct=ET.Element(q(CT,"Types"))
    for ext,ctype in (("rels","application/vnd.openxmlformats-package.relationships+xml"),("xml","application/xml")):
        ET.SubElement(ct,q(CT,"Default"),{"Extension":ext,"ContentType":ctype})
    for path1,mime in (("/xl/workbook.xml","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"),("/xl/styles.xml","application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml")):
        ET.SubElement(ct,q(CT,"Override"),{"PartName":path1,"ContentType":mime})
    for i in range(1,len(sheets)+1):
        ET.SubElement(ct,q(CT,"Override"),{"PartName":f"/xl/worksheets/sheet{i}.xml","ContentType":"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"})
    rootrels=ET.Element(q(REL,"Relationships"))
    ET.SubElement(rootrels,q(REL,"Relationship"),{"Id":"rId1","Type":"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument","Target":"xl/workbook.xml"})
    book=ET.Element(q(S,"workbook")); bs=ET.SubElement(book,q(S,"sheets"))
    bookrels=ET.Element(q(REL,"Relationships"))
    for i,(name,_,_) in enumerate(sheets,1):
        ET.SubElement(bs,q(S,"sheet"),{"name":name,"sheetId":str(i),q(R,"id"):f"rId{i}"})
        ET.SubElement(bookrels,q(REL,"Relationship"),{"Id":f"rId{i}","Type":"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet","Target":f"worksheets/sheet{i}.xml"})
    ET.SubElement(bookrels,q(REL,"Relationship"),{"Id":f"rId{len(sheets)+1}","Type":"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles","Target":"styles.xml"})
    styles='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="10"/><name val="Calibri"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="10"/><name val="Calibri"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF17385A"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>'''
    with zipfile.ZipFile(path,"w",zipfile.ZIP_DEFLATED) as z:
        for name,content in (("[Content_Types].xml",xml_bytes(ct)),("_rels/.rels",xml_bytes(rootrels)),("xl/workbook.xml",xml_bytes(book)),("xl/_rels/workbook.xml.rels",xml_bytes(bookrels)),("xl/styles.xml",styles)):
            z.writestr(name,content)
        for i,(_,headers,rows) in enumerate(sheets,1):
            z.writestr(f"xl/worksheets/sheet{i}.xml",sheet_xml(headers,[[r.get(k,"") for k in headers] for r in rows]))

def write_csv(path,headers,rows):
    with path.open("w",newline="",encoding="utf-8-sig") as fp:
        writer=csv.DictWriter(fp,fieldnames=headers,extrasaction="ignore");writer.writeheader()
        for row in rows:
            # Protect CSV readers from spreadsheet formula injection
            safe={k:("'"+str(v) if str(v).lstrip().startswith(("=","+","-","@","\t","\r")) else v) for k,v in row.items()}
            writer.writerow(safe)

def make_png(bars,colors,width=920,height=360):
    bg=(250,252,254);bitmap=bytearray(bytes(bg)*width*height)
    def rect(x,y,w,h,c):
        for yy in range(max(0,y),min(height,y+h)):
            for xx in range(max(0,x),min(width,x+w)):
                at=(yy*width+xx)*3;bitmap[at:at+3]=bytes(c)
    rect(24,24,width-48,height-48,(238,244,248))
    count=max(1,len(bars));vmax=max(1,max((val for _,val in bars),default=0))
    for i,(_,v) in enumerate(bars):
        bh=min(32,max(12,(height-80)//count-13)); y=48+i*(height-75)//count
        rect(255,y,width-300,bh,(218,232,240))
        rect(255,y,int((width-300)*max(0,v)/vmax),bh,colors[i%len(colors)])
    chunks=[]
    for typ,buf in ((b"IHDR",struct.pack(">2I5B",width,height,8,2,0,0,0)),
                   (b"IDAT",zlib.compress(b"".join(b"\x00"+bitmap[i:i+width*3] for i in range(0,len(bitmap),width*3)),6)),(b"IEND",b"")):
        chunks.append(struct.pack(">I",len(buf))+typ+buf+struct.pack(">I",zlib.crc32(typ+buf)&0xffffffff))
    return b"\x89PNG\r\n\x1a\n"+b"".join(chunks)

def para(body,text,size=19,bold=False,color="263445",space=120):
    p=ET.SubElement(body,q(W,"p"));pr=ET.SubElement(p,q(W,"pPr"));ET.SubElement(pr,q(W,"spacing"),{q(W,"after"):str(space)})
    r=ET.SubElement(p,q(W,"r"));rp=ET.SubElement(r,q(W,"rPr"))
    ET.SubElement(rp,q(W,"sz"),{q(W,"val"):str(size)})
    ET.SubElement(rp,q(W,"color"),{q(W,"val"):color})
    if bold:ET.SubElement(rp,q(W,"b"))
    ET.SubElement(r,q(W,"t")).text=str(text)

def picture(body,rid,name,num):
    p=ET.SubElement(body,q(W,"p"));run=ET.SubElement(p,q(W,"r"));drawing=ET.SubElement(run,q(W,"drawing"))
    inline=ET.SubElement(drawing,q(WP,"inline"));ET.SubElement(inline,q(WP,"extent"),{"cx":"5486400","cy":"2142720"})
    ET.SubElement(inline,q(WP,"docPr"),{"id":str(num),"name":name,"descr":name})
    graphic=ET.SubElement(inline,q(A,"graphic"));gd=ET.SubElement(graphic,q(A,"graphicData"),{"uri":"http://schemas.openxmlformats.org/drawingml/2006/picture"})
    pic=ET.SubElement(gd,q(PIC,"pic"));nv=ET.SubElement(pic,q(PIC,"nvPicPr"))
    ET.SubElement(nv,q(PIC,"cNvPr"),{"id":"0","name":name});ET.SubElement(nv,q(PIC,"cNvPicPr"))
    fill=ET.SubElement(pic,q(PIC,"blipFill"));ET.SubElement(fill,q(A,"blip"),{q(R,"embed"):rid});stretch=ET.SubElement(fill,q(A,"stretch"));ET.SubElement(stretch,q(A,"fillRect"))
    sp=ET.SubElement(pic,q(PIC,"spPr"));xf=ET.SubElement(sp,q(A,"xfrm"));ET.SubElement(xf,q(A,"off"),{"x":"0","y":"0"});ET.SubElement(xf,q(A,"ext"),{"cx":"5486400","cy":"2142720"})
    shape=ET.SubElement(sp,q(A,"prstGeom"),{"prst":"rect"});ET.SubElement(shape,q(A,"avLst"))

def write_docx(path,data,chart1,chart2):
    doc=ET.Element(q(W,"document"));body=ET.SubElement(doc,q(W,"body"))
    ind=data["indicators"]; checks=data["sources"]
    para(body,"CYBER THREAT INTELLIGENCE",38,True,"17385A",210)
    para(body,"Automatic Multi-Type IOC Collection & Context",27,True,"2B5E77")
    para(body,"Live source collection | "+data["generated_utc"],17,False,"53657A",220)
    para(body,"EXECUTIVE SUMMARY",24,True,"17385A")
    indicator_feeds={r['source'] for r in ind}
    para(body,f"Collected {len(ind)} source-specific indicator records from {len(indicator_feeds)} public IOC feeds. Distinct values: {len(set((r['type'],r['indicator']) for r in ind))}.")
    para(body,"These are indicators REPORTED BY EXTERNAL FEEDS, not evidence of an incident in your network. Never block or import automatically without analyst validation and scope checks.",19,True,"8A3340",200)
    para(body,f"Cross-feed overlaps: {len(data['correlations'])}; CISA KEV vulnerability entries: {len(data['vulnerabilities'])} (not IOCs).",18)
    para(body,"1 | INDICATOR CATEGORIES",24,True,"17385A")
    picture(body,"rId1","Indicator types",1)
    for typ,num in sorted(Counter(r["type"] for r in ind).items()):para(body,f"{typ.upper()}: {num} source records")
    para(body,"2 | SOURCE HEALTH",24,True,"17385A")
    picture(body,"rId2","Source health",2)
    for check in checks:para(body,f"{check['source']}: {check['status']} / {check['count']} findings — {check['detail'][:140]}",17)
    para(body,"3 | IOC INDEX — BY CATEGORY (SAMPLES)",24,True,"17385A")
    unique=data.get("unique_indicators",[])
    for typ in IOC_TYPES:
        selection=[x for x in unique if x["type"]==typ]
        if not selection:continue
        para(body,f"{typ.upper()} | {len(selection)} unique",19,True,"246C83")
        for x in selection[:3]:
            para(body,f"{x['indicator'][:105]} | feeds={x['source_count']} | {x['sources'][:85]}",16)
    para(body,"The full, untruncated IOC index with provenance and dedicated type sheets is in CTI_Findings.xlsx / unique_indicators.csv. Never treat source listings as detection in your own network.",17)
    para(body,"4 | PUBLIC-FEED CORRELATION",24,True,"17385A")
    para(body,"Exact-match feed overlap only. Aggregated feeds (IPsum, Phishunt) are not counted as independent publishers. A network containing an IP is a RELATION, not a corroborating sighting.",18)
    for x in data["correlations"][:8]:
        para(body,f"{x['type']}: {x['indicator'][:60]} | feeds={x['source_count']} | non-aggregating publishers={x['direct_publisher_count']} | {x['sources'][:65]}",17)
    para(body,f"Contextual relations (IP in CIDR / URL host): {len(data.get('relations',[]))}; separate sheet and CSV, excluded from overlap counts.",17)
    para(body,"5 | IP ENRICHMENT: RIPESTAT, GREYNOISE & VIRUSTOTAL",24,True,"17385A")
    for x in data["enrichment"][:12]:
        detail=(f"prefix={x.get('prefix')} ASN={x.get('asn')}" if x['source']=="RIPEstat" else
               (f"noise={x.get('noise')} riot={x.get('riot')}" if x['source']=="GreyNoise" else
                f"malicious={x.get('malicious')} suspicious={x.get('suspicious')}"))
        para(body,f"{x['source']}: {x['type']} {x['indicator'][:55]} | {x['status']} | {detail}",17)
    if not data["enrichment"]:para(body,"No enrichment queries returned observations.",17)
    para(body,"6 | CISA KNOWN EXPLOITED VULNERABILITIES",24,True,"17385A")
    para(body,"The following are separate vulnerability-intelligence records (CVE), not indicators of network compromise.",17)
    para(body,"EPSS: estimated probability of exploitation in the next 30 days. It is not proof of active exploitation, nor a CVSS severity score.",17)
    for x in data["vulnerabilities"][:8]:para(body,f"{x['date_added']} | {x['cve']} | {x['vendor']} {x['product']} | EPSS={x.get('epss') or 'n/a'}",17)
    para(body,"7 | OPERATIONAL LIMITATIONS",24,True,"17385A")
    para(body,"OpenPhish is opt-in for non-commercial personal research only under its own Terms; do not redistribute feed content. CERT Polska entries are current reported warning-list domains, not automatically compromised. Feodo can be empty. ET Block and Spamhaus DROP may contain CIDR networks and are never automatically expanded. IPsum aggregates third-party lists and is not independent evidence. CISA KEV and EPSS are separate vulnerability intelligence. GreyNoise access is quota-limited; ThreatFox/MalwareBazaar and VirusTotal need their own API keys.",18)
    para(body,"The tool does not scan hosts, visit phishing URLs, verify exploitation, detect local network contacts or send indicators to MISP. IP/CIDR reports are external claims only. Verify organizational monitoring perimeter and freshness before operational use.",18)
    section=ET.SubElement(body,q(W,"sectPr"));ET.SubElement(section,q(W,"pgSz"),{q(W,"w"):"11906",q(W,"h"):"16838"})
    ET.SubElement(section,q(W,"pgMar"),{q(W,"top"):"990",q(W,"right"):"900",q(W,"bottom"):"900",q(W,"left"):"900",q(W,"header"):"460",q(W,"footer"):"460",q(W,"gutter"):"0"})
    ct=ET.Element(q(CT,"Types"))
    for ext,mime in (("rels","application/vnd.openxmlformats-package.relationships+xml"),("xml","application/xml"),("png","image/png")):
        ET.SubElement(ct,q(CT,"Default"),{"Extension":ext,"ContentType":mime})
    ET.SubElement(ct,q(CT,"Override"),{"PartName":"/word/document.xml","ContentType":"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"})
    rels=ET.Element(q(REL,"Relationships"));ET.SubElement(rels,q(REL,"Relationship"),{"Id":"rId1","Type":"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument","Target":"word/document.xml"})
    pics=ET.Element(q(REL,"Relationships"))
    for i in (1,2):ET.SubElement(pics,q(REL,"Relationship"),{"Id":f"rId{i}","Type":"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image","Target":f"media/chart{i}.png"})
    with zipfile.ZipFile(path,"w",zipfile.ZIP_DEFLATED) as z:
        for name,obj in (("[Content_Types].xml",xml_bytes(ct)),("_rels/.rels",xml_bytes(rels)),("word/document.xml",xml_bytes(doc)),("word/_rels/document.xml.rels",xml_bytes(pics)),("word/media/chart1.png",chart1),("word/media/chart2.png",chart2)):
            z.writestr(name,obj)

def export(out,data):
    out.mkdir(parents=True,exist_ok=True)
    schemas={"indicators":OBS_COLUMNS,"unique_indicators":UNIQUE_COLUMNS,
             "sources":["source","status","count","detail"],"enrichment":ENR_COLUMNS,
             "correlations":CORR_COLUMNS,"relations":REL_COLUMNS,"vulnerabilities":KEV_COLUMNS}
    for key,columns in schemas.items():write_csv(out/f"{key}.csv",columns,data.get(key,[]))
    # Separate type lists with one row per unique typed IOC, all provenance preserved.
    ioc_dir=out/"IOC_per_tipo";ioc_dir.mkdir(exist_ok=True)
    for typ in IOC_TYPES:
        write_csv(ioc_dir/f"{typ}.csv",UNIQUE_COLUMNS,[r for r in data.get("unique_indicators",[]) if r["type"]==typ])
    (out/"analysis.json").write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding="utf-8")
    write_xlsx(out/"CTI_Findings.xlsx",data)
    types=Counter(r["type"] for r in data.get("unique_indicators",[]))
    statuses=Counter(r["status"] for r in data["sources"])
    charts=out/"charts";charts.mkdir(exist_ok=True)
    c1=make_png([(k,types.get(k,0)) for k in IOC_TYPES[:8]],[(32,118,170),(27,147,115),(80,151,163),(32,159,134),(149,99,173),(207,132,57)])
    c2=make_png([(k,statuses.get(k,0)) for k in ("ok","no_data","error","partial_error","skipped")],[(27,147,115),(107,143,169),(207,92,92),(197,158,81)])
    (charts/"types.png").write_bytes(c1);(charts/"source_status.png").write_bytes(c2)
    write_docx(out/"CTI_Report.docx",data,c1,c2)

def main(argv=None,transport=None):
    parser=argparse.ArgumentParser(description="CTI feed collector: trova IOC pubblici automaticamente, senza inserire IP/hash e senza pip")
    parser.add_argument("-o","--output",default="CTI_Risultati",help="Cartella di output")
    parser.add_argument("--limit",type=int,default=2000,help="Massimo record per feed (default 2000, max 5000)")
    parser.add_argument("--vt-limit",type=int,default=4,help="Lookup VT se chiave disponibile (default 4, max 10)")
    parser.add_argument("--gn-limit",type=int,default=5,help="Lookup IP GreyNoise (default 5, max 10; quota anonima)")
    parser.add_argument("--ripe-limit",type=int,default=30,help="Enrichment routing RIPEstat senza chiave (default 30, max 150)")
    parser.add_argument("--kev-limit",type=int,default=50,help="CVE recenti CISA (default 50, max 100)")
    parser.add_argument("--enable-openphish",action="store_true",help="Usa feed OpenPhish solo per ricerca personale non commerciale, secondo i suoi termini")
    parser.add_argument("--version",action="version",version=VERSION)
    args=parser.parse_args(argv)
    if not 1<=args.limit<=5000:parser.error("--limit deve essere fra 1 e 5000")
    if not 0<=args.vt_limit<=10:parser.error("--vt-limit deve essere fra 0 e 10")
    if not 0<=args.gn_limit<=10:parser.error("--gn-limit deve essere fra 0 e 10")
    if not 0<=args.ripe_limit<=150:parser.error("--ripe-limit deve essere fra 0 e 150")
    if not 1<=args.kev_limit<=100:parser.error("--kev-limit deve essere fra 1 e 100")
    ca=os.getenv("REQUESTS_CA_BUNDLE") or os.getenv("SSL_CERT_FILE")
    if ca and not Path(ca).is_file():parser.error("CA bundle non trovato in REQUESTS_CA_BUNDLE/SSL_CERT_FILE")
    print("\nCTI AUTO COLLECTOR | Raccolta automatica di IOC REALI dalle fonti pubbliche\n")
    print("Non vengono interrogati o contattati direttamente gli host segnalati dai feed.\n")
    client=HTTPClient(cafile=ca,transport=transport)
    collector=Collector(client,limit=args.limit,abuse_key=os.getenv("ABUSECH_AUTH_KEY","") or os.getenv("MB_AUTH_KEY",""),
                        vt_key=os.getenv("VT_API_KEY",""),vt_limit=args.vt_limit,
                        gn_limit=args.gn_limit,kev_limit=args.kev_limit,ripe_limit=args.ripe_limit,openphish=args.enable_openphish,
                        spamhaus_cache=Path(args.output)/"_cache"/"spamhaus_drop_v4.jsonl")
    data=collector.execute()
    out=Path(args.output)
    export(out,data)
    good=[x for x in data["sources"] if x["status"]=="ok"]
    print("\n=========== RISULTATO ===========")
    print("Indicatori segnalati e raccolti:",len(data["indicators"]))
    print("Fonti con risultati (include fonti CVE/enrichment):",len(good))
    print("Indicatori univoci:",len(data['unique_indicators']))
    print("Tipologie univoche:",dict(Counter(x['type'] for x in data['unique_indicators'])))
    print("Relazioni contestuali (NON conferme indipendenti):",len(data['relations']))
    print("Indicatori segnalati da piu' feed (exact match):",len(data['correlations']))
    print("Vulnerabilita' CISA KEV (separate dagli IOC):",len(data['vulnerabilities']))
    print("Record enrichment:",len(data['enrichment']))
    if data["indicators"]:
        print("Prime osservazioni pubblicate nei feed:")
        for item in sorted(data["unique_indicators"],key=indicator_sort_key)[:5]:
            print(f" - [{item['source']}] {item['type']}: {item['indicator'][:105]}")
    print("Output:",out.resolve())
    print("File: CTI_Report.docx, CTI_Findings.xlsx, unique_indicators.csv, indicators.csv, correlations.csv, relations.csv, enrichment.csv, sources.csv, vulnerabilities.csv, analysis.json, IOC_per_tipo/, charts/")
    if not data["indicators"]:
        print("ATTENZIONE: nessuna fonte ha restituito IOC validi. Controlla sources.csv e rete/SSL.")
        return 2
    print("ATTENZIONE: feed IOC != compromissione locale confermata. Analisi operativa manuale necessaria.")
    return 0

if __name__=="__main__":
    try:sys.exit(main())
    except (OSError,ValueError) as exc:
        print("ERRORE:",str(exc),file=sys.stderr)
        sys.exit(1)
