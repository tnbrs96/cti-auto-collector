"""Deterministic offline regression suite; never downloads live CTI feeds."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZipFile

SCRIPT=Path(__file__).resolve().parent/'CTI_Auto_Collector.py'
spec=importlib.util.spec_from_file_location('cti_auto',SCRIPT)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

CISA_SAMPLE={'vulnerabilities':[
    {'cveID':'CVE-2024-11111','dateAdded':'2026-09-30','vendorProject':'Fictional Inc','product':'Test Product','vulnerabilityName':'Example bug','knownRansomwareCampaignUse':'Unknown','dueDate':'2026-10-15'},
    {'cveID':'CVE-2022-22222','dateAdded':'2026-10-04','vendorProject':'Sample Co','product':'Appliance','vulnerabilityName':'Example flaw','knownRansomwareCampaignUse':'Known','dueDate':'2026-10-30'},
    {'cveID':'not-a-cve','dateAdded':'2026-10-05'}
]}

class FakeTransport:
    def __init__(self):self.calls=[]
    def __call__(self,url,body,headers):
        self.calls.append(url)
        if url==mod.CERT_PL:return b'cert-warning.example\nnext-cert.example\n'
        if url==mod.PHISHUNT:return b'fresh-one.example\nfresh-two.example\n'
        if url==mod.PHISHING_DB_URL:return b'https://fresh-one.example/a\nhttps://landing.example/path\n'
        if url==mod.PHISHING_DB_DOMAIN:return b'fresh-one.example\nlanding.example\n'
        if url==mod.OPENPHISH:return b'https://phish.example/abc\nhttps://test.example/account\n'
        if url==mod.FEODO:return b'# botnet C2\n11.22.33.44\n'
        if url==mod.ET_COMPROMISED:return b'11.22.33.44\n22.33.44.55\n'
        if url==mod.ET_BLOCK:return b'# ET Block\n22.33.44.55\n33.44.55.0/24\n11.22.33.44\n'
        if url==mod.IPSUM:return b'# IP\toccurrences\n22.33.44.55\t8\n33.44.55.66\t3\n55.66.77.88\t2\n'
        if url==mod.BLOCKLIST:return b'65.32.11.9\n65.32.11.10\n'
        if url.startswith(mod.RIPESTAT+'?'):return json.dumps({'status':'ok','data':{'prefix':'44.55.0.0/16','asns':[64501]}}).encode()
        if url==mod.SPAMHAUS:return b'{"cidr":"198.51.100.0/24","sblid":"SBL123"}\n{"cidr":"44.55.0.0/16","sblid":"SBL999"}\n{"copyright":"Copyright Spamhaus Project"}\n'
        if url==mod.CISA_KEV:return json.dumps(CISA_SAMPLE).encode()
        if url.startswith(mod.FIRST_EPSS+'?'):
            return json.dumps({'data':[{'cve':'CVE-2022-22222','epss':'0.12345','percentile':'0.87654','date':'2026-10-09'},
                                       {'cve':'CVE-2024-11111','epss':'0.56789','percentile':'0.98765','date':'2026-10-09'}]}).encode()
        if url.startswith(mod.GREYNOISE+'/'):
            return json.dumps({'ip':url.rsplit('/',1)[-1],'noise':True,'riot':False,'classification':'malicious','name':'Example scanner','last_seen':'2026-10-08','link':'https://viz.greynoise.io/ip/example'}).encode()
        if url.startswith(mod.VT+'/'):
            return json.dumps({'data':{'attributes':{'last_analysis_stats':{'malicious':2,'suspicious':1,'harmless':0,'undetected':71},'country':'ZZ'}}}).encode()
        if url==mod.THREATFOX:return json.dumps({'query_status':'ok','data':[{'ioc_type':'ip:port','ioc':'44.55.66.77:443','threat_type':'c2','malware_printable':'FakeLab'}]}).encode()
        if url==mod.BAZAAR:return json.dumps({'query_status':'ok','data':[{'sha256_hash':'a'*64,'first_seen':'2026-10-01'}]}).encode()
        raise AssertionError('unexpected endpoint '+url)

class CollectorTests(unittest.TestCase):
    def make_collector(self,**kw):
        t=FakeTransport()
        return mod.Collector(mod.HTTPClient(transport=t),limit=10,**kw),t
    def test_ip_validation(self):
        self.assertEqual(mod.parse_indicator('ip','11.22.33.44'),('ip','11.22.33.44'))
        self.assertIsNone(mod.parse_indicator('ip','10.0.0.1'))
        self.assertIsNone(mod.parse_indicator('ip','203.0.113.2'))
    def test_hash_validation(self):
        self.assertEqual(mod.parse_indicator('sha256','B'*64),('sha256','b'*64))
        self.assertIsNone(mod.parse_indicator('sha256','xyz'))
    def test_url_validation(self):
        self.assertIsNotNone(mod.parse_indicator('url','https://example.org/testing'))
        self.assertIsNone(mod.parse_indicator('url','file:///secret'))
        self.assertIsNone(mod.parse_indicator('url','http://name:pass@example.org/'))
    def test_ip_port_preserved(self):
        self.assertEqual(mod.parse_indicator('ip_port','11.22.33.44:443'),('ip_port','11.22.33.44:443'))
    def test_whitelist_https(self):
        c=mod.HTTPClient(transport=FakeTransport())
        for url in ['http://openphish.com/feed.txt','https://unexpected.test/','https://raw.githubusercontent.com/unknown/file']:
            with self.subTest(url=url),self.assertRaises(mod.SourceFailure):c.request(url)
    def test_et_sources(self):
        c,_=self.make_collector(gn_limit=0)
        c.start='test';c.collect_et(mod.ET_COMPROMISED,'Emerging Threats Compromised','test')
        self.assertEqual(len(c.records),2)
    def test_ipsum_threshold(self):
        c,_=self.make_collector(gn_limit=0)
        c.start='test';c.collect_ipsum()
        self.assertEqual(len(c.records),2)
        self.assertIn('occurrences=8',c.records[0]['context'])
    def test_cisa_recent_and_valid(self):
        c,_=self.make_collector(gn_limit=0)
        c.collect_cisa_kev()
        self.assertEqual([x['cve'] for x in c.vulnerabilities],['CVE-2022-22222','CVE-2024-11111'])
        self.assertEqual(len(c.records),0)
        c.collect_first_epss()
        self.assertEqual(c.vulnerabilities[0]['epss'],'0.12345000')
    def test_correlations_do_not_make_claims(self):
        c,_=self.make_collector(gn_limit=0)
        c.start='test';c.collect_feodo();c.collect_et(mod.ET_COMPROMISED,'Emerging Threats Compromised','test');c.collect_ipsum()
        matches=c.build_correlations()
        self.assertTrue(any(x['indicator']=='11.22.33.44' for x in matches))
        self.assertTrue(any(x['indicator']=='22.33.44.55' for x in matches))
    def test_greynoise_fields(self):
        c,_=self.make_collector(gn_limit=1)
        c.start='test';c.collect_feodo();c.greynoise_lookup()
        self.assertEqual(len(c.enrichment),1)
        self.assertEqual(c.enrichment[0]['source'],'GreyNoise')
        self.assertTrue(c.enrichment[0]['noise'])
    def test_optional_sources(self):
        c,t=self.make_collector(abuse_key='not-a-real-key',vt_key='not-a-real-key',vt_limit=1,gn_limit=0)
        # rate pacing only applies after first lookup
        data=c.execute()
        self.assertTrue(any(x['source']=='MalwareBazaar' for x in data['indicators']))
        self.assertTrue(any(x['source']=='ThreatFox' for x in data['indicators']))
        self.assertTrue(any(x['source']=='VirusTotal' for x in data['enrichment']))
    def test_end_to_end(self):
        c,_=self.make_collector(gn_limit=1)
        data=c.execute()
        self.assertEqual(data['run_mode'],'LIVE_FEEDS_ONLY')
        self.assertEqual(len(data['vulnerabilities']),2)
        self.assertEqual(data['vulnerabilities'][0]['epss'],'0.12345000')
        self.assertEqual(len(data['enrichment']),6) # five RIPEstat lookups and one GreyNoise lookup
        self.assertGreater(len(data['correlations']),0)
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)
            mod.export(out,data)
            for name in ('CTI_Report.docx','CTI_Findings.xlsx'):
                with ZipFile(out/name) as z:
                    self.assertIsNone(z.testzip())
                    for entry in z.namelist():
                        if entry.endswith(('.xml','.rels')):ET.fromstring(z.read(entry))
            for name in ('correlations.csv','vulnerabilities.csv','enrichment.csv','sources.csv','indicators.csv','analysis.json'):
                self.assertTrue((out/name).is_file(),name)
            with ZipFile(out/'CTI_Findings.xlsx') as z:
                self.assertIn('xl/worksheets/sheet5.xml',z.namelist())
            self.assertEqual(len(json.loads((out/'analysis.json').read_text())['vulnerabilities']),2)
    def test_no_fabricated_data(self):
        def failing(*args):raise mod.SourceFailure('network blocked')
        c=mod.Collector(mod.HTTPClient(transport=failing),limit=5,gn_limit=1)
        data=c.execute()
        self.assertEqual(data['indicators'],[])
        self.assertEqual(data['vulnerabilities'],[])
        self.assertTrue(all(x['status'] in ('error','skipped','no_data') for x in data['sources']))
    def test_et_block_cidr_not_discarded(self):
        c,_=self.make_collector(gn_limit=0)
        c.start='test';c.collect_et(mod.ET_BLOCK,'Emerging Threats Block','reported')
        self.assertTrue(any(r['type']=='cidr' and r['indicator']=='33.44.55.0/24' for r in c.records))
        self.assertFalse(any(r['type']=='ip' and r['indicator']=='33.44.55.0' for r in c.records))

    def test_spamhaus_cidr_no_expansion(self):
        c,_=self.make_collector(gn_limit=0)
        c.start='test';c.collect_spamhaus()
        self.assertEqual(len(c.records),1) # documentation-only 198.51.100.0/24 excluded
        self.assertEqual(c.records[0]['indicator'],'44.55.0.0/16')

    def test_all_ioc_types_supported(self):
        for kind,val in [('md5','a'*32),('sha1','b'*40),('sha256','c'*64),('sha512','d'*128),
                         ('domain','portal.example'),('domain_port','portal.example:443'),
                         ('url','https://portal.example/login'),('ip','44.55.66.77'),
                         ('cidr','44.55.66.0/24'),('ip_port','44.55.66.77:8443')]:
            with self.subTest(kind=kind):self.assertIsNotNone(mod.parse_indicator(kind,val))
        for kind,val in [('md5','abc'),('domain','-portal.example'),('url','ftp://portal.example'),
                         ('domain_port','foo.example:99999')]:
            with self.subTest(kind=kind):self.assertIsNone(mod.parse_indicator(kind,val))

    def test_domain_url_sources_and_contextual_relation(self):
        c,_=self.make_collector(gn_limit=0,ripe_limit=0)
        data=c.execute()
        self.assertTrue(any(r['type']=='domain' and r['indicator']=='fresh-one.example' for r in data['unique_indicators']))
        self.assertTrue(any(r['type']=='url' and r['indicator']=='https://fresh-one.example/a' for r in data['unique_indicators']))
        self.assertTrue(any(r['relation']=='url_host_matches_reported_domain' for r in data['relations']))
        first=next(r for r in data['unique_indicators'] if r['type']=='domain' and r['indicator']=='fresh-one.example')
        self.assertEqual(first['source_count'],2)
        self.assertEqual(first['direct_publisher_count'],1)
        self.assertNotEqual(first['correlation_level'],'multiple_nonaggregator_publishers')

    def test_network_relation_does_not_count_as_exact_sighting(self):
        c,_=self.make_collector(gn_limit=0,ripe_limit=0)
        data=c.execute()
        self.assertTrue(any(r['relation']=='ip_within_reported_cidr' for r in data['relations']))
        self.assertNotIn('ip_within_reported_cidr',{r.get('note','') for r in data['correlations']})

    def test_separate_output_sheets_and_files(self):
        c,_=self.make_collector(gn_limit=0,ripe_limit=0)
        data=c.execute()
        with tempfile.TemporaryDirectory() as d:
            path=Path(d);mod.export(path,data)
            with ZipFile(path/'CTI_Findings.xlsx') as z:
                sheet_names=z.namelist()
                self.assertIn('xl/worksheets/sheet18.xml',sheet_names)
                self.assertIsNone(z.testzip())
                for member in sheet_names:
                    if member.endswith('.xml'):ET.fromstring(z.read(member))
            self.assertTrue((path/'unique_indicators.csv').exists())
            self.assertTrue((path/'relations.csv').exists())
            self.assertTrue((path/'IOC_per_tipo'/'url.csv').exists())
            self.assertTrue((path/'IOC_per_tipo'/'domain.csv').exists())
            self.assertTrue((path/'IOC_per_tipo'/'sha256.csv').exists())

    def test_vt_multi_type_lookup_without_visiting_url(self):
        c,t=self.make_collector(vt_key='dummy',vt_limit=4,gn_limit=0,ripe_limit=0)
        c.start='2026-10-09T00:00:00+00:00'
        c.add('sha256','a'*64,'MalwareBazaar','sample')
        c.add('domain','portal.example','Phishunt','domain')
        c.add('url','https://portal.example/login','Phishing.Database URLs','url')
        c.add('ip','44.55.66.77','Feodo Tracker','botnet')
        from unittest.mock import patch
        with patch.object(mod.time, 'sleep', return_value=None):c.vt_lookup()
        self.assertEqual({x['type'] for x in c.enrichment},{'sha256','domain','url','ip'})
        self.assertTrue(all('virustotal.com' in x for x in t.calls))

    def test_openphish_explicit_opt_in(self):
        c,_=self.make_collector(gn_limit=0)
        d=c.execute()
        self.assertEqual(next(s for s in d['sources'] if s['source']=='OpenPhish')['status'],'skipped')
        c2,_=self.make_collector(gn_limit=0,openphish=True)
        d2=c2.execute()
        self.assertTrue(any(r['source']=='OpenPhish' for r in d2['indicators']))

    def test_ripestat_routing_only(self):
        c,_=self.make_collector(gn_limit=0,ripe_limit=2)
        c.start='test';c.collect_feodo();c.ripe_lookup()
        self.assertEqual(c.enrichment[0]['source'],'RIPEstat')
        self.assertEqual(c.enrichment[0]['asn'],'64501')
        self.assertNotIn('malicious',c.enrichment[0])

    def test_ip_enrichment_priority(self):
        c,_=self.make_collector(gn_limit=0)
        c.start='test';c.collect_feodo();c.collect_et(mod.ET_COMPROMISED,'Emerging Threats Compromised','reported')
        c.collect_ipsum()
        ordered=c.candidate_ips(3)
        self.assertEqual(ordered[0],'11.22.33.44')
        self.assertNotIn('10.0.0.1',ordered)

    def test_no_auto_phonehome_to_observed_url(self):
        c,t=self.make_collector(openphish=True,gn_limit=0)
        c.execute()
        self.assertTrue(all('phish.example' not in endpoint for endpoint in t.calls))

    def test_formula_injection_csv(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'csv.csv'
            mod.write_csv(p,['indicator'],[{'indicator':'=HYPERLINK(1)'}])
            self.assertIn("'=HYPERLINK(1)",p.read_text(encoding='utf-8-sig'))

if __name__=='__main__':unittest.main()
