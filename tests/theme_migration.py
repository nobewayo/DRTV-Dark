"""Controlled source changes exercise conservative matching without inventing a version."""
import copy
import json
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from theme_maintenance import compare, read_apk, sites
from product_common import ROOT


class Migration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original=Path(sys.argv[1]) if len(sys.argv)>1 and not sys.argv[1].startswith('-') else ROOT/'original/base.apk'
        cls.source=read_apk(original)
        cls.owner='res/layout/fragment_sports_detail.xml'

    def test_all_121_unchanged(self):
        report=compare(self.source,self.source)
        self.assertEqual(report['counts'],{'unchanged':121})
        self.assertFalse(report['admissionGranted'])

    def test_unique_relocation_is_only_candidate(self):
        candidate=self.source.copy();candidate['res/layout/relocated.xml']=candidate.pop(self.owner)
        report=compare(self.source,candidate)
        self.assertTrue(any(s['status']=='relocated-candidate' for s in report['sites']))
        self.assertFalse(report['automaticMigration'])

    def test_duplicate_relocation_is_ambiguous(self):
        candidate=self.source.copy();content=candidate.pop(self.owner)
        for name in ('one','two'):candidate['res/layout/'+name+'.xml']=content
        self.assertTrue(any(s['status']=='modified-or-ambiguous' for s in compare(self.source,candidate)['sites']))

    def test_missing(self):
        candidate=self.source.copy();candidate.pop(self.owner)
        self.assertTrue(any(s['status']=='missing' for s in compare(self.source,candidate)['sites']))

    def test_same_path_and_color_do_not_accept_changed_context(self):
        candidate=self.source.copy();content=bytearray(candidate[self.owner]);content[-1]^=1;candidate[self.owner]=bytes(content)
        result=compare(self.source,candidate)
        self.assertTrue(all(s['status']=='modified-or-ambiguous' for s in result['sites'] if s['file']==self.owner))

    def test_bright_structure_and_artwork(self):
        from resources import xml_values
        candidate=self.source.copy();content=bytearray(candidate[self.owner])
        row=next(v for v in xml_values(content) if v['attribute']==0x10100d4)
        struct.pack_into('<HBBI',content,row['offset'],8,0,28,0xffeeeeee)
        candidate['res/layout/fixture_new.xml']=bytes(content)
        candidate['res/drawable/fixture_artwork.png']=b'fixture content, never recolor'
        result=compare(self.source,candidate)
        self.assertTrue(any(v['file']=='res/layout/fixture_new.xml' for v in result['potentialBrightStructure']))
        self.assertEqual(result['contentOrArtworkDoNotRecolor'],['res/drawable/fixture_artwork.png'])

    def test_wrong_previous_owner_rejected(self):
        previous=self.source.copy();previous[self.owner]=b'wrong'
        with self.assertRaises(AssertionError):compare(previous,self.source)


if __name__=='__main__':
    # Consume the optional APK path before unittest processes arguments.
    Migration.setUpClass();Migration.setUpClass=classmethod(lambda cls:None)
    unittest.main(argv=[sys.argv[0]],verbosity=2)
