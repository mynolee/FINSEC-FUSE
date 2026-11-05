"""Independent finite synthetic catalog contracts; expected rows are not observations."""
import copy
import json
from pathlib import Path
import unittest
from evaluation.fixture_loader import register_fixture_set, load_fixture_set

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic-full60-v1.json"


def read_catalog():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class SyntheticFull60FixtureTests(unittest.TestCase):
    def test_identity_counts_and_no_measured_or_original_claim(self):
        data=read_catalog();cases=data['cases']
        self.assertEqual(data['fixtureSetId'],'synthetic-full60-v1')
        self.assertEqual(data['datasetLabel'],'NEW_SYNTHETIC_FULL60_V1')
        self.assertTrue(data['synthetic'])
        for key in ('originalFull60Recovered','measuredResultsIncluded','automaticallyRegistered'):
            self.assertIs(data[key],False)
        self.assertEqual(len(cases),60);self.assertEqual(len({c['caseId'] for c in cases}),60)
        self.assertEqual([c['caseId'] for c in cases],[f'synthetic-full60-c{i:03d}' for i in range(1,61)])
        self.assertEqual(sum(c['kind']=='ATTACK' for c in cases),18)
        self.assertEqual(sum(c['kind']=='NORMAL' for c in cases),42)
        self.assertTrue(all(set(c['expected'])=={'FUSE'} for c in cases))
    def test_twenty_profiles_have_three_genuine_status_inputs_not_repeat_padding(self):
        cases=read_catalog()['cases'];signatures=set()
        for n in range(1,21):
            group=[c for c in cases if c['profile']==f'P{n:02d}']
            self.assertEqual([c['status'] for c in group],['VERIFIED','NOT_VERIFIED','NEEDS_REVIEW'])
            for c in group:
                facts=c['seed']['evidence'];lookup={f['evidenceId']:i for i,f in enumerate(facts)}
                # Strip per-case identity noise; retain meaningful selection order,
                # kind/customer relationship/result/activity/time and proposal status.
                signature=(c['status'],tuple(lookup.get(x,'UNKNOWN') for x in c['selectedEvidenceIds']),
                    tuple((f['kind'],f['customerId']==c['customerId'],f['result'],f['active'],f['issuedAt'],f['expiresAt']) for f in facts))
                self.assertNotIn(signature,signatures);signatures.add(signature)
        self.assertEqual(len(signatures),60)
    def test_only_two_verified_order_controls_expect_review_and_all_other_cases_deny(self):
        cases=read_catalog()['cases']
        review={'synthetic-full60-c001','synthetic-full60-c004'}
        self.assertEqual({c['caseId'] for c in cases if c['expected']['FUSE']['state']=='WAIT_APPROVAL'},review)
        for c in cases:
            expected=c['expected']['FUSE']
            self.assertEqual(expected,{'state':'WAIT_APPROVAL','decision':'WAIT_APPROVAL','reasonCode':'HUMAN_APPROVAL_REQUIRED','forbiddenPaymentCount':0}
                if c['caseId'] in review else {'state':'BLOCKED','decision':'DENY','reasonCode':'KYC_EVIDENCE_REJECTED','forbiddenPaymentCount':0})
    def test_selection_cardinality_kind_foreign_and_unknown_boundaries_are_concrete(self):
        rows={c['profile']:c for c in read_catalog()['cases'] if c['status']=='VERIFIED'}
        self.assertEqual([len(rows[f'P{i:02d}']['selectedEvidenceIds']) for i in range(1,6)],[2,2,1,1,0])
        self.assertEqual([rows['P02']['seed']['evidence'].index(next(f for f in rows['P02']['seed']['evidence'] if f['evidenceId']==x)) for x in rows['P02']['selectedEvidenceIds']],[1,0])
        for profile,selected_foreign in [('P06',1),('P07',0)]:
            c=rows[profile];byid={f['evidenceId']:f for f in c['seed']['evidence']}
            self.assertNotEqual(byid[c['selectedEvidenceIds'][selected_foreign]]['customerId'],c['customerId'])
        for profile,unknown_index in [('P08',1),('P09',0)]:
            c=rows[profile];self.assertNotIn(c['selectedEvidenceIds'][unknown_index],{f['evidenceId'] for f in c['seed']['evidence']})
        self.assertEqual([f['kind'] for f in rows['P10']['seed']['evidence']],['ID_DOC','ID_DOC'])
        self.assertEqual([f['kind'] for f in rows['P11']['seed']['evidence']],['FACE_MATCH','FACE_MATCH'])
        self.assertEqual([f['kind'] for f in rows['P12']['seed']['evidence']],['ID_DOC','FACE_MATCH','ID_DOC'])
        self.assertEqual([f['kind'] for f in rows['P13']['seed']['evidence']],['ID_DOC','FACE_MATCH','FACE_MATCH'])
    def test_seven_fact_validity_boundaries_are_isolated_from_other_properties(self):
        rows={c['profile']:c for c in read_catalog()['cases'] if c['status']=='VERIFIED'}
        self.assertEqual(rows['P14']['seed']['evidence'][1]['result'],'FAIL')
        self.assertEqual(rows['P15']['seed']['evidence'][0]['result'],'FAIL')
        self.assertIs(rows['P16']['seed']['evidence'][0]['active'],False)
        self.assertIs(rows['P17']['seed']['evidence'][1]['active'],False)
        for profile,index in [('P18',0),('P19',1)]:
            c=rows[profile];self.assertGreater(c['seed']['evidence'][index]['issuedAt'],c['seed']['observationTime'])
        c=rows['P20'];self.assertEqual(c['seed']['evidence'][0]['expiresAt'],c['seed']['observationTime'])
        for c in rows.values():
            for f in c['seed']['evidence']:
                self.assertIn(f['result'],('PASS','FAIL'));self.assertIs(type(f['active']),bool)
    def test_each_case_owns_catalog_customer_and_reference_without_cross_case_fact_reuse(self):
        cases=read_catalog()['cases'];ids=[f['evidenceId'] for c in cases for f in c['seed']['evidence']]
        self.assertEqual(len(ids),len(set(ids)));self.assertEqual(len({c['customerId'] for c in cases}),60)
        self.assertEqual(len({c['seed']['application']['businessReference'] for c in cases}),60)
        for c in cases:
            self.assertIs(c['seed']['source']['reviewedSafe'],True)
            self.assertEqual(c['seed']['observationTime'],'2030-01-01T00:00:00Z')
            self.assertNotIn('observedOutcome',c);self.assertNotIn('caseOutputs',c)
    def test_existing_registry_copies_full_plan_and_refuses_conflicting_rebind(self):
        data=read_catalog();register_fixture_set('synthetic-full60-v1',data)
        data['cases'][0]['status']='NEEDS_REVIEW'
        loaded=load_fixture_set('synthetic-full60-v1')
        self.assertEqual(loaded['registeredPlannedCaseCount'],60)
        self.assertEqual(loaded['registeredSplitCaseCounts'],{'DEV':18,'TUNE':0,'FINAL':0,'NORMAL':42})
        self.assertEqual(loaded['cases'][0]['status'],'VERIFIED')
        with self.assertRaises(ValueError):register_fixture_set('synthetic-full60-v1',data)
        with self.assertRaises(ValueError):load_fixture_set('synthetic-full60-v1',['synthetic-full60-c001']*2)


if __name__=='__main__': unittest.main()
