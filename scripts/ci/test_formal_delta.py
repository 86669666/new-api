"""Offline policy boundaries for PR 262. No publication, private reads or execution."""
import copy
import time
import unittest
from unittest.mock import Mock, patch

import quality_results as policy


class DeltaPolicyTests(unittest.TestCase):
    def setUp(self):
        self.d = policy.delta
        self.pin = self.d.descriptor()
        self.sha = 'a'*40
        self.ref = self.d.make_reference(self.pin,self.sha,501,10000,'b'*32)
        self.reader = Mock()
        self.proof = {'receipt_sha256':'c'*64}

    def test_one_tree_and_pinned_resource_with_exact_window(self):
        for now in (10000,11800):
            self.d.validate_reference(self.ref,now)
        for now in (9999,11801,True):
            with self.assertRaises(ValueError):
                self.d.validate_reference(self.ref,now)
        for path, field, value in [('identity','candidate_sha',self.d.OLD_HEAD),('identity','candidate_tree',self.d.OLD_TREE),
                                   ('identity','release_expires_at',11801),('artifact','path','other.zip'),
                                   ('artifact','commit','f'*40),('identity','pull_number',258)]:
            changed = copy.deepcopy(self.ref)
            changed[path][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.d.validate_reference(changed,10000)
        with self.assertRaises(ValueError):
            self.d.validate_package(self.pin,b'truncated')
        with self.assertRaises(ValueError):
            self.d.verify(policy,self.ref,self.reader,lambda _:b'',None,10000)

    def test_distinct_approvals_and_exact_review_start(self):
        def stamp(epoch):
            return time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(epoch))

        runs, jobs, approvals = {},{},{}
        for run, role, start, finish in [(501,policy.CONSUMER_JOB,10000,10020),(502,policy.TERMINAL_JOB,10021,10040)]:
            title = ('Formal delta '+self.d.consumer_intent(self.pin,self.sha,self.ref['nonce']) if run==501 else
                     policy.terminal_run_title(self.ref,self.d.C1,501,self.d.HOSTED,self.d.ARCHIVE_SHA))
            runs[run] = dict(id=run,run_attempt=1,workflow_id=policy.FORMAL_WORKFLOW_ID,event='workflow_dispatch',
                             path=policy.consumer.evidence.WORKFLOW_PATH,head_branch=self.d.CONTROL_REF[11:],
                             head_sha=self.sha,repository=dict(id=self.d.REPO_ID,full_name=self.d.REPO),
                             head_repository=dict(id=self.d.REPO_ID),actor={'id':policy.consumer.evidence.TRIGGER_ID},
                             triggering_actor={'id':policy.consumer.evidence.TRIGGER_ID},display_title=title,
                             status='completed',conclusion='success',created_at=stamp(start),updated_at=stamp(finish))
            jobs[run] = [dict(name=role[2],head_sha=self.sha,status='completed',conclusion='success',
                              completed_at=stamp(finish),steps=[dict(name=role[3],status='completed',conclusion='success')])]
            approvals[run] = [dict(state='approved',user={'id':policy.REVIEWER_ID},environments=[dict(name=role[0],id=role[1])])]
        self.reader.latest_run.side_effect = runs.__getitem__
        self.reader.jobs.side_effect = lambda run,attempt: jobs[run]
        self.reader.approvals.side_effect = approvals.__getitem__

        def verify():
            return self.d.verify_approvals(policy,self.reader,self.ref,502,10045)
        self.assertEqual(10040,verify())
        for record, changed in [(runs[501],{'created_at':stamp(10001)}),(runs[501],{'display_title':'Formal delta unrelated'}),
                                (runs[502],{'created_at':stamp(10010)}),(runs[502],{'run_attempt':2}),
                                (approvals[501][0],{'user':{'id':1}}),(approvals[502][0],{'state':'rejected'})]:
            with self.subTest(change=changed), patch.dict(record,changed), self.assertRaises(ValueError):
                verify()

    def test_public_result_bound_to_baseline_and_new_subject(self):
        request = self.d.result(self.ref,502,self.proof)
        env = {'GITHUB_EVENT_NAME':'pull_request','GITHUB_RUN_ID':str(self.d.HOSTED['run_id'])}
        event = {'number':262,'pull_request':{'head':{'sha':self.d.HEAD}}}
        check = dict(id=2000,name=policy.PRIVATE_EVIDENCE_GATE,head_sha=self.d.HEAD,
                     app=dict(id=policy.consumer.APP,slug='new-api-box-formal'),status='completed',conclusion='success',
                     started_at='1970-01-01T02:47:30Z',completed_at='1970-01-01T02:47:31Z')
        self.reader.formal_quality_check.return_value=check
        def signed_readback(body):
            check.update(output={'text':self.d.canonical(body).decode()},external_id=policy.consumer.digest(body))
            return self.d.verify_public(policy,env,self.reader,clock=lambda:10060)
        with patch.object(policy,'ci_premerge_event',return_value=event), patch.object(policy,'validate_ci_evidence_reference'), \
             patch.object(policy,'resolve_ci_candidate'), patch.object(self.d,'current_subject'), \
             patch.object(self.d,'historical_baseline',return_value=self.proof), patch.object(self.d,'verify_approvals',return_value=10045):
            self.assertEqual(request,signed_readback(request))
            for delta in ({'scope':'new-nine-tier-execution'},{'baseline':{}},{'terminal_run':None},
                          {'candidate_tree':self.d.OLD_TREE},{'quality_sha256':'e'*64},{'hosted':policy.REUSE_HOSTED}):
                with self.subTest(delta=delta), self.assertRaises(ValueError):
                    signed_readback(dict(request,**delta))


if __name__ == '__main__':
    unittest.main()
