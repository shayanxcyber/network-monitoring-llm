"""Explicit multi-source aggregates, using the existing supplied-reference contract."""
import hashlib
from pp_context import encoded, MAX_CONTEXT_BYTES
from pp_investigation_tools import json_tool
from pp_service_evidence import service_facts,compare_service

class CaseWorkspace:
    def __init__(self,base,case=None):
        self.base=base;self.case=case
        self.sources={s['review_id']:s for s in (case or {}).get('sources',[])}
        if case:
            self.base.context['case_scope']={'id':case['id'],'title':case['title'],
                'sources':[{k:v for k,v in s.items() if k!='evidence'} for s in case['sources']],
                'policy':'Only explicitly selected case sources. Primary p/l aliases remain the current source. Other sources are inspected through source-qualified aggregates. Prior model answers are not evidence. User labels are context, not diagnosis or authorisation.'}
            summaries=[self.record('case_source_summary',dict(review_id=s['review_id'],role=s['role'],**service_facts(s['evidence']))) for s in case['sources']]
            self.base.context['case_summaries']=[self.base._supply(s) for s in summaries]
            self.base._selection()
            if len(encoded(self.context))>MAX_CONTEXT_BYTES: raise ValueError('Selected case exceeds the context bound; select fewer sources.')

    def __getattr__(self,name):return getattr(self.base,name)
    @property
    def tools(self):
        return self.base.tools+[json_tool(self.inspect_service)]+([json_tool(self.compare_sources),json_tool(self.inspect_case_records)] if self.case else [])
    @property
    def tool_names(self):return self.base.tool_names|{'inspect_service'}|({'compare_sources','inspect_case_records'} if self.case else set())
    def record(self,kind,data):
        row=dict(kind=kind,**data);row['id']=self.digest+':a'+hashlib.sha256(encoded(row)).hexdigest()[:16]
        self.base._aggregate_alias(row['id']);self.base.aggregates[row['id']]=row
        return row
    def inspect_service(self,destination_port:int=0)->dict:
        """Calculate neutral TCP/visible HTTP/DNS facts in the primary saved source; zero means all ports."""
        return self.base._run('inspect_service',dict(destination_port=destination_port),lambda:([self.record('service_observations',service_facts(self.evidence,destination_port))],{}))
    def compare_sources(self,baseline_id:str,comparison_id:str,destination_port:int=0)->dict:
        """Compare two explicitly selected case review UUIDs. Differences are descriptive, not proof of cause or independent corroboration."""
        def operation():
            if baseline_id not in self.sources or comparison_id not in self.sources:raise ValueError('Not selected.')
            result=compare_service(self.sources[baseline_id]['evidence'],self.sources[comparison_id]['evidence'],destination_port)
            return [self.record('case_comparison',dict(baseline_review_id=baseline_id,comparison_review_id=comparison_id,**result))],{}
        return self.base._run('compare_sources',dict(baseline_id=baseline_id,comparison_id=comparison_id,destination_port=destination_port),operation)
    def inspect_case_records(self,review_id:str,numbers:list[int])->dict:
        """Inspect 1-8 original packet or physical-line numbers in an explicitly selected case source. Return exact source provenance through aggregate references."""
        def operation():
            if review_id not in self.sources or not isinstance(numbers,list) or not 1<=len(numbers)<=8 or len(set(numbers))!=len(numbers) or any(type(n)is not int for n in numbers):raise ValueError('Invalid selector.')
            evidence=self.sources[review_id]['evidence'];log=evidence.get('input_kind')=='network_log'
            rows={r['line_number' if log else 'packet']:r for r in evidence.get('log_records' if log else 'packets',[])}
            if not set(numbers)<=set(rows):raise ValueError('Unknown original record.')
            return [self.record('case_original_record',dict(review_id=review_id,source_sha256=evidence['capture']['sha256'],original=rows[n])) for n in numbers],{}
        return self.base._run('inspect_case_records',dict(review_id=review_id,numbers=numbers),operation)
