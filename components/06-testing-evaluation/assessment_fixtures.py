"""Protocol-stub responses, never presented as live inference."""
def stub_answer(context):
    reference = context['overview']['id']
    counts = context['coverage']
    partial = ((counts['decoded_records'] != counts['total_records'] if 'total_records' in counts
                else counts['decoded_packets'] != context['capture']['packet_count'])
               or not context['context_selection']['all_detail_included'])
    return {
        'schema_version': '2.0', 'capture_sha256': context['capture']['sha256'],
        'assessment': 'inconclusive', 'summary': 'Review the observed traffic and its context.',
        'observations': [{'text': 'Packets were observed in this capture.', 'references': [reference]}],
        'interpretation': 'The purpose cannot be established from headers alone.',
        'alternatives': ['An authorised diagnostic may explain these observations.'],
        'uncertainty': ['Authorisation and business impact are not established.'],
        'coverage': {'status': 'partial' if partial else 'complete_supported', 'limitations': ['No application content or authorisation is established.']},
        'measurements': [],
        'recommendations': [{'action': 'investigate', 'target': None, 'duration_seconds': None,
                             'rationale': 'Check the activity with the operator.', 'references': [reference]}],
        'questions': ['Was this activity authorised?'],
    }
