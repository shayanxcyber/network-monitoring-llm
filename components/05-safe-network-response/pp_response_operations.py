"""Public capability catalogue and fixed argv templates, shared with the root broker.

Suggestion is not authority: the broker only dispatches validated operations here.
No shell text, model-generated script or caller-chosen executable is accepted.
"""
import shlex
import uuid

TARGET = '10.77.0.20'
DESTINATION = '10.77.0.10'
PORT = 8080
IP = '/usr/sbin/ip'
TC = '/usr/sbin/tc'
IPTABLES = '/usr/sbin/iptables'
NAMESPACE = 'pp-lab-service'
HANDLE = '7a00:'

CAPABILITIES = {
    'investigate': dict(title='Inspect more evidence', execution=False,
                        description='Inspect the selected capture or log; ask about unknown business intent.'),
    'no_action': dict(title='No network change', execution=False,
                      description='Explain why the evidence does not warrant changing the network.'),
    'block_source': dict(title='Temporary service block', execution=True,
                        description='Block one lab client from TCP/8080, leaving the control client reachable.'),
    'rate_limit_service': dict(title='Temporary service rate limit', execution=True,
                              description='Shape TCP/8080 replies to one lab client; measure transfer speed and restoration.'),
    'suggest_command': dict(title='Command or script example', execution=False,
                           description='Explained code to review, copy or download; never executed as model text.'),
    'capture_traffic': dict(title='Continuous collection', execution=False, unavailable=True,
                           description='Not implemented. Import a saved source or capture the fixed current lab instead.'),
    'change_external_network': dict(title='Other network changes', execution=False, unavailable=True,
                                  description='Not supported by this disconnected-lab broker. Provide authorised mapping outside this prototype.'),
}


def catalogue():
    return [dict(action=key, **value) for key, value in CAPABILITIES.items()]


def validate_parameters(operation, target, destination, port, duration_seconds, rate_kbit=None):
    if operation not in ('block_source', 'rate_limit_service'):
        raise ValueError('This capability has no implemented lab execution.')
    if target != TARGET or destination != DESTINATION or type(port) is not int or port != PORT:
        raise ValueError('Supported scope is lab client 10.77.0.20 to service 10.77.0.10 TCP/8080 only.')
    if type(duration_seconds) is not int or not 5 <= duration_seconds <= 120:
        raise ValueError('Choose an explicit duration between 5 and 120 seconds.')
    if operation == 'rate_limit_service':
        if type(rate_kbit) is not int or not 256 <= rate_kbit <= 2048:
            raise ValueError('Choose an explicit rate between 256 and 2048 kbit/s.')
    elif rate_kbit is not None:
        raise ValueError('A block has no rate parameter.')
    return dict(operation=operation, target=target, destination=destination, port=port,
                protocol='tcp', duration_seconds=duration_seconds, rate_kbit=rate_kbit)


def identifier(action_id):
    if type(action_id) is not str or str(uuid.UUID(action_id)) != action_id:
        raise ValueError('Invalid action identifier.')
    return action_id


def block_spec(action_id):
    identifier(action_id)
    return ['-s', TARGET+'/32', '-d', DESTINATION+'/32', '-p', 'tcp', '--dport', str(PORT),
            '-m', 'comment', '--comment', 'packetpilot:'+action_id, '-j', 'DROP']


def command_plan(parameters, action_id):
    identifier(action_id)
    p = validate_parameters(parameters['operation'], parameters['target'], parameters['destination'],
                            parameters['port'], parameters['duration_seconds'], parameters.get('rate_kbit'))
    prefix = [IP, 'netns', 'exec', NAMESPACE]
    if p['operation'] == 'block_source':
        apply = [prefix+[IPTABLES, '-w', '2', '-I', 'INPUT', '1', *block_spec(action_id)]]
        undo = [prefix+[IPTABLES, '-w', '2', '-D', 'INPUT', *block_spec(action_id)]]
        effect = 'The selected source cannot reach the service; the control client remains reachable.'
    else:
        apply = [
            prefix+[TC, 'qdisc', 'add', 'dev', 'eth0', 'root', 'handle', HANDLE, 'htb', 'default', '20'],
            prefix+[TC, 'class', 'add', 'dev', 'eth0', 'parent', HANDLE, 'classid', '7a00:10', 'htb',
                    'rate', str(p['rate_kbit'])+'kbit', 'ceil', str(p['rate_kbit'])+'kbit', 'burst', '4kb'],
            prefix+[TC, 'class', 'add', 'dev', 'eth0', 'parent', HANDLE, 'classid', '7a00:20', 'htb',
                    'rate', '10gbit', 'ceil', '10gbit'],
            prefix+[TC, 'filter', 'add', 'dev', 'eth0', 'parent', HANDLE, 'protocol', 'ip', 'pref', '10',
                    'flower', 'ip_proto', 'tcp', 'src_ip', DESTINATION, 'dst_ip', TARGET,
                    'src_port', str(PORT), 'classid', '7a00:10'],
        ]
        undo = [prefix+[TC, 'qdisc', 'del', 'dev', 'eth0', 'root', 'handle', HANDLE]]
        effect = 'Replies to the selected source are shaped; other lab replies use a separate high-capacity 10 Gbit/s default class. Verify the control transfer against its baseline, not just its reachability.'
    return dict(parameters=p, action_id=action_id, apply_argv=apply, reversal_argv=undo,
                commands=[shlex.join(a) for a in apply], reversal=[shlex.join(a) for a in undo],
                expected_effect=effect, implementation='Validated fixed template, not generated shell execution',
                expiry='The independent broker removes its exact change at expiry or recovery.')


def proposal_script(action):
    """Reviewable exact plan, deliberately not a second unmanaged execution path."""
    plan = action['command_plan']
    lines = ['# PacketPilot validated proposal '+action['id'],
             '# Review copy: the approved broker executes these argv operations, not this file.',
             '# No executable commands run when this review file is opened.',
             '# Apply (after separate exact proposal approval):']
    lines += ['# '+line for line in plan['commands']]
    lines += ['# Reversal (independent expiry or explicit rollback):']
    lines += ['# '+line for line in plan['reversal']]
    return '\n'.join(lines)+'\n'
