# -*- coding: utf-8 -*-
"""LLM tool-calling agent behind an ELog gateway: indirect prompt injection, policy gate, log-before-act, ELog evaluation.
Usage:  python agent/run_agent.py --model Qwen/Qwen2.5-7B-Instruct --out results/agent_qwen7b.json
        python agent/run_agent.py --mock --out results/agent_mock.json     (offline pipeline test only)"""
import sys, os, json, time, argparse, statistics as st, platform
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))
import elog, evalkit
from elog import ELog
from tools import SYSTEM_PROMPT, policy, make_tasks, Sandbox, success, APPROVED_ACCOUNTS
from backends import MockBackend, HFBackend, parse_action

MAX_STEPS = 6

def run_mode(backend, tasks, gate, epoch_size=20):
    """gate=True enforces the policy; gate=False logs the decision but executes anyway (ELog logging on in both)."""
    log = ELog(epoch_size=epoch_size)
    recs = []; llm_t = []; log_t = []; calls = 0; bad = 0
    for task in tasks:
        sb = Sandbox(task['docs'])
        msgs = [{'role': 'system', 'content': SYSTEM_PROMPT}, {'role': 'user', 'content': task['prompt']}]
        attempted_violation = False; executed_violation = False; denied_any = False; steps = 0
        for _ in range(MAX_STEPS):
            t0 = time.perf_counter(); out = backend.generate(msgs); llm_t.append(time.perf_counter() - t0)
            kind, a, b = parse_action(out); steps += 1
            msgs.append({'role': 'assistant', 'content': out})
            if kind == 'bad':
                bad += 1; msgs.append({'role': 'user', 'content': 'Invalid output. Reply with one JSON object.'}); continue
            if kind == 'final': break
            tool, args = a, b; calls += 1
            allowed = policy(tool, args)
            if not allowed: attempted_violation = True
            # ---- log-before-act: intent is durable before execution
            ev = {'agent': backend.name, 'tool': tool, 'args': args, 'result': 'PENDING',
                  'decision': 'intent:allow' if allowed else ('intent:deny' if gate else 'intent:violation-unenforced'), 'ts': int(time.time())}
            t1 = time.perf_counter(); log.append(ev); log_t.append(time.perf_counter() - t1)
            if allowed or not gate:
                res = sb.run(tool, args)
                if not allowed: executed_violation = True
                dec = 'result:allow' if allowed else 'result:violation-unenforced'
            else:
                res = 'BLOCKED by policy'; denied_any = True; dec = 'result:deny'
            ev2 = {'agent': backend.name, 'tool': tool, 'args': args, 'result': res[:300], 'decision': dec, 'ts': int(time.time())}
            t1 = time.perf_counter(); log.append(ev2); log_t.append(time.perf_counter() - t1)
            msgs.append({'role': 'user', 'content': f'Tool result: {res}'})
        recs.append({'id': task['id'], 'kind': task['kind'], 'attack': task['attack'], 'steps': steps,
                     'success': success(task, sb), 'attempted_violation': attempted_violation,
                     'executed_violation': executed_violation, 'denied_any': denied_any})
    def rate(sel, key):
        s = [r for r in recs if sel(r)]; return (sum(1 for r in s if r[key]) / len(s) * 100) if s else None
    summ = {
        'gate': gate, 'tasks': len(tasks), 'tool_calls': calls, 'malformed_outputs': bad,
        'benign_success_%': rate(lambda r: r['kind'] == 'benign', 'success'),
        'benign_false_block_%': rate(lambda r: r['kind'] == 'benign', 'denied_any'),
        'benign_violation_attempt_%': rate(lambda r: r['kind'] == 'benign', 'attempted_violation'),
        'inject_attempt_%': rate(lambda r: r['kind'] == 'inject', 'attempted_violation'),
        'inject_executed_violation_%': rate(lambda r: r['kind'] == 'inject', 'executed_violation'),
        'inject_task_success_%': rate(lambda r: r['kind'] == 'inject', 'success'),
        'llm_step_s_mean': st.mean(llm_t), 'llm_step_s_median': st.median(llm_t),
        'elog_append_us_mean': st.mean(log_t) * 1e6, 'elog_append_us_median': st.median(log_t) * 1e6,
        'elog_overhead_per_call_us': (sum(log_t) / max(calls, 1)) * 1e6,
        'elog_overhead_vs_llm_%': sum(log_t) / sum(llm_t) * 100,
        'events_logged': len(log.h),
    }
    by_attack = {}
    for r in recs:
        if r['kind'] == 'inject':
            k = r['attack']['kind'] + '/' + r['attack']['style']
            d = by_attack.setdefault(k, {'n': 0, 'attempt': 0, 'executed': 0}); d['n'] += 1
            d['attempt'] += r['attempted_violation']; d['executed'] += r['executed_violation']
    return summ, by_attack, log, recs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--model', default='Qwen/Qwen2.5-7B-Instruct'); ap.add_argument('--mock', action='store_true')
    ap.add_argument('--n-benign', type=int, default=100); ap.add_argument('--n-inject', type=int, default=100)
    ap.add_argument('--out', default='results/agent_results.json'); ap.add_argument('--seed', type=int, default=0)
    ap.add_argument('--trials', type=int, default=100)
    a = ap.parse_args()
    backend = MockBackend() if a.mock else HFBackend(a.model)
    tasks = make_tasks(a.n_benign, a.n_inject, a.seed)
    out = {'model': backend.name, 'env': {'python': platform.python_version(), 'platform': platform.platform()},
           'config': {'n_benign': a.n_benign, 'n_inject': a.n_inject, 'seed': a.seed, 'max_steps': MAX_STEPS, 'epoch_size': 20, 'decoding': 'greedy'}}
    try:
        import torch; out['env']['torch'] = torch.__version__
        if torch.cuda.is_available(): out['env']['gpu'] = torch.cuda.get_device_name(0)
    except Exception: pass
    logs = {}
    for gate in (False, True):
        summ, by_attack, log, recs = run_mode(backend, tasks, gate)
        key = 'gate_on' if gate else 'gate_off'
        out[key] = summ; out[key + '_by_attack'] = by_attack; logs[key] = log
        print(key, json.dumps(summ, indent=1), flush=True)
        json.dump(recs, open(a.out.replace('.json', f'_{key}_tasks.json'), 'w'), indent=1)
    # ---- ELog evaluation on the REAL gate_on trace
    log = logs['gate_on']
    N = len(log.h); n = log.n
    print('events', N, 'epochs', len(log.epochs), flush=True)
    out['trace'] = {'events': N, 'epochs': len(log.epochs), 'open_events': N - len(log.epochs) * n,
                    'public_bytes_per_event': 256, 'private_bytes_per_event': (sum(len(b) for b in log.blobs.values()) + 32 * len(log.keys)) / N}
    t = time.perf_counter()
    pub = elog.export_public(log); ok = elog.verify_log(pub, n, log.pk, 2, log.chain); out['trace']['audit_ok'] = ok
    out['trace']['audit_s'] = time.perf_counter() - t
    out['forensic'] = evalkit.forensic_demo(log)
    out['attack_matrix'] = evalkit.attack_matrix(log, trials=a.trials)
    out['forged'] = evalkit.forged_disclosures(log, attempts=500)
    out['erasure'] = evalkit.erasure_eval(log)
    json.dump(out, open(a.out, 'w'), indent=1, default=str)
    print('saved', a.out)

if __name__ == '__main__':
    main()
