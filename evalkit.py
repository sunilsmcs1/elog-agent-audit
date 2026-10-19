# -*- coding: utf-8 -*-
"""Evaluation helpers that work on ANY ELog instance (synthetic or real agent traces)."""
import copy, random, time, os
import elog
from elog import *

ATTACKS = ['edit', 'delete', 'reorder', 'insert', 'fork', 'truncate']

def attack_matrix(log, trials=100, seed=1):
    """Tamper-detection rates (%) for adversaries S (store) and K (store + signing key) at verifier levels V0/V1/V2.
    Returns dict like {'S|edit|anchored': [v0, v1, v2], ...}."""
    n = log.n
    pub0 = export_public(log); pk = log.pk; chain = log.chain
    N = len(pub0['events']); E_FULL = len(pub0['epochs']); ANCH = E_FULL * n
    assert E_FULL >= 4 and N - ANCH >= 2, 'need >=4 closed epochs and >=2 open events'
    rng = random.Random(seed)
    def rnd32(): return bytes(rng.getrandbits(8) for _ in range(32))
    def fresh(): return {'comms': [rnd32() for _ in range(NF)], 'R': b'', 'h': b''}
    def apply(attack, j, adv):
        a = copy.deepcopy(pub0); ev = a['events']; key = log.sk if adv == 'K' else None
        if attack == 'edit': ev[j]['comms'][rng.randrange(NF)] = rnd32()
        elif attack == 'delete': del ev[j]
        elif attack == 'reorder':
            if j + 1 >= len(ev): j -= 1
            ev[j], ev[j + 1] = ev[j + 1], ev[j]
        elif attack == 'insert': ev.insert(j, fresh())
        elif attack == 'fork':
            for q in range(j, len(ev)): ev[q] = fresh()
        elif attack == 'truncate':
            t = rng.randint(1, 3); cut = (E_FULL - t) * n
            del ev[cut:]; a['epochs'] = a['epochs'][:E_FULL - t]
            return a
        rebuild(a, n, key)
        return a
    out = {}
    for adv in ['S', 'K']:
        for attack in ATTACKS:
            for region in ['anchored', 'open']:
                if attack == 'truncate' and region == 'open': continue
                det = [0, 0, 0]
                for _ in range(trials):
                    j = rng.randrange(0, ANCH) if region == 'anchored' else rng.randrange(ANCH, N - 1)
                    a = apply(attack, j, adv)
                    for lv in (0, 1, 2):
                        if not verify_log(a, n, pk, lv, chain): det[lv] += 1
                out[f'{adv}|{attack}|{region}'] = [d / trials * 100 for d in det]
    det = [0, 0, 0]
    for _ in range(trials):
        a = copy.deepcopy(pub0); k = rng.randint(1, N - ANCH); del a['events'][-k:]
        for lv in (0, 1, 2):
            if not verify_log(a, n, pk, lv, chain): det[lv] += 1
    out['S|truncate|open'] = [d / trials * 100 for d in det]; out['K|truncate|open'] = out['S|truncate|open']
    nd = 0
    for _ in range(trials):
        a = copy.deepcopy(pub0); j = rng.randrange(0, N); a['events'][j]['comms'][0] = rnd32()
        if not verify_log(a, n, pk, 0, chain): nd += 1
    out['naive_edit_V0'] = nd / trials * 100
    out['_meta'] = {'trials': trials, 'N': N, 'n': n, 'anchored_events': ANCH, 'open_events': N - ANCH}
    return out

def forged_disclosures(log, attempts=2000, seed=21):
    rng = random.Random(seed); ANCH = len(log.epochs) * log.n
    acc = tot = 0
    for _ in range(attempts):
        i = rng.randrange(0, ANCH); f = rng.choice(FIELDS)
        p = log.disclose(i, f)
        muts = []
        q = dict(p); q['value'] = 'forged-%d' % rng.getrandbits(32); muts.append(q)
        q = dict(p); q['salt'] = os.urandom(16); muts.append(q)
        q = dict(p); q['field'] = FIELDS[(FIELDS.index(f) + 1) % NF]; muts.append(q)
        if p['field_path']:
            q = dict(p); fp = list(p['field_path']); fp[0] = os.urandom(32); q['field_path'] = fp; muts.append(q)
        q = dict(p); q['i'] = p['i'] + 1 if p['i'] + 1 < ANCH else p['i'] - 1; muts.append(q)
        for q in muts:
            tot += 1
            if verify_disclosure(q, log.pk, log.chain): acc += 1
    return {'attempts': tot, 'accepted': acc}

def erasure_eval(log, fractions=(0.0, 0.1, 0.5, 0.9, 1.0), seed=5, sample=300):
    """Erase random fractions of events (crypto-shredding) and re-audit. Modifies `log` (pass a fresh/copy)."""
    rng = random.Random(seed); N = len(log.h); ANCH = len(log.epochs) * log.n
    ids = list(range(N)); rng.shuffle(ids); erased = set(); rows = []
    for q in fractions:
        target = int(q * N)
        for i in ids[len(erased):target]:
            log.erase(i); erased.add(i)
        pub = export_public(log)
        t = time.perf_counter(); ok = verify_log(pub, log.n, log.pk, 2, log.chain); vt = time.perf_counter() - t
        kept = [i for i in range(ANCH) if i not in erased]
        samp = rng.sample(kept, min(sample, len(kept))) if kept else []
        okd = sum(verify_disclosure(log.disclose(i, rng.choice(FIELDS)), log.pk, log.chain) for i in samp)
        er = rng.sample(sorted(erased), min(sample, len(erased))) if erased else []
        blocked = 0
        for i in er:
            try: log.disclose(i, 'args')
            except (KeyError, ValueError): blocked += 1
        priv = sum(len(b) for b in log.blobs.values()) + 32 * len(log.keys)
        rows.append({'q': q, 'erased': len(erased), 'elog_audit_ok': ok, 'audit_s': vt, 'disclosure_ok': f'{okd}/{len(samp)}',
                     'erased_blocked': f'{blocked}/{len(er)}', 'private_MB': priv / 1e6})
    return rows

def forensic_demo(log, decision_prefix='result:deny'):
    """Auditor learns WHICH actions were blocked (tool + decision) without seeing arguments or results."""
    ANCH = len(log.epochs) * log.n; found = []; ok = 0; sizes = []
    for i in range(ANCH):
        if i in log.keys:
            ev = json.loads(ChaCha20Poly1305(hmac.new(log.keys[i], b'e', sha).digest()).decrypt(b'\x00' * 12, log.blobs[i], None))
            if str(ev['decision']).startswith(decision_prefix): found.append(i)
    for i in found:
        for f in ('tool', 'decision'):
            p = log.disclose(i, f); sizes.append(log.proof_size(p))
            ok += verify_disclosure(p, log.pk, log.chain)
    return {'blocked_events_found': len(found), 'disclosures_verified': ok, 'disclosures_total': 2 * len(found),
            'mean_proof_bytes': (sum(sizes) / len(sizes)) if sizes else 0}

import json, hmac
from elog import ChaCha20Poly1305, sha
