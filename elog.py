# -*- coding: utf-8 -*-
"""ELog: erasure-compatible, selectively disclosable, tamper-evident agent audit log.
Pure-Python reference prototype (hashlib, hmac, cryptography). No network access required."""
import hashlib, hmac, json, os, struct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature

FIELDS = ['agent', 'tool', 'args', 'result', 'decision', 'ts']
NF = len(FIELDS)
sha = hashlib.sha256

def H(*parts):
    return sha(b''.join(parts)).digest()

def canon(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

# ---------------- RFC 6962-style Merkle tree ----------------
def _split(n):
    k = 1
    while k * 2 < n: k *= 2
    return k

def mth_leaf(d): return H(b'\x00', d)

def mth(leaves):
    """leaves: list of leaf-hashes (already H(0x00||data))"""
    n = len(leaves)
    if n == 0: return sha(b'').digest()
    if n == 1: return leaves[0]
    k = _split(n)
    return H(b'\x01', mth(leaves[:k]), mth(leaves[k:]))

def audit_path(leaves, m):
    n = len(leaves)
    if n == 1: return []
    k = _split(n)
    if m < k: return audit_path(leaves[:k], m) + [mth(leaves[k:])]
    return audit_path(leaves[k:], m - k) + [mth(leaves[:k])]

def root_from_path(leaf, m, n, path):
    """verify an audit path; returns computed root or None if malformed"""
    def rec(leaf, m, n, path):
        if n == 1: return leaf if not path else None
        if not path: return None
        k = _split(n); sib = path[-1]; rest = path[:-1]
        if m < k:
            sub = rec(leaf, m, k, rest)
            return None if sub is None else H(b'\x01', sub, sib)
        sub = rec(leaf, m - k, n - k, rest)
        return None if sub is None else H(b'\x01', sib, sub)
    return rec(leaf, m, n, list(path))

# ---------------- simulated anchor chain ----------------
class Chain:
    """Append-only anchor ledger standing in for a smart contract (immutable once appended)."""
    def __init__(self): self.anchors = []
    def anchor(self, a): self.anchors.append(a)
    def length(self): return len(self.anchors)

# ---------------- ELog ----------------
HDR = struct.Struct('>QQQ')  # epoch, first_index, count

def make_header(e, first, cnt, M, hlast, prev_hdr_hash):
    return HDR.pack(e, first, cnt) + M + hlast + prev_hdr_hash  # 24 + 32*3 = 120 bytes

class ELog:
    def __init__(self, epoch_size=100, sign=True, commit=True, encrypt=True, chain=None, key=None):
        self.n = epoch_size; self.sign = sign; self.commit = commit; self.encrypt = encrypt
        self.chain = chain if chain is not None else Chain()
        self.sk = key or Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()
        # public part of the log
        self.R = []        # field-Merkle root per event
        self.comms = []    # field commitments per event
        self.h = []        # hash-chain value per event
        self.epochs = []   # dicts: hdr, sig
        # private part
        self.keys = {}     # i -> k_i  (key store, erasable)
        self.blobs = {}    # i -> ciphertext of canonical field map (erasable)
        self._prev_hdr_hash = b'\x00' * 32

    # --- append ---
    def append(self, ev):
        i = len(self.h)
        prev = self.h[-1] if i else b'\x00' * 32
        if self.commit:
            k = os.urandom(32)
            comms = []
            for fi, f in enumerate(FIELDS):
                salt = hmac.new(k, b's' + bytes([fi]), sha).digest()[:16]
                comms.append(H(b'\x10', f.encode(), salt, canon(ev[f])))
            R = mth([mth_leaf(c) for c in comms])
            self.comms.append(comms)
            if self.encrypt:
                ek = hmac.new(k, b'e', sha).digest()
                self.blobs[i] = ChaCha20Poly1305(ek).encrypt(b'\x00' * 12, canon(ev), None)
            self.keys[i] = k
        else:
            R = sha(canon(ev)).digest()  # plain hash-chain baseline (no per-field structure)
            self.comms.append(None)
            self.blobs[i] = canon(ev)
        self.R.append(R)
        hi = H(b'\x00', struct.pack('>Q', i), prev, R)
        self.h.append(hi)
        if (i + 1) % self.n == 0 and self.sign:
            self._close_epoch((i + 1) // self.n - 1)
        return i

    def _close_epoch(self, e):
        first = e * self.n
        hs = self.h[first:first + self.n]
        M = mth([mth_leaf(x) for x in hs])
        hdr = make_header(e, first, len(hs), M, hs[-1], self._prev_hdr_hash)
        sig = self.sk.sign(hdr)
        self.epochs.append({'hdr': hdr, 'sig': sig})
        self._prev_hdr_hash = H(hdr)
        self.chain.anchor(H(hdr))

    # --- selective disclosure ---
    def disclose(self, i, field):
        if i not in self.keys: raise KeyError('event %d erased' % i)
        k = self.keys[i]; fi = FIELDS.index(field)
        salt = hmac.new(k, b's' + bytes([fi]), sha).digest()[:16]
        ev = json.loads(ChaCha20Poly1305(hmac.new(k, b'e', sha).digest()).decrypt(b'\x00' * 12, self.blobs[i], None))
        leaves = [mth_leaf(c) for c in self.comms[i]]
        e = i // self.n
        if e >= len(self.epochs): raise ValueError('event in open epoch: not yet anchored')
        first = e * self.n
        hl = [mth_leaf(x) for x in self.h[first:first + self.n]]
        return {
            'i': i, 'field': field, 'value': ev[field], 'salt': salt,
            'field_path': audit_path(leaves, fi),
            'prev': self.h[i - 1] if i else b'\x00' * 32,
            'event_path': audit_path(hl, i - first),
            'hdr': self.epochs[e]['hdr'], 'sig': self.epochs[e]['sig'],
        }

    # --- erasure (crypto-shredding) ---
    def erase(self, i):
        self.keys.pop(i, None); self.blobs.pop(i, None)

    def proof_size(self, p):
        return (len(canon(p['value'])) + len(p['salt']) + 32 * len(p['field_path']) + 32 + 8
                + 32 * len(p['event_path']) + len(p['hdr']) + len(p['sig']))

def verify_disclosure(p, pk, chain=None):
    """Verifier knows pk and (optionally) the anchor ledger. Returns True/False."""
    try:
        fi = FIELDS.index(p['field'])
        c = H(b'\x10', p['field'].encode(), p['salt'], canon(p['value']))
        R = root_from_path(mth_leaf(c), fi, NF, p['field_path'])
        if R is None: return False
        hi = H(b'\x00', struct.pack('>Q', p['i']), p['prev'], R)
        e, first, cnt = HDR.unpack(p['hdr'][:24]); M = p['hdr'][24:56]
        if not (first <= p['i'] < first + cnt): return False
        root = root_from_path(mth_leaf(hi), p['i'] - first, cnt, p['event_path'])
        if root is None or root != M: return False
        pk.verify(p['sig'], p['hdr'])
        if chain is not None:
            if e >= chain.length() or chain.anchors[e] != H(p['hdr']): return False
        return True
    except (InvalidSignature, ValueError, KeyError, struct.error):
        return False

# ---------------- whole-log verification (auditor) ----------------
def rebuild(pub, n, key=None, from_event=0):
    """Attacker/ops helper: recompute hash chain, epoch roots and headers over pub['events'].
    key=None -> old signatures are kept (stale); key given -> headers re-signed."""
    ev = pub['events']
    for i in range(len(ev)):
        prev = ev[i - 1]['h'] if i else b'\x00' * 32
        ev[i]['R'] = mth([mth_leaf(c) for c in ev[i]['comms']])
        ev[i]['h'] = H(b'\x00', struct.pack('>Q', i), prev, ev[i]['R'])
    full = len(ev) // n
    old = pub['epochs']
    new = []; prev_hash = b'\x00' * 32
    for e in range(full):
        hs = [x['h'] for x in ev[e * n:(e + 1) * n]]
        M = mth([mth_leaf(x) for x in hs])
        hdr = make_header(e, e * n, n, M, hs[-1], prev_hash)
        sig = key.sign(hdr) if key is not None else (old[e]['sig'] if e < len(old) else b'\x00' * 64)
        new.append({'hdr': hdr, 'sig': sig}); prev_hash = H(hdr)
    pub['epochs'] = new

def export_public(log):
    return {'events': [{'comms': list(c), 'R': r, 'h': h} for c, r, h in zip(log.comms, log.R, log.h)],
            'epochs': [dict(e) for e in log.epochs]}

def verify_log(pub, n, pk, level, chain=None):
    """level 0: hash-chain consistency only; 1: + signed epoch headers; 2: + on-chain anchors.
    Returns True if the log passes (i.e. NO tampering detected)."""
    ev = pub['events']
    # V0: recompute chain and field roots
    prev = b'\x00' * 32
    for i, x in enumerate(ev):
        R = mth([mth_leaf(c) for c in x['comms']])
        if R != x['R']: return False
        h = H(b'\x00', struct.pack('>Q', i), prev, R)
        if h != x['h']: return False
        prev = h
    if level == 0: return True
    # V1: epoch headers
    prev_hash = b'\x00' * 32
    for e, E in enumerate(pub['epochs']):
        ee, first, cnt = HDR.unpack(E['hdr'][:24])
        if ee != e or first != e * n or first + cnt > len(ev): return False
        hs = [x['h'] for x in ev[first:first + cnt]]
        if mth([mth_leaf(x) for x in hs]) != E['hdr'][24:56]: return False
        if E['hdr'][56:88] != hs[-1]: return False
        if E['hdr'][88:120] != prev_hash: return False
        try: pk.verify(E['sig'], E['hdr'])
        except InvalidSignature: return False
        prev_hash = H(E['hdr'])
    if level == 1: return True
    # V2: anchors (count and content)
    if len(pub['epochs']) != chain.length(): return False
    for e, E in enumerate(pub['epochs']):
        if chain.anchors[e] != H(E['hdr']): return False
    return True
