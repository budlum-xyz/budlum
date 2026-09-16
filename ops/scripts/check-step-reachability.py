#!/usr/bin/env python3
"""Read a workflow's step headers and say which steps can actually run.

CI here has learned the same lesson three times, from three different steps: a
job is a sequence, and a step that fails skips every later step that does not
carry `if: always()` - or an equivalent guard. `Format` did it, then `Clippy`
did it, then `Feature matrix` did it while `Format` and `Clippy` sat behind the
verdict they were supposed to protect. The fix each time was the same and is
written in `docs/CONTRIBUTING.md`: a red step must never stand between a reader
and another step's answer.

That fix is expressed in `if:` expressions, and expressions are the one part of
a workflow that cannot be checked here: the runner evaluates them and
`actionlint` is not installed on it (measured: `Repo Lint`'s annotation reads
`actionlint did not run: No such file or directory`). A typo in a step id inside
a guard fails *open* - `steps.nothere.outcome` is not `'success'`, so the step is
skipped, and a job with thirty skipped gates looks like a job with thirty green
ones. That is the gap this script closes.

Two hard findings, then a report:

* a `steps.<id>` reference whose `<id>` is not declared by any step in the same
  job - a guard that can never be true, so every step behind it is skipped;
* a guard that references an id declared *later* in the same job - GitHub
  evaluates steps in order, so the reference is null at evaluation time and the
  guarded step is silently skipped, which is the same failure wearing a smile.

`--fail JOB:STEP` answers the question a red run asks: if this step fails, which
steps still run? It evaluates the guards with the subset of the expression
language the workflows in this repository use (`always()`, `success()`,
`failure()`, `steps.<id>.outcome == '<x>'`, `!`, `&&`, `||`, parentheses), so a
surface behind `if: failure()` shows up as running only in a run that is red -
which is what a surface is for.

Step headers only are parsed - `id:`, `name:`, `if:`, `continue-on-error:` - at
the indentation Actions uses, so no YAML parser is needed and this runs on a
stock python3 anywhere. `run:` bodies are ignored on purpose: their content is
not what decides reachability.

Usage:
    python3 ops/scripts/check-step-reachability.py [workflow.yml ...]   # check
    python3 ops/scripts/check-step-reachability.py --self-test
    python3 ops/scripts/check-step-reachability.py --fail 'budlum:Test'
"""

import glob
import os
import re
import sys

STEP_START = re.compile(r"^      - ")
JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")


def jobs_of(text):
    """Map job id -> (start, end) line indices, using the file's own indentation."""
    keys = [(i, m.group(1)) for i, line in enumerate(text.split("\n"))
            for m in [JOB_KEY.match(line)] if m]
    out = {}
    for k, (i, name) in enumerate(keys):
        end = keys[k + 1][0] if k + 1 < len(keys) else len(text.split("\n"))
        out[name] = (i, end)
    return out


def steps_of(text, job):
    """Header fields of every step in `job`, in file order."""
    lines = text.split("\n")
    start, end = jobs_of(text)[job]
    idx = [i for i in range(start, end) if STEP_START.match(lines[i])]
    steps = []
    for k, s in enumerate(idx):
        e = idx[k + 1] if k + 1 < len(idx) else end
        # The first line carries the key too, as `- name: X`, so it is rewritten
        # to the same shape as the rest of the block before fields are read.
        block = ("      " + lines[s][len("      - "):] + "\n" + "\n".join(lines[s + 1:e]))

        def field(name):
            m = re.search(r"^\s*%s: (.*)$" % name, block, re.M)
            if not m:
                return None
            v = m.group(1).strip()
            # YAML accepts a wholly quoted scalar; a value that merely ends with
            # an apostrophe (an expression like `... == 'success'`) must survive.
            if len(v) > 1 and v[0] == v[-1] and v[0] in "'\"\"":
                v = v[1:-1].strip()
            return v
        step_id = field("id")
        steps.append({
            "at": s,
            "name": field("name") or field("uses") or "",
            "id": step_id or "",
            "if": field("if"),
            "raw": block,
        })
    return steps


def split_top(expr, op):
    """Split on `op` outside quotes and parentheses."""
    out, cur, depth, inq, i = [], "", 0, False, 0
    while i < len(expr):
        c = expr[i]
        if c == "'":
            inq = not inq
        if not inq and c == "(":
            depth += 1
        if not inq and c == ")":
            depth -= 1
        if not inq and depth == 0 and expr.startswith(op, i):
            out.append(cur)
            cur = ""
            i += len(op)
            continue
        cur += c
        i += 1
    out.append(cur)
    return [x for x in out if x.strip()]


def evaluate(expr, ids, failed):
    """Evaluate the guarded subset of the Actions expression language."""
    e = expr.strip()
    if e.startswith("!"):
        return not evaluate(e[1:], ids, failed)
    for op in ("||", "&&"):
        parts = split_top(e, op)
        if len(parts) > 1:
            vals = [evaluate(x, ids, failed) for x in parts]
            return all(vals) if op == "&&" else any(vals)
    if e.startswith("(") and e.endswith(")"):
        return evaluate(e[1:-1], ids, failed)
    m = re.fullmatch(r"steps\.([A-Za-z0-9_-]+)\.outcome\s*==\s*'(\w+)'", e)
    if m:
        return ids.get(m.group(1)) == m.group(2)
    if e in ("always()", "success()"):
        return True if e == "always()" else not failed
    if e in ("failure()", "cancelled()"):
        return failed if e == "failure()" else False
    raise ValueError("expression outside the supported subset: %r" % e)


def check(text, source="<workflow>"):
    """Hard findings: dangling and forward `steps.<id>` references."""
    findings = []
    for job in jobs_of(text):
        steps = steps_of(text, job)
        positions = {}
        for i, s in enumerate(steps):
            if s["id"]:
                positions[s["id"]] = i
        for i, s in enumerate(steps):
            if not s["if"]:
                continue
            for ref in re.findall(r"steps\.([A-Za-z0-9_-]+)\.", s["if"]):
                if ref not in positions:
                    findings.append(
                        "%s: job %r, step %r: guard references `steps.%s`, which no step "
                        "in this job declares - every step behind this guard is skipped"
                        % (source, job, s["name"] or s["raw"].split("\n")[0], ref)
                    )
                elif positions[ref] > i:
                    findings.append(
                        "%s: job %r, step %r: guard references `steps.%s`, declared later in "
                        "the same job - the reference is null at evaluation time, so the step "
                        "is skipped" % (source, job, s["name"], ref)
                    )
    return findings


def reachability(text, fail_job, fail_step):
    """Which steps run when `fail_step` in `fail_job` fails (and the rest succeed)."""
    rows = []
    ids, failed = {}, False
    for s in steps_of(text, fail_job):
        guard = s["if"]
        try:
            run = evaluate(guard, ids, failed) if guard else (not failed)
        except ValueError as exc:
            rows.append((s["name"], "UNKNOWN", str(exc)))
            continue
        outcome = "failure" if s["name"] == fail_step else "success"
        if s["id"]:
            ids[s["id"]] = outcome
        if outcome == "failure":
            failed = True
        rows.append((s["name"], "run" if run else "SKIP", outcome))
    return rows


SELF_TEST_YAML = """name: fixture
on: push
jobs:
  ok:
    runs-on: ubuntu-latest
    steps:
      - id: rust
        uses: dtolnay/rust-toolchain@x
      - name: Verdict
        run: cargo test
      - name: Guarded and reachable
        if: always() && steps.rust.outcome == 'success'
        run: cargo fmt --check
  dangling:
    runs-on: ubuntu-latest
    steps:
      - name: Guarded on nothing
        if: always() && steps.nothere.outcome == 'success'
        run: echo unreachable
  forward:
    runs-on: ubuntu-latest
    steps:
      - name: Runs before its guard's id exists
        if: always() && steps.later.outcome == 'success'
        run: echo skipped
      - id: later
        run: echo hi
  masked:
    runs-on: ubuntu-latest
    steps:
      - id: first
        name: First
        run: exit 1
      - name: Unguarded later verdict
        run: cargo test
      - name: Guarded later verdict
        if: always() && steps.first.outcome == 'success'
        run: echo skipped-too
"""


def self_test():
    """The checker must catch both silent-skip shapes and agree with the runner."""
    def expect(cond, what):
        if not cond:
            print("FAIL [step-reachability-self-test]: %s" % what)
            return 1
        return 0

    rc = 0
    text = SELF_TEST_YAML
    f = check(text, "fixture")
    joined = "\n".join(f)
    rc |= expect(len(f) == 2, "expected exactly 2 findings, got %d:\n%s" % (len(f), joined))
    rc |= expect("nothere" in joined, "the dangling reference was not reported")
    rc |= expect("declared later" in joined, "the forward reference was not reported")
    rows = reachability(text, "masked", "First")
    skipped = [n for n, r, _ in rows if r == "SKIP"]
    rc |= expect(skipped == ["Unguarded later verdict", "Guarded later verdict"],
                 "a red first step must skip the unguarded step; got %r" % (skipped,))
    rows = reachability(text, "ok", "Verdict")
    ran = [n for n, r, _ in rows if r == "run"]
    rc |= expect("Guarded and reachable" in ran,
                 "a guard on a successful toolchain step must run even when an earlier "
                 "step is red; ran=%r" % (ran,))
    try:
        evaluate("hash()", {}, False)
        rc |= expect(False, "an unsupported expression was accepted silently")
    except ValueError:
        pass
    real = sorted(glob.glob(os.path.join(".github", "workflows", "*.yml")))
    if real:
        n = sum(len(check(open(w).read(), w)) for w in real)
        rc |= expect(n == 0, "%d dangling/forward reference(s) in this repository" % n)
    print("ok: step-reachability self-test (2 findings, 4 guard behaviours, %d real workflows)"
          % len(real))
    return rc


def main(argv):
    args = argv[1:]
    if "--self-test" in args:
        return self_test()
    fail = None
    kept = []
    it = iter(args)
    for a in it:
        if a.startswith("--fail="):
            fail = a.split("=", 1)[1]
        elif a == "--fail":
            fail = next(it, None)
        else:
            kept.append(a)
    args = kept
    files = args or sorted(glob.glob(os.path.join(".github", "workflows", "*.yml")))
    if not files:
        print("FAIL [step-reachability]: no workflow files found; a check that scans "
              "nothing passes nothing")
        return 1
    if fail:
        if ":" not in fail:
            print("usage: --fail JOB:STEP-NAME", file=sys.stderr)
            return 2
        job, step = fail.split(":", 1)
        text = "".join(open(w).read() for w in files if _has_job(w, job))
        for name, verdict, outcome in reachability(text, job, step):
            print("%-4s %-9s %s" % (verdict, outcome, name))
        return 0
    findings = []
    for w in files:
        findings += check(open(w).read(), w)
    if findings:
        for x in findings:
            print("FAIL [step-reachability]: %s" % x)
        print("%d finding(s) in %d workflow(s)" % (len(findings), len(files)))
        return 1
    print("ok: every steps.<id> guard resolves to an id declared earlier in its job "
          "(%d workflows)" % len(files))
    return 0


def _has_job(path, job):
    try:
        return job in jobs_of(open(path).read())
    except Exception:
        return False


if __name__ == "__main__":
    sys.exit(main(sys.argv))
