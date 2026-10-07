# Attack Path Core Engine

Python package for rebuilding observed attack paths, identifying root causes,
estimating reachability from an environment graph, and replaying mitigations.
It also traces evidence backward from an incident to rank likely origins while
allowing suspicious devices and accounts to be classified as intermediary victims.

## Install

From this directory, run `python -m pip install -e .`. The package requires
Python 3.11 or newer and NetworkX.

## Public API

```python
from attackpath import analyze, apply_remediation, verify, explain

result = analyze(events, environment)
updated_environment = apply_remediation(environment, result["remediations"][0])
verification = verify(result["attack_path"], environment, updated_environment)
summary = explain(result)
```

`events` is a list of event dictionaries. `environment` contains `nodes` and
`edges`; each edge uses `from`, `to`, and `permission`. Nodes may include
`sensitivity`, `tags`, `owner`, and `revoked`. `analyze` returns `correlation`,
`attack_path`, `root_cause`, `blast_radius`, `remediations`, and an
`attack_origin` dictionary. The origin result contains ranked
`candidate_origins`, a nullable `likely_origin`, evidence links, and limitations.
Candidates include a numeric confidence score and level, supporting and
counter-evidence, a backward event chain, and a reason. Victim evidence lowers
the score and marks the entity as `potential_victim` or
`suspected_compromised_device`. A likely origin describes telemetry evidence;
it does not identify or confirm a human attacker.
`apply_remediation` returns a deep copy and leaves the input environment
unchanged. `verify` replays environment edges and returns `PATH_BROKEN` or
`PATH_STILL_OPEN` with the first denied attack-path step.

The Nimbus checks use the team guide's chain (`tok-9f2` through `customers-db`)
and the stated expected breakpoints: token revocation at attack step 2 and
removal of `payments:admin` at step 6. The seven-step event fixture in
`tests/test_nimbus.py` is synthetic and self-contained because the scenario
JSON and contract examples were not present in this workspace. Confirm field
names against the team's shared contracts when those files are added.

## Development checks

Run `python -m pytest` from this directory.
