# Integrating an independent agent

`sentinel_sdk` is a small typed wrapper around the existing Rust gateway. It does not implement a second authorization engine, expose approval issuance to an agent, or execute denied operations. A trusted controller chooses the task template and starts `TrustedSession`; only its `tools.request(Proposal(...))` method is registered with a model dispatcher.

```python
from sentinel_sdk import Proposal, TrustedSession

with TrustedSession(injected=False) as session:
    result = session.tools.request(Proposal("read_file", "README.md"))
    print(result.decision, result.executed, result.event_id)
```

Run the independent deterministic example from a source checkout after `cargo build --locked`:

```sh
python -m examples.independent_agent
```

It demonstrates an authorized read/write, a denied sensitive-file request and an approval-required API request. No provider credentials or model downloads are needed. A developer can replace proposal generation with their model; every proposal must still be submitted separately. Treat result data/provenance as untrusted input. Never attach unrestricted shell, filesystem or network tools beside this dispatcher.

`TrustedSession` internally uses the existing trusted supervisor and signed contracts. It belongs to the trusted controller, not arbitrary model-generated Python. Python object privacy is not a sandbox: hostile Python code in the same process can introspect objects or invoke system APIs. This SDK is for model tool proposals under a trusted application, not secure execution of untrusted Python. Approvals and authenticated administration stay in the control plane; the SDK deliberately has no auto-approval method. Gateway failures raise `GatewayUnavailable` without fallback execution. Closing the session revokes its running gateway.

Core SDK imports have no additional dependencies. Build/install the platform Rust gateway first. Existing macOS/Linux/Windows capability limitations apply unchanged.

For a bundled installation, use `<installation>/sentinel example`. To import the SDK
from a separate trusted Python application, add the installation directory to
`PYTHONPATH` and set `SENTINEL_RUNTIME=<installation>/bin/sentinel-runtime` in that
application's trusted launch configuration. Do not let model output select the runtime
binary or task template. No Ollama/Qwen dependency is required.
