# LurePermit gateway adapter example

Run the side-effect-free callable adapter from the repository root:

```bash
python examples/lurepermit/gateway_adapter.py
```

It prints the aggregate LureRange result and writes nothing. Replace
`policy_decision` with a translation to your policy engine, preserving the exact
four-field response contract. The adapter must make a decision only; it must not
execute a tool, request, credential operation, stop, or remediation.

See [`docs/LUREPERMIT_LURERANGE.md`](../../docs/LUREPERMIT_LURERANGE.md) for the
contract and claims boundary.
