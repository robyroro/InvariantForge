# Demo: protect a subprocess boundary

Copy this directory to a fresh working directory and initialize Git there.
The source starts with a subprocess call that passes an argument array.

```sh
git init
git add .
git commit -m "baseline"
invariantforge init
invariantforge discover --provider static
invariantforge show INV-001
invariantforge approve INV-001
invariantforge generate
invariantforge check
```

Now edit `app.py` so its subprocess call passes a string and `shell=True`:

```python
subprocess.run(message, shell=True, check=True)
```

The demo does not ask you to run that changed application code. Run:

```sh
invariantforge diff
invariantforge check
```

BoundaryDiff should identify a subprocess change and map it to `INV-001`.
`check` should fail at the call. Restore the argument-array call and run
`invariantforge check` and `invariantforge prove`. The evidence bundle records
the revision and dirty state. Commit the fixed source first for reproducible
evidence.
