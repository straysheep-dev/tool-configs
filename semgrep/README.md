# semgrep

Validate rule syntax:

```bash
semgrep validate ~/src/tool-configs/semgrep/
```

Run custom rules along with all of the default security rules:

```bash
semgrep scan --config p/default --config ./custom.yaml ~/src/project/
```