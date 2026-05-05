---
name: Bug report
about: Report a defect in the container or its tooling.
title: '[BUG] '
labels: bug
assignees: ''
---

### Summary
<!-- One-line description of the bug. -->

### Steps to reproduce
1.
2.
3.

### Expected behaviour

### Actual behaviour
<!-- Paste the full error message and the relevant section of the audit log. -->

### Environment

```
docker version          : <run `docker version`>
docker compose version  : <run `docker compose version`>
host OS                 : Linux/macOS/Windows + version
forensics image version : <inside container: cat /opt/forensics/VERSION>
forensics-health output : <inside container: forensics-health quick-check>
```

### Reproducible from a fresh build?
- [ ] Yes — I ran `docker compose build --no-cache` before reproducing.
- [ ] No — uses an existing image.

### Additional context
<!-- Anything else useful: relevant module, recent changes, etc. -->
