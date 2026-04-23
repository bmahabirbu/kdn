---
name: working-with-json-output-types
description: Guide to the JSON output types used by CLI commands, where they are defined, and how to find them
argument-hint: ""
---

# Working with JSON Output Types

All JSON output types for CLI commands are defined in the external module `github.com/openkaiden/kdn-api/cli/go`. This module is the single source of truth for every JSON shape that `kdn` commands emit.

## Where to Find the Module

The module is listed in `go.mod` — check there for the current version:

```bash
grep 'openkaiden/kdn-api/cli/go' go.mod
```

After downloading (run `make build` if you haven't yet), the source is in the Go module cache. Use the version from `go.mod` to build the path:

```bash
$(go env GOPATH)/pkg/mod/github.com/openkaiden/kdn-api/cli/go@<version>/
```

The only file that matters is `api.go` in that directory — it contains every type definition. Read it to see the exact JSON field names and which fields are optional (`omitempty`):

```bash
cat $(go env GOPATH)/pkg/mod/github.com/openkaiden/kdn-api/cli/go@$(grep 'openkaiden/kdn-api/cli/go' go.mod | awk '{print $2}')/api.go
```

