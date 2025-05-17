# AGENT Instructions

## Scope

These guidelines apply to the entire repository.

## Code Style

- Go is the primary language. Format Go code with `gofmt` and `gofumpt` before committing.
- Use `golangci-lint run` to check for lint issues. Run with `--fix` when possible.
- Format Markdown, JSON, and YAML files with Prettier.
  Use `npx prettier --write .` to fix formatting and `npx prettier --check .` to verify before committing.

## Testing

- Run `go test ./...` to ensure all tests pass.
- `go build ./...` can be used to confirm code builds successfully.

## Pull Requests

- Summaries should briefly describe the change and include citations to modified lines.
- Mention the result of running tests and lint commands in a separate testing section.
