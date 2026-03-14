# Agent Instructions

This project uses **nd** for issue tracking. Run `nd prime` to get started. Historical
`bd`/beads references are archival only.

## Quick Reference

```bash
nd ready              # Find available work
nd show <id>          # View issue details
nd update <id> --status=in_progress  # Claim work
nd update <id> --append-notes "<block>"  # Append nd_contract / evidence
nd labels add <id> delivered            # Mark developer delivery
nd close <id>         # Complete work when acting as pm_acceptor
nd list --parent <epic-id>           # Inspect related work
```

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Update the story's `nd_contract`, append evidence/proof, and mark delivered when ready for PM acceptance
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
- `nd` is the active tracker; any beads-era references should be treated as historical compatibility only
