---
name: pr-commit-review-merge
description: Create a focused git/GitHub workflow for committing local changes to a feature branch, opening a pull request, reviewing the diff for risks and regressions, and merging to origin/master after checks pass. Use when the user asks to prepare a PR, perform code review, and merge changes end-to-end.
---

# PR Commit Review Merge

## Preconditions

- Confirm the workspace state with `git status --short`.
- Preserve unrelated local changes.
- Confirm the default base is `master` and remote is `origin`.
- Confirm required tools are available: `git`, `gh` (if PR creation is requested).

## Branch and Commit Workflow

1. Inspect current branch and remotes.
2. Create a new branch from latest `origin/master`.
3. Stage only files required for the requested change.
4. Write a scoped commit message in imperative mood.
5. Push the branch to `origin`.

## Pull Request Workflow

1. Summarize what changed and why.
2. Open a PR targeting `master`.
3. Include a test plan and risk notes.
4. Link related issues when provided.

## Review Workflow

1. Review the full diff with a bug-focused mindset.
2. Prioritize findings by severity: correctness, regressions, security, missing tests.
3. Document findings with file references and concise remediation.
4. Apply fixes on the same branch and push follow-up commits.

## Merge Workflow

1. Verify CI/checks are successful.
2. Rebase or merge `origin/master` into the branch when needed to resolve drift.
3. Merge PR to `master` using the requested strategy.
4. Confirm `origin/master` contains the merged commits.
5. Optionally delete the remote branch after merge.

## Output Contract

Return a concise execution summary with:

- Branch name
- Commit SHA(s)
- PR URL
- Review findings (or explicit no-findings statement)
- Merge commit SHA on `origin/master`

## Safety Rules

- Never use destructive git commands unless explicitly requested.
- Never include unrelated files in commits.
- Stop and ask before merge when checks fail or review finds unresolved high-severity issues.
