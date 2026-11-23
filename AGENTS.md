# Project Guidelines: Sentinel AI

## Autonomous Commit & Push Workflow (One-by-One)
Whenever any task or feature is given:
1. Implement the requested task or feature.
2. Run and test the changes locally to verify zero errors.
3. Review staged files against all security rules (NO API keys, passwords, .env files, database credentials, or private tokens).
4. Create a clean, descriptive Git commit.
5. **Autonomously push immediately**: Push the commit directly to `origin main` (`https://github.com/nishandshettyofficial/sentinel-ai`) one by one WITHOUT asking for confirmation or waiting for permission.
6. Verify push success from git command output.
7. Report the milestone summary (task completed, files changed, tests performed, commit hash, and push confirmation).

## Security & Repository Protection
- Repository remote: `https://github.com/nishandshettyofficial/sentinel-ai`
- Never push to any other repository.
- Strictly ignore and never commit secrets, `.env`, tokens, or private credentials.
