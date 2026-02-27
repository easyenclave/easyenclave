CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_github_login_unique
ON accounts(github_login COLLATE NOCASE)
WHERE github_login IS NOT NULL AND github_login <> '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_github_org_unique
ON accounts(github_org COLLATE NOCASE)
WHERE github_org IS NOT NULL AND github_org <> '';
