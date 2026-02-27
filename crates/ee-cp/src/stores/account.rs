use ee_common::error::{AppError, AppResult};
use ee_common::types::AccountType;
use serde::Serialize;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AccountRecord {
    pub account_id: Uuid,
    pub name: String,
    pub account_type: AccountType,
    pub github_login: Option<String>,
    pub github_org: Option<String>,
}

#[derive(Clone)]
pub struct AccountStore {
    pool: SqlitePool,
}

impl AccountStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, name: &str, account_type: AccountType) -> AppResult<AccountRecord> {
        self.create_with_api_key(name, account_type, None, None, None, None)
            .await
    }

    pub async fn create_with_api_key(
        &self,
        name: &str,
        account_type: AccountType,
        api_key_hash: Option<&str>,
        api_key_prefix: Option<&str>,
        github_login: Option<&str>,
        github_org: Option<&str>,
    ) -> AppResult<AccountRecord> {
        let account_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO accounts (account_id, name, account_type, api_key_hash, api_key_prefix, github_login, github_org) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
            .bind(account_id.to_string())
            .bind(name)
            .bind(account_type_to_db(account_type))
            .bind(api_key_hash)
            .bind(api_key_prefix)
            .bind(github_login)
            .bind(github_org)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::External(format!("failed to create account: {e}")))?;

        self.get(account_id).await?.ok_or(AppError::NotFound)
    }

    pub async fn get(&self, account_id: Uuid) -> AppResult<Option<AccountRecord>> {
        let row = sqlx::query(
            "SELECT account_id, name, account_type, github_login, github_org FROM accounts WHERE account_id = ?1",
        )
        .bind(account_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to fetch account: {e}")))?;

        row.map(row_to_account).transpose()
    }

    pub async fn list(&self) -> AppResult<Vec<AccountRecord>> {
        let rows = sqlx::query(
            "SELECT account_id, name, account_type, github_login, github_org FROM accounts ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to list accounts: {e}")))?;

        rows.into_iter().map(row_to_account).collect()
    }

    pub async fn balance_cents(&self, account_id: Uuid) -> AppResult<i64> {
        let row = sqlx::query(
            "SELECT COALESCE(SUM(amount_cents), 0) AS balance_cents FROM transactions WHERE account_id = ?1",
        )
        .bind(account_id.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::External(format!("failed to compute account balance: {e}")))?;

        row.try_get::<i64, _>("balance_cents")
            .map_err(|e| AppError::External(format!("failed to read balance_cents: {e}")))
    }

    pub async fn lookup_api_hash_by_prefix(&self, key_prefix: &str) -> AppResult<Option<String>> {
        let row = sqlx::query("SELECT api_key_hash FROM accounts WHERE api_key_prefix = ?1")
            .bind(key_prefix)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::External(format!("failed to lookup api hash: {e}")))?;

        row.map(|r| {
            r.try_get::<Option<String>, _>("api_key_hash")
                .map_err(|e| AppError::External(format!("read api_key_hash failed: {e}")))
        })
        .transpose()
        .map(Option::flatten)
    }

    pub async fn api_hash_for_account(&self, account_id: Uuid) -> AppResult<Option<String>> {
        let row = sqlx::query("SELECT api_key_hash FROM accounts WHERE account_id = ?1")
            .bind(account_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::External(format!("failed to lookup account api hash: {e}")))?;

        row.map(|r| {
            r.try_get::<Option<String>, _>("api_key_hash")
                .map_err(|e| AppError::External(format!("read api_key_hash failed: {e}")))
        })
        .transpose()
        .map(Option::flatten)
    }

    pub async fn lookup_account_auth_by_prefix(
        &self,
        key_prefix: &str,
    ) -> AppResult<Option<(Uuid, String)>> {
        let row =
            sqlx::query("SELECT account_id, api_key_hash FROM accounts WHERE api_key_prefix = ?1")
                .bind(key_prefix)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    AppError::External(format!("failed to lookup account auth by prefix: {e}"))
                })?;

        row.map(|r| {
            let account_id: String = r
                .try_get("account_id")
                .map_err(|e| AppError::External(format!("read account_id failed: {e}")))?;
            let api_key_hash: Option<String> = r
                .try_get("api_key_hash")
                .map_err(|e| AppError::External(format!("read api_key_hash failed: {e}")))?;
            let parsed = Uuid::parse_str(&account_id)
                .map_err(|e| AppError::External(format!("invalid account_id uuid: {e}")))?;
            Ok(api_key_hash.map(|hash| (parsed, hash)))
        })
        .transpose()
        .map(Option::flatten)
    }

    pub async fn lookup_account_id_by_github_owner(&self, owner: &str) -> AppResult<Option<Uuid>> {
        let owner = owner.to_ascii_lowercase();
        let row = sqlx::query(
            "SELECT account_id
             FROM accounts
             WHERE lower(github_login) = ?1 OR lower(github_org) = ?1
             ORDER BY created_at ASC
             LIMIT 1",
        )
        .bind(owner)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            AppError::External(format!("failed to lookup account by github owner: {e}"))
        })?;

        row.map(|r| {
            let account_id: String = r
                .try_get("account_id")
                .map_err(|e| AppError::External(format!("read account_id failed: {e}")))?;
            Uuid::parse_str(&account_id)
                .map_err(|e| AppError::External(format!("invalid account_id uuid: {e}")))
        })
        .transpose()
    }
}

fn row_to_account(row: sqlx::sqlite::SqliteRow) -> AppResult<AccountRecord> {
    let account_id: String = row
        .try_get("account_id")
        .map_err(|e| AppError::External(format!("read account_id failed: {e}")))?;
    let name: String = row
        .try_get("name")
        .map_err(|e| AppError::External(format!("read name failed: {e}")))?;
    let account_type: String = row
        .try_get("account_type")
        .map_err(|e| AppError::External(format!("read account_type failed: {e}")))?;
    let github_login: Option<String> = row
        .try_get("github_login")
        .map_err(|e| AppError::External(format!("read github_login failed: {e}")))?;
    let github_org: Option<String> = row
        .try_get("github_org")
        .map_err(|e| AppError::External(format!("read github_org failed: {e}")))?;

    Ok(AccountRecord {
        account_id: Uuid::parse_str(&account_id)
            .map_err(|e| AppError::External(format!("invalid account_id uuid: {e}")))?,
        name,
        account_type: account_type_from_db(&account_type)?,
        github_login,
        github_org,
    })
}

fn account_type_to_db(account_type: AccountType) -> &'static str {
    match account_type {
        AccountType::Deployer => "deployer",
        AccountType::Agent => "agent",
        AccountType::Contributor => "contributor",
        AccountType::Launcher => "launcher",
        AccountType::Platform => "platform",
    }
}

fn account_type_from_db(raw: &str) -> AppResult<AccountType> {
    match raw {
        "deployer" => Ok(AccountType::Deployer),
        "agent" => Ok(AccountType::Agent),
        "contributor" => Ok(AccountType::Contributor),
        "launcher" => Ok(AccountType::Launcher),
        "platform" => Ok(AccountType::Platform),
        _ => Err(AppError::External(format!("invalid account type: {raw}"))),
    }
}

#[cfg(test)]
mod tests {
    use ee_common::types::AccountType;
    use sqlx::sqlite::SqlitePoolOptions;

    use super::AccountStore;

    #[tokio::test]
    async fn account_balance_from_transactions() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrate");

        let store = AccountStore::new(pool.clone());
        let account = store
            .create("alice", AccountType::Deployer)
            .await
            .expect("create");

        sqlx::query(
            "INSERT INTO transactions (transaction_id, account_id, amount_cents, balance_after_cents, tx_type) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(account.account_id.to_string())
        .bind(10_000_i64)
        .bind(10_000_i64)
        .bind("deposit")
        .execute(&pool)
        .await
        .expect("insert deposit");

        sqlx::query(
            "INSERT INTO transactions (transaction_id, account_id, amount_cents, balance_after_cents, tx_type) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(account.account_id.to_string())
        .bind(-2_500_i64)
        .bind(7_500_i64)
        .bind("charge")
        .execute(&pool)
        .await
        .expect("insert charge");

        let balance = store
            .balance_cents(account.account_id)
            .await
            .expect("balance");
        assert_eq!(balance, 7_500);
    }

    #[tokio::test]
    async fn create_with_api_key_stores_hash_prefix() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrate");

        let store = AccountStore::new(pool);
        let prefix = "ee_live_abcd";
        let hash = "$argon2id$v=19$m=19456,t=2,p=1$abc$def";

        let _account = store
            .create_with_api_key(
                "bob",
                AccountType::Deployer,
                Some(hash),
                Some(prefix),
                Some("bob"),
                Some("easyenclave"),
            )
            .await
            .expect("create");

        let found = store
            .lookup_api_hash_by_prefix(prefix)
            .await
            .expect("lookup");
        assert_eq!(found.as_deref(), Some(hash));

        let auth = store
            .lookup_account_auth_by_prefix(prefix)
            .await
            .expect("auth lookup")
            .expect("auth record");
        assert_eq!(auth.1, hash);
    }

    #[tokio::test]
    async fn lookup_account_by_github_owner_matches_login_or_org() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrate");

        let store = AccountStore::new(pool);
        let account = store
            .create_with_api_key(
                "carol",
                AccountType::Deployer,
                None,
                None,
                Some("carol"),
                Some("example-org"),
            )
            .await
            .expect("create");

        let by_login = store
            .lookup_account_id_by_github_owner("CAROL")
            .await
            .expect("lookup login");
        assert_eq!(by_login, Some(account.account_id));

        let by_org = store
            .lookup_account_id_by_github_owner("example-org")
            .await
            .expect("lookup org");
        assert_eq!(by_org, Some(account.account_id));
    }

    #[tokio::test]
    async fn github_owner_mapping_is_unique_case_insensitive() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrate");

        let store = AccountStore::new(pool);
        let _ = store
            .create_with_api_key(
                "delta",
                AccountType::Deployer,
                None,
                None,
                Some("DeltaUser"),
                Some("DeltaOrg"),
            )
            .await
            .expect("create");

        let dup_login = store
            .create_with_api_key(
                "delta-2",
                AccountType::Deployer,
                None,
                None,
                Some("deltauser"),
                None,
            )
            .await;
        assert!(dup_login.is_err());

        let dup_org = store
            .create_with_api_key(
                "delta-3",
                AccountType::Deployer,
                None,
                None,
                None,
                Some("deltaorg"),
            )
            .await;
        assert!(dup_org.is_err());
    }
}
