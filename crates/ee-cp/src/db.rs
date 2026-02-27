use ee_common::error::{AppError, AppResult};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

pub async fn connect_and_migrate(database_url: &str) -> AppResult<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .map_err(|e| AppError::External(format!("sqlite connect failed: {e}")))?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| AppError::External(format!("sqlite migrate failed: {e}")))?;

    Ok(pool)
}
