use axum::response::Html;

pub async fn root() -> Html<&'static str> {
    Html(include_str!("ui_root.html"))
}
