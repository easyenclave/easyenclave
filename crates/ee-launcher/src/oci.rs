use ee_common::error::AppResult;

pub async fn extract_image(image: &str) -> AppResult<String> {
    Ok(format!("/tmp/ee-image/{}", image.replace(['/', ':'], "_")))
}
