use crate::model::Report;
use anyhow::Result;

pub fn render(report: &Report) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}
