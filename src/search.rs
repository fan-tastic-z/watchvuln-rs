use regex::Regex;
use snafu::ResultExt;
use tracing::{info, warn};

use crate::{
    error::{OctocrabErrSnafu, RegexErrSnafu, Result},
    utils::get_last_year_data,
};

pub async fn search_github_poc(cve_id: &str) -> Vec<String> {
    let mut res = Vec::new();
    let (nuclei_res, repo_res) = tokio::join!(search_nuclei_pr(cve_id), search_github_repo(cve_id));
    match nuclei_res {
        Ok(nuclei) => res.extend(nuclei),
        Err(e) => {
            warn!("search nucli pr error:{:?}", e);
        }
    }
    match repo_res {
        Ok(repo) => res.extend(repo),
        Err(e) => {
            warn!("search github repo error:{:?}", e);
        }
    }
    res
}

pub async fn search_nuclei_pr(cve_id: &str) -> Result<Vec<String>> {
    info!("search nuclei PR of {}", cve_id);
    let page = octocrab::instance()
        .pulls("projectdiscovery", "nuclei-templates")
        .list()
        .per_page(100)
        .page(1u32)
        .send()
        .await
        .with_context(|_| OctocrabErrSnafu {
            search: cve_id.to_owned(),
        })?;
    let re = format!(r"(?i)(?:\b|/|_){}(?:\b|/|_)", cve_id);
    let regex = Regex::new(re.as_str()).with_context(|_| RegexErrSnafu { re })?;
    let links = page
        .into_iter()
        .filter(|pull| pull.title.is_some() || pull.body.is_some())
        .filter(|pull| {
            regex.is_match(pull.title.as_ref().unwrap_or(&String::new()))
                || regex.is_match(pull.body.as_ref().unwrap_or(&String::new()))
        })
        .filter_map(|pull| pull.html_url)
        .map(|u| u.to_string())
        .collect::<Vec<_>>();
    Ok(links)
}

pub async fn search_github_repo(cve_id: &str) -> Result<Vec<String>> {
    info!("search github repo of {}", cve_id);
    let last_year = get_last_year_data();
    let query = format!("language:Python language:JavaScript language:C language:C++ language:Java language:PHP language:Ruby language:Rust language:C# created:>{} {}",last_year, cve_id);
    let page = octocrab::instance()
        .search()
        .repositories(&query)
        .per_page(100)
        .page(1u32)
        .send()
        .await
        .with_context(|_| OctocrabErrSnafu {
            search: cve_id.to_owned(),
        })?;
    let re = format!(r"(?i)(?:\b|/|_){}(?:\b|/|_)", cve_id);
    let regex = Regex::new(re.as_str()).with_context(|_| RegexErrSnafu { re })?;
    let links = page
        .into_iter()
        .filter_map(|r| r.html_url)
        .filter(|url| regex.captures(url.as_str()).is_some())
        .map_while(|u| Some(u.to_string()))
        .collect::<Vec<_>>();
    Ok(links)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_search_github_repo() -> Result<()> {
        let res = search_github_repo("CVE-2021-4034").await?;
        println!("{:?}", res);
        Ok(())
    }

    #[tokio::test]
    async fn test_search_nuclei_pr() -> Result<()> {
        let res = search_nuclei_pr("CVE-2023-3380").await?;
        println!("{:?}", res);
        Ok(())
    }
}
