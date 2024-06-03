use crate::error::Result;
use crate::grab::VulnInfo;
use crate::utils::render_string;
use serde_json::Value;

const VULN_INFO_MSG_TEMPLATE: &str = r####"
# {{ title }}

- CVE编号: {% if cve %} {{ cve }}{% else %}暂无 {% endif %}
- 危害定级: **{{ severity }}**
- 漏洞标签: {% for tag in tags %}**{{ tag }}**{% endfor %}
- 披露日期: **{{ disclosure }}**
- 推送原因: {% for v in reasons %}{{ v }}{% endfor %}
- 信息来源: [{{ from }}]

{% if description %}### **漏洞描述**
{{ description }}
{% endif %}
{% if solutions %}### **修复方案**
{{ solutions }}
{% endif %}
{% if references%}### **参考链接**
{% for reference in references %}{{ loop.index }}.{{ reference }}
{% endfor %}{% endif %}"####;

const INIT_MSG_TEMPLATE: &str = r#"
数据初始化完成
当前版本: {{ version }}
本地漏洞数量: {{ vuln_count }}
检查周期配置: {{ cron_config }}

目前爬取的数据源：{% for v in grabs %}
{{ loop.index }}.{{ v }}{% endfor %}"#;

const MAX_REFERENCE_LENGTH: usize = 8;

pub fn reader_vulninfo(mut vuln: VulnInfo) -> Result<String> {
    if vuln.references.len() > MAX_REFERENCE_LENGTH {
        vuln.references = vuln.references[..MAX_REFERENCE_LENGTH].to_vec();
    }
    let json_value: Value = serde_json::to_value(vuln)?;
    let markdown = render_string(VULN_INFO_MSG_TEMPLATE, &json_value)?;
    Ok(markdown)
}

pub fn escape_markdown(input: String) -> String {
    input
        .replace('_', "\\_")
        .replace('.', "\\.")
        .replace('*', "\\*")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('(', "\\(")
        .replace(')', "\\)")
        .replace('~', "\\~")
        .replace('`', "\\`")
        .replace('>', "\\>")
        .replace('#', "\\#")
        .replace('+', "\\+")
        .replace('-', "\\-")
        .replace('=', "\\=")
        .replace('|', "\\|")
        .replace('{', "\\{")
        .replace('}', "\\}")
        .replace('!', "\\!")
}

pub fn render_init(
    version: String,
    vuln_count: u64,
    cron_config: String,
    grabs: Vec<String>,
) -> Result<String> {
    let json_value = serde_json::json!(
        {
            "version": version,
            "vuln_count": vuln_count,
            "cron_config": cron_config,
            "grabs": grabs
        }
    );
    let markdown = render_string(INIT_MSG_TEMPLATE, &json_value)?;
    Ok(markdown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reader_vulninfo() -> Result<()> {
        let tags: Vec<String> = Vec::new();
        let reasons: Vec<String> = Vec::new();

        let v = VulnInfo {
            unique_key: "AVD-2023-50379".to_string(),
            title: "Apache Ambari 命令注入漏洞（CVE-2023-50379）".to_string(),
            description: "2.7.8之前的Apache Ambari中存在恶意代码注入导致RCE。".to_string(),
            severity: crate::grab::Severity::High,
            cve: "CVE-2023-50379".to_string(),
            disclosure: "2024-02-27".to_string(),
            references: vec![
                "http://www.openwall.com/lists/oss-security/2024/02/27/1".to_string(),
                "https://ambari.apache.org/".to_string(),
                "https://lists.apache.org/thread/jglww6h6ngxpo1r6r5fx7ff7z29lnvv8".to_string(),
                "https://www.cve.org/CVERecord?id=CVE-2023-50379".to_string(),
            ],
            solutions: "建议用户升级到2.7.8版本，该版本修复了此问题。".to_string(),
            from: "https://avd.aliyun.com/high-risk/list".to_string(),
            tags,
            reasons,
            is_valuable: false,
        };
        let res = reader_vulninfo(v)?;
        println!("{}", res);
        Ok(())
    }
}
