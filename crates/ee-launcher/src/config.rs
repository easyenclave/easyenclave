use std::collections::HashMap;

pub fn kernel_cmdline(extra: HashMap<String, String>) -> String {
    let mut parts = vec!["console=ttyS0".to_owned(), "panic=1".to_owned()];
    for (k, v) in extra {
        parts.push(format!("ee.{k}={v}"));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::kernel_cmdline;

    #[test]
    fn cmdline_contains_prefixed_keys() {
        let mut values = HashMap::new();
        values.insert("owner".to_owned(), "github:org/example".to_owned());
        let line = kernel_cmdline(values);
        assert!(line.contains("ee.owner=github:org/example"));
    }
}
