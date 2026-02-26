use dashmap::DashSet;

#[derive(Default)]
pub struct TrustedMrtdRegistry {
    values: DashSet<String>,
}

impl TrustedMrtdRegistry {
    pub fn add(&self, mrtd: String) {
        self.values.insert(mrtd);
    }

    pub fn contains(&self, mrtd: &str) -> bool {
        self.values.contains(mrtd)
    }
}
