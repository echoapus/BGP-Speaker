use crate::{
    config::{PolicyAction, PolicyRule},
    route::Route,
};

/// Attribute overrides as (key, value) text, validated with `Route::set_attribute` when set.
pub type Overrides = Vec<(String, String)>;

#[derive(Clone, Debug)]
pub struct Policy {
    rules: Vec<PolicyRule>,
    overrides: Overrides,
}

impl Policy {
    pub fn new(rules: &[PolicyRule], overrides: &[(String, String)]) -> Self {
        Self {
            rules: rules.to_vec(),
            overrides: overrides.to_vec(),
        }
    }

    pub fn from_rules(rules: &[PolicyRule]) -> Self {
        Self::new(rules, &[])
    }

    /// The route as this peer receives it: each override replaces that attribute.
    pub fn apply(&self, route: &Route) -> Route {
        let mut route = route.clone();
        for (key, value) in &self.overrides {
            // Validated when the override was set, so this cannot fail.
            let _ = route.set_attribute(key, value);
        }
        route
    }

    pub fn allows(&self, route: &Route) -> bool {
        self.rules
            .iter()
            .find(|rule| rule.prefix == route.prefix)
            .is_some_and(|rule| rule.action == PolicyAction::Permit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn policy_denies_by_default() {
        let policy = Policy::from_rules(&[]);
        let route = Route::new(
            "192.0.2.0/24".parse().unwrap(),
            Ipv4Addr::new(198, 51, 100, 1),
        );
        assert!(!policy.allows(&route));
    }

    #[test]
    fn first_matching_rule_wins() {
        let prefix = "192.0.2.0/24".parse().unwrap();
        let route = Route::new(prefix, Ipv4Addr::new(198, 51, 100, 1));
        let policy = Policy::from_rules(&[
            PolicyRule {
                prefix,
                action: PolicyAction::Deny,
            },
            PolicyRule {
                prefix,
                action: PolicyAction::Permit,
            },
        ]);
        assert!(!policy.allows(&route));
    }

    #[test]
    fn overrides_replace_only_their_attribute() {
        let mut route = Route::new(
            "192.0.2.0/24".parse().unwrap(),
            Ipv4Addr::new(198, 51, 100, 1),
        );
        route.med = Some(50);
        route.communities = vec![1];
        let policy = Policy::new(
            &[],
            &[
                ("next_hop".into(), "1.1.1.1".into()),
                ("communities".into(), "65000:9".into()),
            ],
        );
        let sent = policy.apply(&route);
        assert_eq!(sent.next_hop, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(sent.communities, [65000 << 16 | 9]);
        assert_eq!(sent.med, Some(50));
        assert_eq!(route.next_hop, Ipv4Addr::new(198, 51, 100, 1));
    }
}
