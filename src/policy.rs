use crate::{
    config::{PeerConfig, PolicyAction, PolicyRule},
    route::Route,
};

#[derive(Clone, Debug)]
pub struct Policy {
    rules: Vec<PolicyRule>,
}

impl Policy {
    pub fn for_peer(peer: &PeerConfig) -> Self {
        Self {
            rules: peer.policy.clone(),
        }
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
        let policy = Policy { rules: Vec::new() };
        let route = Route {
            prefix: "192.0.2.0/24".parse().unwrap(),
            next_hop: Ipv4Addr::new(198, 51, 100, 1),
        };
        assert!(!policy.allows(&route));
    }

    #[test]
    fn first_matching_rule_wins() {
        let prefix = "192.0.2.0/24".parse().unwrap();
        let route = Route {
            prefix,
            next_hop: Ipv4Addr::new(198, 51, 100, 1),
        };
        let policy = Policy {
            rules: vec![
                PolicyRule {
                    prefix,
                    action: PolicyAction::Deny,
                },
                PolicyRule {
                    prefix,
                    action: PolicyAction::Permit,
                },
            ],
        };
        assert!(!policy.allows(&route));
    }
}
