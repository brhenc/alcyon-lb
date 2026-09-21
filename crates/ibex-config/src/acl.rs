//! ACL Evaluation Engine for HAProxy syntax.

use crate::ast::{AclCriterion, AclDef};

/// Request context evaluated by ACL expressions
pub struct RequestEvaluationContext<'a> {
    pub path: &'a str,
    pub host: Option<&'a str>,
    pub method: &'a str,
    pub src_ip: &'a str,
    pub is_ssl: bool,
}

/// Evaluates an ACL definition against a request context.
pub fn evaluate_acl(acl: &AclDef, ctx: &RequestEvaluationContext) -> bool {
    match &acl.criterion {
        AclCriterion::PathBeg(prefix) => ctx.path.starts_with(prefix),
        AclCriterion::PathExact(exact) => ctx.path == exact,
        AclCriterion::HostExact(host) => ctx.host.map_or(false, |h| h == host),
        AclCriterion::MethodExact(method) => ctx.method.eq_ignore_ascii_case(method),
        AclCriterion::SrcIp(ip) => ctx.src_ip == ip,
        AclCriterion::SslFc => ctx.is_ssl,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acl_evaluation() {
        let acl_api = AclDef {
            name: "is_api".to_string(),
            criterion: AclCriterion::PathBeg("/api/".to_string()),
        };

        let ctx = RequestEvaluationContext {
            path: "/api/v1/users",
            host: Some("example.com"),
            method: "GET",
            src_ip: "127.0.0.1",
            is_ssl: true,
        };

        assert!(evaluate_acl(&acl_api, &ctx));

        let ctx_static = RequestEvaluationContext {
            path: "/static/img.png",
            host: Some("example.com"),
            method: "GET",
            src_ip: "127.0.0.1",
            is_ssl: true,
        };

        assert!(!evaluate_acl(&acl_api, &ctx_static));
    }
}
