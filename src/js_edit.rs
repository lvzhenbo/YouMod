//! Structural JavaScript editing.
//!
//! Wand ships minified bundles whose formatting differs between builds, so a
//! patch anchors on a stable API name and splices bytes at AST-derived offsets
//! instead of matching text. `oxc` supplies the offsets; every byte outside an
//! edit is copied through untouched, so minified formatting never has to be
//! reproduced.

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Function, MethodDefinition, ObjectProperty, Program, PropertyKey, PropertyKind, Statement,
    StringLiteral,
};
use oxc_ast_visit::VisitJs;
use oxc_ast_visit::walk_js::{
    walk_function, walk_method_definition, walk_object_property, walk_string_literal,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};
use oxc_syntax::scope::ScopeFlags;

/// The object property the account reducer writes the signed-in account to.
const ACCOUNT_PROPERTY: &str = "account";

/// A byte splice: `source[start..end]` becomes `text`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsEdit {
    pub start: usize,
    pub end: usize,
    pub text: String,
}

/// Outcome of looking for one patch's edit site in one bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Located {
    /// Sites found. Every entry is a splice into the original bytes.
    Edits(Vec<JsEdit>),
    /// The site is present but already carries this patch's payload.
    AlreadyPatched,
    /// The anchor this patch keys on is not in this bundle.
    Absent,
}

/// Parses a bundle, returning `None` when it is not parseable as a whole.
///
/// Bundles are parsed one at a time and a failure only means "not my file": a
/// patch whose anchor is missing everywhere is reported by the caller instead.
pub fn parse<'a>(allocator: &'a Allocator, source: &'a str) -> Option<Program<'a>> {
    let parsed = Parser::new(allocator, source, SourceType::unambiguous()).parse();
    if parsed.fatal_error || parsed.program.body.is_empty() {
        return None;
    }
    Some(parsed.program)
}

/// Applies splices, tolerating any input order. Edits must not overlap.
pub fn apply_edits(source: &str, mut edits: Vec<JsEdit>) -> String {
    edits.sort_by_key(|edit| std::cmp::Reverse((edit.start, edit.end)));
    let mut patched = source.to_string();
    let mut boundary = source.len();
    for edit in edits {
        debug_assert!(edit.end <= boundary, "overlapping JS edits");
        boundary = edit.start;
        patched.replace_range(edit.start..edit.end, &edit.text);
    }
    patched
}

/// Rewrites the last top-level `return X` of `method` as `return <wrapper>`,
/// where `wrapper` uses `$0` for the original expression.
///
/// The surrounding method is left exactly as found, which matters for calls
/// such as `getUserAccount()` whose request body must survive verbatim.
pub fn wrap_return(
    program: &Program<'_>,
    source: &str,
    method: &str,
    wrapper: &str,
    marker: &str,
) -> Located {
    let sites = find_named(program, method);
    if sites.is_empty() {
        return Located::Absent;
    }

    let mut edits = Vec::new();
    let mut already = 0;
    for site in sites {
        let Some(body) = site.body else { continue };
        if body_text(source, body).contains(marker) {
            already += 1;
            continue;
        }

        let Some(argument) = site.return_argument else {
            continue;
        };
        let expression = slice(source, argument);
        edits.push(JsEdit {
            start: argument.start as usize,
            end: argument.end as usize,
            text: wrapper.replace("$0", &format!("({expression})")),
        });
    }

    conclude(edits, already)
}

/// Replaces everything between the braces of `method`'s body with `body`.
pub fn replace_body(
    program: &Program<'_>,
    source: &str,
    method: &str,
    body: &str,
    marker: &str,
) -> Located {
    let sites = find_named(program, method);
    if sites.is_empty() {
        return Located::Absent;
    }

    let mut edits = Vec::new();
    let mut already = 0;
    for site in sites {
        let Some(span) = site.body else { continue };
        let existing = body_text(source, span);
        if existing.contains(marker) {
            already += 1;
            continue;
        }

        edits.push(JsEdit {
            start: span.start as usize + 1,
            end: span.end as usize - 1,
            text: body.to_string(),
        });
    }

    conclude(edits, already)
}

/// Rewrites the `account` property inside the reducer declared after the
/// `anchor` string literal, so account writes that bypass the API wrappers
/// still report an active subscription.
pub fn wrap_reducer_account(
    program: &Program<'_>,
    source: &str,
    anchor: &str,
    template: &str,
    marker: &str,
) -> Located {
    let mut anchors = AnchorFinder { anchor, end: None };
    anchors.visit_program(program);
    let Some(anchor_end) = anchors.end else {
        return Located::Absent;
    };

    let mut functions = FirstFunctionAfter {
        after: anchor_end,
        found: None,
    };
    functions.visit_program(program);
    let Some(reducer) = functions.found else {
        return Located::Absent;
    };
    let Some(body) = reducer.body else {
        return Located::Absent;
    };

    if body_text(source, body).contains(marker) {
        return Located::AlreadyPatched;
    }

    let mut accounts = AccountFinder {
        range: reducer.span,
        property: None,
    };
    accounts.visit_program(program);
    let Some(property) = accounts.property else {
        return Located::Absent;
    };

    let expression = slice(source, property.value).to_string();
    Located::Edits(vec![JsEdit {
        start: property.whole.start as usize,
        end: property.whole.end as usize,
        text: template.replace("${account}", &expression),
    }])
}

fn conclude(edits: Vec<JsEdit>, already: usize) -> Located {
    if edits.is_empty() {
        if already > 0 {
            Located::AlreadyPatched
        } else {
            Located::Absent
        }
    } else {
        Located::Edits(edits)
    }
}

fn slice(source: &str, span: Span) -> &str {
    source
        .get(span.start as usize..span.end as usize)
        .unwrap_or_default()
}

/// The statements between a `{ ... }` body's braces.
fn body_text(source: &str, span: Span) -> &str {
    source
        .get(span.start as usize + 1..span.end as usize - 1)
        .unwrap_or_default()
}

/// A located function or class method, reduced to the spans a patch needs.
#[derive(Debug, Clone, Copy)]
struct Site {
    span: Span,
    body: Option<Span>,
    /// The argument of the last direct-child `return` statement.
    return_argument: Option<Span>,
}

impl Site {
    fn of(function: &Function<'_>) -> Self {
        let Some(body) = function.body.as_ref() else {
            return Self {
                span: function.span,
                body: None,
                return_argument: None,
            };
        };

        let return_argument = body
            .statements
            .iter()
            .rev()
            .find_map(|statement| match statement {
                Statement::ReturnStatement(ret) => {
                    Some(ret.argument.as_ref().map(|argument| argument.span()))
                }
                _ => None,
            });

        Self {
            span: function.span,
            body: Some(body.span),
            return_argument: return_argument.flatten(),
        }
    }
}

/// Collects every function or method called `name`.
struct NamedFinder<'n> {
    name: &'n str,
    sites: Vec<Site>,
}

fn find_named(program: &Program<'_>, name: &str) -> Vec<Site> {
    let mut finder = NamedFinder {
        name,
        sites: Vec::new(),
    };
    finder.visit_program(program);
    finder.sites
}

impl<'ast> VisitJs<'ast> for NamedFinder<'_> {
    fn visit_method_definition(&mut self, node: &MethodDefinition<'ast>) {
        if matches!(&node.key, PropertyKey::StaticIdentifier(key) if key.name.as_str() == self.name)
        {
            self.sites.push(Site::of(&node.value));
        }
        walk_method_definition(self, node);
    }

    fn visit_function(&mut self, node: &Function<'ast>, flags: ScopeFlags) {
        if matches!(&node.id, Some(id) if id.name.as_str() == self.name) {
            self.sites.push(Site::of(node));
        }
        walk_function(self, node, flags);
    }
}

/// Finds the end offset of a string literal with a given value.
struct AnchorFinder<'n> {
    anchor: &'n str,
    end: Option<u32>,
}

impl<'ast> VisitJs<'ast> for AnchorFinder<'_> {
    fn visit_string_literal(&mut self, node: &StringLiteral<'ast>) {
        if self.end.is_none() && node.value.as_str() == self.anchor {
            self.end = Some(node.span.end);
        }
        walk_string_literal(self, node);
    }
}

/// Finds the first function starting after an offset.
struct FirstFunctionAfter {
    after: u32,
    found: Option<Site>,
}

impl<'ast> VisitJs<'ast> for FirstFunctionAfter {
    fn visit_function(&mut self, node: &Function<'ast>, flags: ScopeFlags) {
        if node.span.start > self.after
            && self
                .found
                .is_none_or(|found| node.span.start < found.span.start)
        {
            self.found = Some(Site::of(node));
        }
        walk_function(self, node, flags);
    }
}

/// Finds the first `account` property inside a span.
struct AccountFinder {
    range: Span,
    property: Option<AccountProperty>,
}

#[derive(Debug, Clone, Copy)]
struct AccountProperty {
    /// The whole `account: value` property.
    whole: Span,
    /// Just the value expression.
    value: Span,
}

impl<'ast> VisitJs<'ast> for AccountFinder {
    fn visit_object_property(&mut self, node: &ObjectProperty<'ast>) {
        if node.kind == PropertyKind::Init
            && node.span.start >= self.range.start
            && node.span.end <= self.range.end
            && matches!(&node.key, PropertyKey::StaticIdentifier(key) if key.name.as_str() == ACCOUNT_PROPERTY)
            && self
                .property
                .is_none_or(|found| node.span.start < found.whole.start)
        {
            self.property = Some(AccountProperty {
                whole: node.span,
                value: node.value.span(),
            });
        }
        walk_object_property(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patches::{ACCOUNT_REDUCER_TEMPLATE, PRO_SUBSCRIPTION_WRAPPER};

    /// Verbatim from Wand 12.61's `app-4e8d88bd.*.bundle.js`.
    const REAL_ACCOUNT_API: &str = concat!(
        "class X{",
        r#"requestRemoteAuthCode(){return this.#e.post("/v3/auth/remote_code")}"#,
        r#"getUserAccount(){return this.#e.fetch({endpoint:"/v3/account",method:"GET",name:"/v3/account",collectMetrics:!1})}"#,
        r#"setAccountLanguage(e,t){return this.#e.post("/v3/account/language",{tag:e,auto:t})}"#,
        r#"setAccountWandBrandExperience(){return this.#e.post("/v3/account/brand_experience_wand")}"#,
        "}",
    );

    /// Verbatim from Wand 12.61's `app-6f178a3f.*.bundle.js`.
    const REAL_ACCOUNT_REDUCER: &str = concat!(
        r#"const m="ACTION_SET_ACCOUNT";function p(t,e){return{...t,account:e}}"#,
        r#"function T(t,e,n){return{...t,mapSettings:{...t.mapSettings,[e]:n}}}"#,
    );

    fn locate<F>(source: &str, locate: F) -> Located
    where
        F: FnOnce(&Program<'_>) -> Located,
    {
        let allocator = Allocator::default();
        let program = parse(&allocator, source).expect("fixture should parse");
        locate(&program)
    }

    fn apply(source: &str, located: Located) -> String {
        match located {
            Located::Edits(edits) => apply_edits(source, edits),
            other => panic!("expected edits, got {other:?}"),
        }
    }

    #[test]
    fn wraps_get_user_account_return_only() {
        let located = locate(REAL_ACCOUNT_API, |program| {
            wrap_return(
                program,
                REAL_ACCOUNT_API,
                "getUserAccount",
                PRO_SUBSCRIPTION_WRAPPER,
                "state:\"active\"",
            )
        });
        let patched = apply(REAL_ACCOUNT_API, located);

        assert!(patched.contains(concat!(
            r#"getUserAccount(){return (this.#e.fetch({endpoint:"/v3/account",method:"GET","#,
            r#"name:"/v3/account",collectMetrics:!1})).then((response)=>"#,
        )));
        // The unpatched request body survives byte for byte.
        assert!(patched.contains(r#"collectMetrics:!1})"#));
        // Neighbouring methods are untouched.
        assert!(patched.contains(
            r#"setAccountLanguage(e,t){return this.#e.post("/v3/account/language",{tag:e,auto:t})}"#
        ));
    }

    #[test]
    fn wraps_set_account_language() {
        let located = locate(REAL_ACCOUNT_API, |program| {
            wrap_return(
                program,
                REAL_ACCOUNT_API,
                "setAccountLanguage",
                PRO_SUBSCRIPTION_WRAPPER,
                "state:\"active\"",
            )
        });
        let patched = apply(REAL_ACCOUNT_API, located);

        assert!(patched.contains(concat!(
            r#"setAccountLanguage(e,t){return (this.#e.post("/v3/account/language",{tag:e,auto:t}))"#,
            r#".then((response)=>"#,
        )));
    }

    #[test]
    fn replaces_remote_auth_code_body() {
        let located = locate(REAL_ACCOUNT_API, |program| {
            replace_body(
                program,
                REAL_ACCOUNT_API,
                "requestRemoteAuthCode",
                "return Promise.reject(new Error(\"you-mod: native mobile pairing disabled\"))",
                "native mobile pairing disabled",
            )
        });
        let patched = apply(REAL_ACCOUNT_API, located);

        assert!(patched.contains(concat!(
            "requestRemoteAuthCode(){return Promise.reject(",
            "new Error(\"you-mod: native mobile pairing disabled\"))}"
        )));
        assert!(!patched.contains("/v3/auth/remote_code"));
        assert!(patched.contains("getUserAccount(){"));
    }

    #[test]
    fn wraps_the_account_property_of_the_reducer_after_the_anchor() {
        let located = locate(REAL_ACCOUNT_REDUCER, |program| {
            wrap_reducer_account(
                program,
                REAL_ACCOUNT_REDUCER,
                "ACTION_SET_ACCOUNT",
                ACCOUNT_REDUCER_TEMPLATE,
                "state:\"active\"",
            )
        });
        let patched = apply(REAL_ACCOUNT_REDUCER, located);

        assert!(patched.contains(concat!(
            r#"account:((account)=>account&&"object"==typeof account?"#,
            r#"{...account,subscription:{period:"yearly",state:"active"}}:account)(e)"#
        )));
        // The mapSettings reducer that follows is not the account reducer.
        assert!(!patched.contains("mapSettings:((account)=>"));
    }

    #[test]
    fn ignores_other_account_values() {
        let source = concat!(
            r#"const m="ACTION_SET_ACCOUNT";function p(t,e){return{...t,account:e}}"#,
            r#"function q(t){return{account:{deep:1}}}"#,
        );
        let located = locate(source, |program| {
            wrap_reducer_account(
                program,
                source,
                "ACTION_SET_ACCOUNT",
                ACCOUNT_REDUCER_TEMPLATE,
                "state:\"active\"",
            )
        });
        let patched = apply(source, located);
        assert!(patched.contains("{...t,account:((account)=>"));
        assert!(patched.contains(r#"}:account)(e)}"#));
        assert!(patched.contains("{account:{deep:1}}"));
    }

    #[test]
    fn missing_anchors_report_absent() {
        let source = "const a = 1;";
        assert_eq!(
            locate(source, |program| wrap_return(
                program,
                source,
                "getUserAccount",
                PRO_SUBSCRIPTION_WRAPPER,
                "state:\"active\""
            )),
            Located::Absent
        );
        assert_eq!(
            locate(source, |program| wrap_reducer_account(
                program,
                source,
                "ACTION_SET_ACCOUNT",
                ACCOUNT_REDUCER_TEMPLATE,
                "state:\"active\""
            )),
            Located::Absent
        );
    }

    #[test]
    fn reapplying_is_detected_not_repeated() {
        let source = REAL_ACCOUNT_API;
        let once = apply(
            source,
            locate(source, |program| {
                wrap_return(
                    program,
                    source,
                    "getUserAccount",
                    PRO_SUBSCRIPTION_WRAPPER,
                    "state:\"active\"",
                )
            }),
        );
        assert_eq!(
            locate(&once, |program| wrap_return(
                program,
                &once,
                "getUserAccount",
                PRO_SUBSCRIPTION_WRAPPER,
                "state:\"active\""
            )),
            Located::AlreadyPatched
        );
    }

    #[test]
    fn detects_a_sibling_already_wrapped_method() {
        let source = concat!(
            r#"class X{getUserAccount(){return (this.#e.fetch({})).then((response)=>{response.subscription={period:"yearly",state:"active"};return response})}"#,
            r#"setAccountLanguage(e,t){return this.#e.post("/v3/account/language",{tag:e,auto:t})}"#,
            "}",
        );
        let located = locate(source, |program| {
            wrap_return(
                program,
                source,
                "setAccountLanguage",
                PRO_SUBSCRIPTION_WRAPPER,
                "state:\"active\"",
            )
        });
        let patched = apply(source, located);
        assert!(patched.contains(r#"setAccountLanguage(e,t){return (this.#e.post("#));
    }

    #[test]
    fn picks_the_last_top_level_return() {
        let source = r#"function f(){if(x){return 1}return 2}"#;
        let located = locate(source, |program| {
            wrap_return(program, source, "f", "$0;//w", "//w")
        });
        let patched = apply(source, located);
        assert_eq!(patched, r#"function f(){if(x){return 1}return (2);//w}"#);
    }

    #[test]
    fn refuses_a_body_without_a_return_value() {
        let source = r#"function f(){doWork();return;}"#;
        assert_eq!(
            locate(source, |program| wrap_return(
                program, source, "f", "$0;//w", "//w"
            )),
            Located::Absent
        );
    }

    #[test]
    fn does_not_touch_a_call_site_only_bundle() {
        let source = r#"const x = api.getUserAccount();"#;
        assert_eq!(
            locate(source, |program| wrap_return(
                program,
                source,
                "getUserAccount",
                PRO_SUBSCRIPTION_WRAPPER,
                "state:\"active\""
            )),
            Located::Absent
        );
    }
}
