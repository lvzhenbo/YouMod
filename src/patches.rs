use regex::Regex;
use std::sync::LazyLock;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PatchKind {
    ProSpoof,
    DisableUpdates,
}

pub struct JsPatch {
    pub name: &'static str,
    pub kind: PatchKind,
    pub candidate_files: &'static [&'static str],
    pub search_hints: &'static [&'static str],
    pub target: LazyLock<Regex>,
    pub field_extractor: Option<LazyLock<Regex>>,
    pub replacement_template: &'static str,
    pub single_match: bool,
}

pub static PATCHES: LazyLock<Vec<JsPatch>> = LazyLock::new(|| {
    vec![
        JsPatch {
            name: "getUserAccount (Pro spoof)",
            kind: PatchKind::ProSpoof,
            candidate_files: &[],
            search_hints: &["getUserAccount()", "/v3/account"],
            target: LazyLock::new(|| {
                Regex::new(r"(?s)getUserAccount\(\)\{.*?return\s+this\.#\w+\.fetch\(\{.*?\}\)\}")
                    .unwrap()
            }),
            field_extractor: Some(LazyLock::new(|| {
                Regex::new(r"return\s+this\.#(\w+)\.fetch").unwrap()
            })),
            replacement_template: concat!(
                r#"getUserAccount(){return this.#<field>.fetch({endpoint:"/v3/account","#,
                r#"method:"GET",name:"/v3/account",collectMetrics:0}).then(response=>{"#,
                r#"response.subscription={period:"yearly",state:"active"};return response;})}"#
            ),
            single_match: true,
        },
        JsPatch {
            name: "setAccountWandBrandExperience (Pro spoof)",
            kind: PatchKind::ProSpoof,
            candidate_files: &[],
            search_hints: &[
                "setAccountWandBrandExperience()",
                "/v3/account/brand_experience_wand",
            ],
            target: LazyLock::new(|| {
                Regex::new(r#"(?s)setAccountWandBrandExperience\(\)\{.*?return\s+this\.#\w+\.post\("/v3/account/brand_experience_wand"\)\}"#)
                    .unwrap()
            }),
            field_extractor: Some(LazyLock::new(|| {
                Regex::new(r"return\s+this\.#(\w+)\.post").unwrap()
            })),
            replacement_template: concat!(
                r#"setAccountWandBrandExperience(){return this.#<field>.post("/v3/account/brand_experience_wand")"#,
                r#".then(response=>{response.subscription={period:"yearly",state:"active"};return response;})}"#
            ),
            single_match: true,
        },
        JsPatch {
            name: "Disable Updates",
            kind: PatchKind::DisableUpdates,
            candidate_files: &["index.js"],
            search_hints: &["ACTION_CHECK_FOR_UPDATE"],
            target: LazyLock::new(|| {
                Regex::new(r#"(?s)registerHandler\("ACTION_CHECK_FOR_UPDATE".*?\)\)\)\)"#).unwrap()
            }),
            field_extractor: None,
            replacement_template: r#"registerHandler("ACTION_CHECK_FOR_UPDATE",(e=>expectUpdateFeedUrl(e,(e=>null)))"#,
            single_match: true,
        },
    ]
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_user_account_regex_matches() {
        let patch = &PATCHES[0];
        let js = r#"getUserAccount(){return this.#abc.fetch({endpoint:"/v3/account",method:"GET",name:"/v3/account"})}"#;
        let m = patch.target.find(js);
        assert!(m.is_some(), "getUserAccount target regex should match");
    }

    #[test]
    fn test_get_user_account_field_extractor() {
        let patch = &PATCHES[0];
        let js = r#"return this.#myField.fetch"#;
        let extractor = patch.field_extractor.as_ref().unwrap();
        let caps = extractor.captures(js).unwrap();
        assert_eq!(&caps[1], "myField");
    }

    #[test]
    fn test_get_user_account_replacement() {
        let patch = &PATCHES[0];
        let js = r#"getUserAccount(){return this.#x.fetch({endpoint:"/v3/account",method:"GET",name:"/v3/account"})}"#;
        let caps = patch
            .field_extractor
            .as_ref()
            .unwrap()
            .captures(js)
            .unwrap();
        let field = &caps[1];
        let replacement = patch.replacement_template.replace("<field>", field);
        let result = patch.target.replace(js, replacement.as_str()).to_string();
        assert!(result.contains(r#"subscription={period:"yearly",state:"active"}"#));
        assert!(!result.contains("<field>"));
    }

    #[test]
    fn test_set_account_brand_regex_matches() {
        let patch = &PATCHES[1];
        let js = r#"setAccountWandBrandExperience(){return this.#abc.post("/v3/account/brand_experience_wand")}"#;
        let m = patch.target.find(js);
        assert!(
            m.is_some(),
            "setAccountWandBrandExperience target regex should match"
        );
    }

    #[test]
    fn test_set_account_brand_field_extractor() {
        let patch = &PATCHES[1];
        let js = r#"return this.#svc.post"#;
        let extractor = patch.field_extractor.as_ref().unwrap();
        let caps = extractor.captures(js).unwrap();
        assert_eq!(&caps[1], "svc");
    }

    #[test]
    fn test_set_account_brand_replacement() {
        let patch = &PATCHES[1];
        let js = r#"setAccountWandBrandExperience(){return this.#x.post("/v3/account/brand_experience_wand")}"#;
        let caps = patch
            .field_extractor
            .as_ref()
            .unwrap()
            .captures(js)
            .unwrap();
        let field = &caps[1];
        let replacement = patch.replacement_template.replace("<field>", field);
        let result = patch.target.replace(js, replacement.as_str()).to_string();
        assert!(result.contains(r#"subscription={period:"yearly",state:"active"}"#));
    }

    #[test]
    fn test_disable_updates_regex_matches() {
        let patch = &PATCHES[2];
        let js = r#"registerHandler("ACTION_CHECK_FOR_UPDATE",(e=>expectUpdateFeedUrl(e,(e=>{let t=...}))))"#;
        let m = patch.target.find(js);
        assert!(m.is_some(), "Disable Updates target regex should match");
    }

    #[test]
    fn test_disable_updates_replacement() {
        let patch = &PATCHES[2];
        let js = r#"registerHandler("ACTION_CHECK_FOR_UPDATE",(e=>expectUpdateFeedUrl(e,(e=>{let t=e.updateInfo.url}))))"#;
        let result = patch
            .target
            .replace(js, patch.replacement_template)
            .to_string();
        assert!(result.contains(
            r#"registerHandler("ACTION_CHECK_FOR_UPDATE",(e=>expectUpdateFeedUrl(e,(e=>null)))"#
        ));
    }

    #[test]
    fn test_search_hints_present() {
        let js_with_hints = r#"some code getUserAccount() more code /v3/account setAccountWandBrandExperience() /v3/account/brand_experience_wand ACTION_CHECK_FOR_UPDATE here"#;
        for patch in PATCHES.iter() {
            let all_found = patch.search_hints.iter().all(|h| js_with_hints.contains(h));
            assert!(
                all_found,
                "Search hints for '{}' should be found",
                patch.name
            );
        }
    }
}
