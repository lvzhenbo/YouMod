//! The JavaScript patches applied to Wand's `app.asar` before it is repacked.
//!
//! Patches are anchored on API names that survive minification rather than on
//! the surrounding formatting, which differs between Wand builds. The
//! structural operations in [`crate::js_edit`] splice bytes at AST offsets;
//! [`PatchOp::ReplaceText`] remains for the one handler whose text is regular
//! enough to match directly.

use regex::Regex;
use std::sync::LazyLock;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PatchKind {
    ProSpoof,
    DisableUpdates,
}

/// Marks a bundle that already carries one of our Pro payloads.
pub const PRO_PAYLOAD_MARKER: &str = r#"state:"active""#;

/// Marks a bundle whose remote-pairing method was already stubbed.
pub const PAIRING_PAYLOAD_MARKER: &str = "native mobile pairing disabled";

/// Rewrites a resolved account response so it always reports an active
/// subscription. `$0` is the original return expression.
pub const PRO_SUBSCRIPTION_WRAPPER: &str = concat!(
    r#"$0.then((response)=>{response&&"object"==typeof response&&"#,
    r#"(response.subscription={period:"yearly",state:"active"});return response})"#
);

/// Wraps the account the reducer stores. `${account}` is the original value
/// expression.
pub const ACCOUNT_REDUCER_TEMPLATE: &str = concat!(
    r#"account:((account)=>account&&"object"==typeof account?"#,
    r#"{...account,subscription:{period:"yearly",state:"active"}}:account)(${account})"#
);

/// Native phone pairing signs the desktop session out, which would undo the
/// Pro unlock.
pub const DISABLE_NATIVE_PAIRING_BODY: &str =
    r#"return Promise.reject(new Error("you-mod: native mobile pairing disabled"))"#;

/// The update-check handler's patched form, which no longer matches
/// [`PatchOp::ReplaceText`]'s pattern and so needs its own marker.
pub const DISABLE_UPDATES_MARKER: &str = "expectUpdateFeedUrl(e,(e=>null))";

pub enum PatchOp {
    /// Rewrites the last top-level `return` of `method`.
    WrapReturn {
        method: &'static str,
        wrapper: &'static str,
    },
    /// Replaces everything between the braces of `method`'s body.
    ReplaceBody {
        method: &'static str,
        body: &'static str,
    },
    /// Wraps the account property of the reducer declaration following `anchor`.
    WrapReducerAccount {
        anchor: &'static str,
        template: &'static str,
    },
    /// Literal text substitution, for handlers whose shape is stable.
    ReplaceText {
        target: LazyLock<Regex>,
        replacement: &'static str,
        single_match: bool,
    },
}

pub struct JsPatch {
    pub name: &'static str,
    pub kind: PatchKind,
    /// Restricts the search to these file names; empty means every `.js` file.
    pub candidate_files: &'static [&'static str],
    /// Cheap pre-filter run before a file is parsed or matched.
    pub search_hints: &'static [&'static str],
    /// A payload substring whose presence means the patch is already in place.
    pub payload_marker: Option<&'static str>,
    pub op: PatchOp,
}

pub static PATCHES: LazyLock<Vec<JsPatch>> = LazyLock::new(|| {
    vec![
        JsPatch {
            name: "getUserAccount (Pro spoof)",
            kind: PatchKind::ProSpoof,
            candidate_files: &[],
            search_hints: &["getUserAccount("],
            payload_marker: Some(PRO_PAYLOAD_MARKER),
            op: PatchOp::WrapReturn {
                method: "getUserAccount",
                wrapper: PRO_SUBSCRIPTION_WRAPPER,
            },
        },
        JsPatch {
            name: "setAccountWandBrandExperience (Pro spoof)",
            kind: PatchKind::ProSpoof,
            candidate_files: &[],
            search_hints: &["setAccountWandBrandExperience("],
            payload_marker: Some(PRO_PAYLOAD_MARKER),
            op: PatchOp::WrapReturn {
                method: "setAccountWandBrandExperience",
                wrapper: PRO_SUBSCRIPTION_WRAPPER,
            },
        },
        JsPatch {
            name: "setAccountLanguage (Pro spoof)",
            kind: PatchKind::ProSpoof,
            candidate_files: &[],
            search_hints: &["setAccountLanguage("],
            payload_marker: Some(PRO_PAYLOAD_MARKER),
            op: PatchOp::WrapReturn {
                method: "setAccountLanguage",
                wrapper: PRO_SUBSCRIPTION_WRAPPER,
            },
        },
        JsPatch {
            name: "setAccountReducer (Pro spoof)",
            kind: PatchKind::ProSpoof,
            candidate_files: &[],
            search_hints: &["ACTION_SET_ACCOUNT"],
            payload_marker: Some(PRO_PAYLOAD_MARKER),
            op: PatchOp::WrapReducerAccount {
                anchor: "ACTION_SET_ACCOUNT",
                template: ACCOUNT_REDUCER_TEMPLATE,
            },
        },
        JsPatch {
            name: "disableNativeRemotePairing (Pro spoof)",
            kind: PatchKind::ProSpoof,
            candidate_files: &[],
            search_hints: &["requestRemoteAuthCode"],
            payload_marker: Some(PAIRING_PAYLOAD_MARKER),
            op: PatchOp::ReplaceBody {
                method: "requestRemoteAuthCode",
                body: DISABLE_NATIVE_PAIRING_BODY,
            },
        },
        JsPatch {
            name: "Disable Updates",
            kind: PatchKind::DisableUpdates,
            candidate_files: &["index.js"],
            search_hints: &["ACTION_CHECK_FOR_UPDATE"],
            payload_marker: Some(DISABLE_UPDATES_MARKER),
            op: PatchOp::ReplaceText {
                target: LazyLock::new(|| {
                    Regex::new(r#"(?s)registerHandler\("ACTION_CHECK_FOR_UPDATE".*?\)\)\)\)"#)
                        .unwrap()
                }),
                replacement: r#"registerHandler("ACTION_CHECK_FOR_UPDATE",(e=>expectUpdateFeedUrl(e,(e=>null)))"#,
                single_match: true,
            },
        },
    ]
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_patch_has_at_least_one_hint() {
        for patch in PATCHES.iter() {
            assert!(!patch.search_hints.is_empty(), "{}", patch.name);
        }
    }

    #[test]
    fn pro_patches_cover_the_five_account_anchors() {
        let pro: Vec<&str> = PATCHES
            .iter()
            .filter(|patch| patch.kind == PatchKind::ProSpoof)
            .map(|patch| patch.search_hints[0])
            .collect();

        assert_eq!(
            pro,
            vec![
                "getUserAccount(",
                "setAccountWandBrandExperience(",
                "setAccountLanguage(",
                "ACTION_SET_ACCOUNT",
                "requestRemoteAuthCode",
            ]
        );
    }

    #[test]
    fn pro_payloads_wrap_rather_than_rebuild() {
        for patch in PATCHES
            .iter()
            .filter(|patch| patch.kind == PatchKind::ProSpoof)
        {
            match &patch.op {
                PatchOp::WrapReturn { wrapper, .. }
                | PatchOp::WrapReducerAccount {
                    template: wrapper, ..
                } => assert!(
                    wrapper.contains("$0") || wrapper.contains("${account}"),
                    "{} must keep the original expression",
                    patch.name
                ),
                PatchOp::ReplaceBody { body, .. } => assert!(!body.is_empty()),
                PatchOp::ReplaceText { .. } => panic!("{} should be structural", patch.name),
            }
        }
    }

    #[test]
    fn hints_are_absent_from_unrelated_bundles() {
        let unrelated = "console.log('hello world');";
        for patch in PATCHES.iter() {
            assert!(
                !patch
                    .search_hints
                    .iter()
                    .any(|hint| unrelated.contains(hint)),
                "{} matches unrelated code",
                patch.name
            );
        }
    }

    #[test]
    fn disable_updates_is_limited_to_the_main_bundle() {
        let patch = PATCHES
            .iter()
            .find(|patch| patch.kind == PatchKind::DisableUpdates)
            .unwrap();
        assert_eq!(patch.candidate_files, &["index.js"]);
    }

    #[test]
    fn disable_updates_regex_matches_once() {
        let PatchOp::ReplaceText { target, .. } = &PATCHES
            .iter()
            .find(|patch| patch.kind == PatchKind::DisableUpdates)
            .unwrap()
            .op
        else {
            panic!("Disable Updates should be a text replacement");
        };

        let js = r#"registerHandler("ACTION_CHECK_FOR_UPDATE",(e=>expectUpdateFeedUrl(e,(e=>{let t=...}))))"#;
        assert!(target.find(js).is_some());
        assert_eq!(target.find_iter(js).count(), 1);
    }
}
