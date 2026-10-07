pub mod components;

use crate::detector::{WandInstallation, detect_wand};
use crate::orchestrator::{self, PatchConfig};
use crate::ui::components::*;
use gpui_kit::component::{
    ActiveTheme as _, Disableable, Root, Theme, ThemeMode,
    button::{Button, ButtonVariants},
    checkbox::Checkbox,
    h_flex, init,
    scroll::ScrollableElement,
    v_flex,
};
use gpui_kit::*;
use std::sync::mpsc;

type AppResult = Result<orchestrator::PatchStats, crate::error::YouModError>;

struct MainWindow {
    install: Option<WandInstallation>,
    pro_checked: bool,
    updates_checked: bool,
    running: bool,
    patched: bool,
    cleaning_old: bool,
    old_version_count: usize,
    logs: Vec<LogEntry>,
    result_rx: Option<mpsc::Receiver<AppResult>>,
    pending_action: Option<&'static str>,
    cleanup_rx: Option<mpsc::Receiver<Result<orchestrator::CleanupStats, crate::error::YouModError>>>,
}

impl MainWindow {
    fn push_log(&mut self, message: &str, level: LogLevel) {
        self.logs.push(LogEntry {
            message: message.into(),
            level,
        });
    }
}

impl Render for MainWindow {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let has_install = self.install.is_some();
        let running = self.running || self.cleaning_old;
        let patched = self.patched;
        let has_selection = self.pro_checked || self.updates_checked;
        let has_old_versions = self.old_version_count > 0;
        let t = cx.theme().clone();

        if let Some(ref rx) = self.result_rx
            && let Ok(result) = rx.try_recv()
        {
            match result {
                Ok(stats) => match self.pending_action {
                    Some("apply") => {
                        for name in &stats.applied {
                            self.push_log(&format!("已施: {}", name), LogLevel::Success);
                        }
                        for name in &stats.failed {
                            self.push_log(&format!("败: {}", name), LogLevel::Error);
                        }
                        if stats.failed.is_empty() {
                            self.push_log("补丁施毕", LogLevel::Success);
                        }
                        self.patched = true;
                    }
                    Some("restore") => {
                        self.push_log("已复旧观", LogLevel::Success);
                        self.patched = false;
                    }
                    _ => {}
                },
                Err(e) => self.push_log(&format!("谬误: {}", e), LogLevel::Error),
            }
            self.result_rx = None;
            self.running = false;
            self.pending_action = None;
            cx.notify();
        }

        if let Some(ref rx) = self.cleanup_rx
            && let Ok(result) = rx.try_recv()
        {
            match result {
                Ok(stats) => {
                    for name in &stats.deleted {
                        self.push_log(&format!("已删旧版: {}", name), LogLevel::Success);
                    }
                    self.old_version_count = crate::detector::find_old_installations().len();
                }
                Err(e) => self.push_log(&format!("删旧版谬误: {}", e), LogLevel::Error),
            }
            self.cleanup_rx = None;
            self.cleaning_old = false;
            cx.notify();
        }

        v_flex()
            .size_full()
            .child(
                h_flex()
                    .w_full()
                    .px_4()
                    .pt_4()
                    .pb_2()
                    .justify_between()
                    .items_center()
                    .child(
                        div()
                            .font_weight(FontWeight::BOLD)
                            .text_size(px(18.))
                            .child("YouMod"),
                    )
                    .child(
                        div()
                            .text_size(px(13.))
                            .text_color(t.muted_foreground)
                            .child("解 Wand 会员之锢"),
                    ),
            )
            .child(
                div()
                    .w_full()
                    .mx_4()
                    .mb_3()
                    .px_3()
                    .py_2()
                    .rounded(t.radius)
                    .child(match &self.install {
                        Some(inst) => {
                            let ver = inst
                                .root_dir
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default();
                            h_flex().justify_between().items_center().child(
                                h_flex()
                                    .gap_2()
                                    .items_center()
                                    .child(
                                        div()
                                            .text_size(px(14.))
                                            .text_color(if patched {
                                                t.green
                                            } else {
                                                t.muted_foreground
                                            })
                                            .child(if patched {
                                                "● 已破"
                                            } else {
                                                "○ 未破"
                                            }),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(13.))
                                            .text_color(t.muted_foreground)
                                            .child(ver),
                                    ),
                            )
                        }
                        None => div()
                            .text_color(t.red)
                            .text_size(px(14.))
                            .child("未觅得 Wand/WeMod 之迹"),
                    }),
            )
            .child(
                div()
                    .w_full()
                    .mx_4()
                    .mb_3()
                    .px_3()
                    .py_2()
                    .rounded(t.radius)
                    .child(
                        v_flex()
                            .gap_1()
                            .child(
                                div()
                                    .text_color(t.muted_foreground)
                                    .text_size(px(13.))
                                    .pb_1()
                                    .child("补丁之选"),
                            )
                            .child(
                                Checkbox::new("pro-check")
                                    .checked(self.pro_checked)
                                    .label("启 Pro 之权")
                                    .on_click(cx.listener(|this, _: &bool, _window, _cx| {
                                        this.pro_checked = !this.pro_checked
                                    })),
                            )
                            .child(
                                Checkbox::new("updates-check")
                                    .checked(self.updates_checked)
                                    .label("绝更新之路")
                                    .on_click(cx.listener(|this, _: &bool, _window, _cx| {
                                        this.updates_checked = !this.updates_checked
                                    })),
                            ),
                    ),
            )
            .child(
                h_flex()
                    .w_full()
                    .mx_4()
                    .mb_3()
                    .gap_2()
                    .child(
                        Button::new("apply-btn")
                            .label("施补丁")
                            .primary()
                            .disabled(!has_install || running || patched || !has_selection)
                            .on_click(cx.listener(|this, _event: &ClickEvent, _window, cx| {
                                let install = this.install.clone();
                                if let Some(ref install) = install
                                    && !this.running
                                {
                                    let config = PatchConfig {
                                        pro: this.pro_checked,
                                        disable_updates: this.updates_checked,
                                    };
                                    this.running = true;
                                    this.pending_action = Some("apply");
                                    this.push_log("正施补丁…", LogLevel::Info);
                                    let install = install.clone();
                                    let (tx, rx) = mpsc::channel();
                                    this.result_rx = Some(rx);
                                    std::thread::spawn(move || {
                                        let _ =
                                            tx.send(orchestrator::apply_patches(&install, &config));
                                    });
                                    cx.notify();
                                }
                            })),
                    )
                    .child(
                        Button::new("restore-btn")
                            .label("复旧观")
                            .outline()
                            .disabled(!has_install || running || !patched)
                            .on_click(cx.listener(|this, _event: &ClickEvent, _window, cx| {
                                let install = this.install.clone();
                                if let Some(ref install) = install
                                    && !this.running
                                {
                                    this.running = true;
                                    this.pending_action = Some("restore");
                                    this.push_log("正复旧观…", LogLevel::Info);
                                    let install = install.clone();
                                    let (tx, rx) = mpsc::channel();
                                    this.result_rx = Some(rx);
                                    std::thread::spawn(move || {
                                        let _ =
                                            tx.send(orchestrator::restore(&install).map(|_| {
                                                orchestrator::PatchStats {
                                                    applied: vec![],
                                                    failed: vec![],
                                                }
                                            }));
                                    });
                                    cx.notify();
                                }
                            })),
                    )
                    .child(
                        Button::new("cleanup-btn")
                            .label({
                                if has_old_versions {
                                    format!("删旧版({})", self.old_version_count)
                                } else {
                                    "删旧版".to_string()
                                }
                            })
                            .danger()
                            .disabled(!has_install || running || !has_old_versions)
                            .on_click(cx.listener(|this, _event: &ClickEvent, _window, cx| {
                                if !this.running
                                    && !this.cleaning_old
                                    && this.old_version_count > 0
                                {
                                    this.cleaning_old = true;
                                    this.push_log("正清理旧版本…", LogLevel::Info);
                                    let (tx, rx) = mpsc::channel();
                                    this.cleanup_rx = Some(rx);
                                    std::thread::spawn(move || {
                                        let _ = tx.send(orchestrator::delete_old_versions());
                                    });
                                    cx.notify();
                                }
                            })),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .w_full()
                    .mx_4()
                    .mb_4()
                    .overflow_hidden()
                    .child(
                        div()
                            .h_full()
                            .px_3()
                            .py_2()
                            .rounded(t.radius)
                            .bg(t.background)
                            .overflow_y_scrollbar()
                            .child(LogList::new(self.logs.clone(), t.clone())),
                    ),
            )
    }
}

pub fn run_app() {
    let app = gpui_kit::application().with_assets(gpui_kit::assets::Assets);
    app.run(move |cx| {
        init(cx);
        Theme::change(ThemeMode::Dark, None, cx);
        let window_options = WindowOptions {
            titlebar: Some(TitlebarOptions {
                title: Some("YouMod — 解 Wand 会员之锢".into()),
                ..Default::default()
            }),
            window_bounds: Some(WindowBounds::centered(size(px(480.), px(420.)), cx)),
            window_min_size: Some(size(px(480.), px(420.))),
            is_resizable: false,
            ..Default::default()
        };
        cx.spawn(async move |cx| {
            cx.open_window(window_options, |window, cx| {
                let install = detect_wand().ok();
                let mut logs = Vec::new();
                let mut patched = false;
                let old_version_count = crate::detector::find_old_installations().len();
                if let Some(ref inst) = install {
                    patched = orchestrator::is_patched(inst);
                    logs.push(LogEntry {
                        message: format!("已察 Wand 之所在: {}", inst.root_dir.display()).into(),
                        level: LogLevel::Info,
                    });
                }
                let view = cx.new(|_cx| MainWindow {
                    install,
                    pro_checked: true,
                    updates_checked: false,
                    running: false,
                    patched,
                    cleaning_old: false,
                    old_version_count,
                    logs,
                    result_rx: None,
                    pending_action: None,
                    cleanup_rx: None,
                });
                cx.new(|cx| Root::new(view, window, cx))
            })
            .expect("Failed to open window");
        })
        .detach();
    });
}
