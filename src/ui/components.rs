use gpui_kit::component::{Theme, v_flex};
use gpui_kit::*;

#[derive(Clone)]
pub struct LogEntry {
    pub message: SharedString,
    pub level: LogLevel,
}

#[derive(Clone)]
pub enum LogLevel {
    Info,
    Success,
    Error,
}

#[derive(IntoElement)]
pub struct LogList {
    entries: Vec<LogEntry>,
    theme: Theme,
}

impl LogList {
    pub fn new(entries: Vec<LogEntry>, theme: Theme) -> Self {
        Self { entries, theme }
    }
}

impl RenderOnce for LogList {
    fn render(self, _window: &mut Window, _cx: &mut App) -> impl IntoElement {
        let t = &self.theme;
        v_flex()
            .gap_1()
            .children(self.entries.into_iter().map(|entry| {
                let color = match entry.level {
                    LogLevel::Info => t.foreground,
                    LogLevel::Success => t.green,
                    LogLevel::Error => t.red,
                };
                div().text_size(px(13.)).font_family("Consolas").text_color(color).child(entry.message)
            }))
    }
}
