#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use barracuda_ip_intelligence::config::Settings;
use barracuda_ip_intelligence::engine::{AnalysisOptions, analyze};
use barracuda_ip_intelligence::reporting::{write_csv, write_json};
use eframe::egui::{
    self, Align, Button, Color32, FontFamily, FontId, Frame, Label, Layout, ProgressBar, RichText,
    ScrollArea, Stroke, TextEdit, TextWrapMode, Ui, Vec2,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

const BG: Color32 = Color32::from_rgb(8, 13, 13);
const BAR: Color32 = Color32::from_rgb(13, 21, 20);
const PANEL: Color32 = Color32::from_rgb(14, 23, 22);
const FIELD: Color32 = Color32::from_rgb(11, 20, 19);
const BORDER: Color32 = Color32::from_rgb(41, 64, 57);
const TEXT: Color32 = Color32::from_rgb(217, 237, 228);
const MUTED: Color32 = Color32::from_rgb(136, 163, 154);
const ACCENT: Color32 = Color32::from_rgb(157, 224, 110);
const AMBER: Color32 = Color32::from_rgb(233, 184, 109);
const RED: Color32 = Color32::from_rgb(237, 134, 125);

fn mono(text: impl Into<String>, size: f32, color: Color32) -> RichText {
    RichText::new(text)
        .font(FontId::new(size, FontFamily::Monospace))
        .color(color)
}

fn panel() -> Frame {
    Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(6)
        .inner_margin(15)
}

struct BarracudaApp {
    ip: String,
    keyless: bool,
    abuseipdb: bool,
    virustotal: bool,
    shodan: bool,
    greynoise: bool,
    report: Option<Value>,
    output: String,
    receiver: Option<Receiver<Result<Value, String>>>,
    status: String,
    status_color: Color32,
    notice: String,
}

impl BarracudaApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = BG;
        visuals.window_fill = BG;
        visuals.extreme_bg_color = FIELD;
        visuals.widgets.noninteractive.bg_fill = PANEL;
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
        visuals.widgets.inactive.bg_fill = FIELD;
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
        visuals.widgets.hovered.bg_fill = BORDER;
        visuals.widgets.active.bg_fill = BORDER;
        visuals.selection.bg_fill = BORDER;
        cc.egui_ctx.set_visuals(visuals);
        Self {
            ip: "8.8.8.8".to_owned(),
            keyless: true,
            abuseipdb: true,
            virustotal: true,
            shodan: true,
            greynoise: true,
            report: None,
            output: "# HENÜZ ANALİZ YOK\n\nHedef IP adresini girin ve ANALİZ ET düğmesine basın.\nIP profili burada görüntülenecektir.".to_owned(),
            receiver: None,
            status: "HAZIR".to_owned(),
            status_color: ACCENT,
            notice: "Pasif kaynaklar kullanılır. Konum bilgisi yaklaşık değerdir.".to_owned(),
        }
    }

    fn start_analysis(&mut self) {
        let ip = self.ip.trim().to_owned();
        if ip.is_empty() {
            self.notice = "Önce bir IPv4 veya IPv6 adresi girin.".to_owned();
            return;
        }
        if ip.parse::<std::net::IpAddr>().is_err() {
            self.notice = "Geçersiz IP adresi.".to_owned();
            return;
        }
        let mut providers = BTreeSet::new();
        for (selected, name) in [
            (self.abuseipdb, "abuseipdb"),
            (self.virustotal, "virustotal"),
            (self.shodan, "shodan"),
            (self.greynoise, "greynoise"),
        ] {
            if selected {
                providers.insert(name.to_owned());
            }
        }
        let options = AnalysisOptions {
            use_keyless: self.keyless,
            providers,
        };
        let settings = Settings::load();
        let (sender, receiver) = mpsc::channel();
        self.receiver = Some(receiver);
        self.report = None;
        self.status = "SORGULANIYOR".to_owned();
        self.status_color = ACCENT;
        self.output = format!("# PASİF ANALİZ\n\nHedef: {ip}\nKaynaklardan yanıt bekleniyor...");
        self.notice = "Pasif kaynaklar sorgulanıyor...".to_owned();
        thread::spawn(move || {
            let _ = sender.send(analyze(&ip, &settings, &options));
        });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let outcome = self.receiver.as_ref().map(Receiver::try_recv);
        match outcome {
            Some(Ok(Ok(report))) => {
                self.output = serde_json::to_string_pretty(&report).unwrap_or_default();
                self.report = Some(report);
                self.receiver = None;
                self.status = "TAMAMLANDI".to_owned();
                self.status_color = ACCENT;
                self.notice = "Analiz tamamlandı. Kaynak kanıtlarını raporda inceleyin.".to_owned();
            }
            Some(Ok(Err(error))) => {
                self.output = format!("# ANALİZ BAŞARISIZ\n\n{error}");
                self.receiver = None;
                self.status = "HATA".to_owned();
                self.status_color = RED;
                self.notice = error;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.receiver = None;
                self.status = "HATA".to_owned();
                self.status_color = RED;
                self.notice = "Analiz iş parçacığı durdu.".to_owned();
            }
            Some(Err(TryRecvError::Empty)) => {
                ctx.request_repaint_after(Duration::from_millis(100));
            }
            None => {}
        }
    }

    fn save(&mut self, kind: &str) {
        let Some(report) = self.report.as_ref() else {
            self.notice = "Önce bir analiz çalıştırın.".to_owned();
            return;
        };
        let ip = report["target"].as_str().unwrap_or("ip").replace(':', "_");
        let initial = format!("ip-report-{ip}.{kind}");
        let mut dialog = rfd::FileDialog::new()
            .set_file_name(&initial)
            .add_filter(kind, &[kind]);
        if let Some(directory) = report_directory() {
            dialog = dialog.set_directory(directory);
        }
        let Some(path) = dialog.save_file() else {
            return;
        };
        let result = match kind {
            "json" => write_json(report, &path),
            _ => write_csv(report, &path),
        };
        self.notice = match result {
            Ok(()) => format!("Rapor kaydedildi: {}", path.display()),
            Err(error) => format!("Rapor kaydedilemedi: {error}"),
        };
    }

    fn source_row(ui: &mut Ui, name: &str, enabled: &mut bool) {
        ui.horizontal(|ui| {
            ui.label(mono(name, 12.0, TEXT));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let state = if *enabled { "[ ON ]" } else { "[ OFF ]" };
                let color = if *enabled { ACCENT } else { MUTED };
                if ui
                    .add(Button::new(mono(state, 12.0, color)).frame(false))
                    .clicked()
                {
                    *enabled = !*enabled;
                }
            });
        });
    }

    fn profile_row(ui: &mut Ui, name: &str, value: String) {
        ui.horizontal(|ui| {
            ui.label(mono(name, 12.0, MUTED));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(mono(value, 12.0, TEXT));
            });
        });
        ui.separator();
    }

    fn profile_rows(ui: &mut Ui, report: &Value) {
        let shown = |value: &Value| match value {
            Value::Null => "-".to_owned(),
            Value::String(text) if text.is_empty() => "-".to_owned(),
            Value::String(text) => text.clone(),
            _ => value.to_string(),
        };
        let network = &report["network"];
        let geo = &report["geolocation"];
        let asn = if network["asn"].is_null() {
            &geo["asn"]
        } else {
            &network["asn"]
        };
        let country = if geo["country"].is_null() {
            &report["rdap"]["country"]
        } else {
            &geo["country"]
        };
        for (name, value) in [
            ("target", shown(&report["target"])),
            ("ip_version", shown(&report["classification"]["type"])),
            ("global", shown(&report["classification"]["is_global"])),
            ("ptr", shown(&report["reverse_dns"]["hostname"])),
            ("asn", shown(asn)),
            ("prefix", shown(&network["prefix"])),
            ("rir", shown(&network["rir"])),
            ("country", shown(country)),
        ] {
            Self::profile_row(ui, name, value);
        }
    }

    fn risk_panel(&mut self, ui: &mut Ui, height: f32) {
        panel().show(ui, |ui| {
            ui.set_min_height(height);
            ui.horizontal(|ui| {
                ui.label(mono("RISK_ENGINE", 12.0, ACCENT));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(mono("v1", 11.0, MUTED));
                });
            });
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(15.0);
            ui.label(mono("RISK SCORE", 11.0, MUTED));
            let risk = self.report.as_ref().map(|report| &report["risk"]);
            let count = risk
                .and_then(|risk| risk["provider_count"].as_u64())
                .unwrap_or(0);
            let score = risk
                .and_then(|risk| risk["score"].as_u64())
                .unwrap_or(0)
                .min(100);
            let level = if self.report.is_none() {
                "BEKLENİYOR"
            } else if count == 0 {
                "KANIT YOK"
            } else {
                match risk.and_then(|risk| risk["level"].as_str()).unwrap_or("") {
                    "low" => "DÜŞÜK",
                    "medium" => "ORTA",
                    "high" => "YÜKSEK",
                    "critical" => "KRİTİK",
                    _ => "BELİRSİZ",
                }
            };
            let color = if self.report.is_none() {
                MUTED
            } else if count == 0 || (25..50).contains(&score) {
                AMBER
            } else if score >= 50 {
                RED
            } else {
                ACCENT
            };
            ui.horizontal(|ui| {
                ui.label(mono(
                    if self.report.is_none() || count == 0 {
                        "--".to_owned()
                    } else {
                        format!("{score:02}")
                    },
                    35.0,
                    color,
                ));
                ui.label(mono(format!("/ 100 · {level}"), 14.0, color));
            });
            ui.add(
                ProgressBar::new(if count == 0 {
                    0.0
                } else {
                    score as f32 / 100.0
                })
                .fill(color)
                .desired_height(6.0),
            );
            ui.label(mono(
                if self.report.is_none() {
                    "SAĞLAYICI KANITI: --".to_owned()
                } else {
                    format!("SAĞLAYICI KANITI: {count}")
                },
                11.0,
                MUTED,
            ));
            ui.add_space(14.0);
            ui.separator();
            ui.add_space(12.0);
            ui.label(mono("KAYNAK SEÇİMİ", 11.0, MUTED));
            ui.add_space(7.0);
            Self::source_row(ui, "Anahtarsız kaynaklar", &mut self.keyless);
            Self::source_row(ui, "AbuseIPDB", &mut self.abuseipdb);
            Self::source_row(ui, "VirusTotal", &mut self.virustotal);
            Self::source_row(ui, "Shodan", &mut self.shodan);
            Self::source_row(ui, "GreyNoise", &mut self.greynoise);
        });
    }
}

impl eframe::App for BarracudaApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        self.poll(ui.ctx());
        ui.painter().rect_filled(ui.max_rect(), 0, BG);
        Frame::new().fill(BAR).inner_margin(15).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(mono("[ BARRACUDA // IP INTELLIGENCE ]", 14.0, ACCENT).strong());
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(mono(format!("● {}", self.status), 12.0, self.status_color));
                });
            });
        });
        Frame::new().fill(BG).inner_margin(18).show(ui, |ui| {
            panel().show(ui, |ui| {
                ui.label(mono("TARGET / IP ADRESİ", 11.0, ACCENT));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label(mono(">", 16.0, ACCENT));
                    let width = (ui.available_width() - 145.0).max(120.0);
                    let entry = ui.add_sized(
                        [width, 34.0],
                        TextEdit::singleline(&mut self.ip)
                            .font(FontId::new(15.0, FontFamily::Monospace)),
                    );
                    let activate = ui.add_enabled(
                        self.receiver.is_none(),
                        Button::new(mono("ANALİZ ET  →", 13.0, BG).strong())
                            .fill(ACCENT)
                            .min_size(Vec2::new(130.0, 34.0)),
                    );
                    if activate.clicked()
                        || (entry.lost_focus()
                            && ui.input(|input| input.key_pressed(egui::Key::Enter)))
                    {
                        self.start_analysis();
                    }
                });
            });
            ui.add_space(12.0);
            let available = ui.available_size();
            let body_height = (available.y - 54.0).max(300.0);
            let left_width = ((available.x - 12.0) * 0.62).max(250.0);
            ui.horizontal(|ui| {
                ui.allocate_ui_with_layout(
                    Vec2::new(left_width, body_height),
                    Layout::top_down(Align::Min),
                    |ui| {
                        panel().show(ui, |ui| {
                            ui.set_min_height((body_height - 32.0).max(250.0));
                            ui.horizontal(|ui| {
                                ui.label(mono("IP_PROFILE.JSON", 12.0, ACCENT).strong());
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    let target = self
                                        .report
                                        .as_ref()
                                        .and_then(|report| report["target"].as_str())
                                        .unwrap_or("ANALİZ BEKLENİYOR");
                                    ui.label(mono(format!("● {target}"), 11.0, MUTED));
                                });
                            });
                            ui.add_space(9.0);
                            ui.separator();
                            ScrollArea::both()
                                .auto_shrink([false, false])
                                .max_height((body_height - 85.0).max(190.0))
                                .show(ui, |ui| {
                                    if let Some(report) = &self.report {
                                        Self::profile_rows(ui, report);
                                        ui.add_space(13.0);
                                        ui.collapsing(mono("TAM JSON", 11.0, ACCENT), |ui| {
                                            ui.add(
                                                Label::new(mono(&self.output, 12.0, TEXT))
                                                    .wrap_mode(TextWrapMode::Extend),
                                            );
                                        });
                                    } else {
                                        ui.add(
                                            Label::new(mono(&self.output, 12.0, TEXT))
                                                .wrap_mode(TextWrapMode::Extend),
                                        );
                                    }
                                });
                        });
                    },
                );
                ui.add_space(12.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(ui.available_width(), body_height),
                    Layout::top_down(Align::Min),
                    |ui| self.risk_panel(ui, (body_height - 32.0).max(250.0)),
                );
            });
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.label(mono(&self.notice, 11.0, MUTED));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .add(Button::new(mono("↓ CSV", 12.0, TEXT)).fill(FIELD))
                        .clicked()
                    {
                        self.save("csv");
                    }
                    if ui
                        .add(Button::new(mono("↓ JSON", 12.0, TEXT)).fill(FIELD))
                        .clicked()
                    {
                        self.save("json");
                    }
                });
            });
        });
    }
}

fn report_directory() -> Option<PathBuf> {
    let folder = std::env::current_exe().ok()?.parent()?.join("reports");
    folder.is_dir().then_some(folder)
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 690.0])
            .with_min_inner_size([850.0, 590.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Barracuda IP Intelligence",
        options,
        Box::new(|cc| Ok(Box::new(BarracudaApp::new(cc)))),
    )
}
