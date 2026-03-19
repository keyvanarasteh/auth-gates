use crate::models::FinalReport;
use std::fs::File;
use std::io::Write;
use chrono::Utc;

pub fn generate_dashboard(report: &FinalReport, output_path: &str) -> Result<(), std::io::Error> {
    let mut html = String::from("<html><head><meta charset='UTF-8'><title>Auth-Gates Security Scan Dashboard</title>");
    html.push_str("<style>");
    html.push_str("body { font-family: 'Inter', sans-serif; background-color: #0f172a; color: #f8fafc; margin: 40px; padding: 20px; }");
    html.push_str(".card { background: #1e293b; padding: 20px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1); margin-bottom: 30px; }");
    html.push_str("h1, h2, h3 { color: #38bdf8; }");
    html.push_str("table { width: 100%; border-collapse: collapse; margin-top: 20px; }");
    html.push_str("th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; }");
    html.push_str("th { background-color: #0f172a; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 0.85rem; }");
    html.push_str(".metric { font-size: 2rem; font-weight: bold; color: #10b981; }");
    html.push_str(".error { color: #ef4444; }");
    html.push_str(".stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }");
    html.push_str(".stat-box { background: #0f172a; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #334155; }");
    html.push_str(".stat-label { color: #94a3b8; font-size: 0.9rem; margin-bottom: 5px; }");
    html.push_str(".badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }");
    html.push_str(".badge-success { background: #064e3b; color: #34d399; }");
    html.push_str(".badge-warning { background: #78350f; color: #fbbf24; }");
    html.push_str(".badge-error { background: #7f1d1d; color: #f87171; }");
    html.push_str("</style></head><body>");

    html.push_str("<h1>🛡️ Auth-Gates Security Dashboard</h1>");
    html.push_str(&format!("<p>Generated at: {}</p>", Utc::now().to_rfc3339()));
    
    // Overview Card
    html.push_str("<div class='card'>");
    html.push_str("<h2>Execution Overview</h2>");
    html.push_str("<div class='stats-grid'>");
    html.push_str(&format!("<div class='stat-box'><div class='stat-label'>Target</div><div style='font-size:1.2rem; margin-top:10px;'>{}</div></div>", report.target_name));
    html.push_str(&format!("<div class='stat-box'><div class='stat-label'>URL</div><div style='font-size:1rem; margin-top:10px; word-break: break-all;'>{}</div></div>", report.target_url));
    html.push_str(&format!("<div class='stat-box'><div class='stat-label'>Total Requests</div><div class='metric'>{}</div></div>", report.total_requests));
    
    let rate_limit_html = if report.rate_limited {
        let text = format!("YES (at #{})", report.first_429_at.unwrap_or(0));
        format!("<div class='stat-box'><div class='stat-label'>Rate Limited</div><div class='metric error'>{}</div></div>", text)
    } else {
        "<div class='stat-box'><div class='stat-label'>Rate Limited</div><div class='metric'>NO</div></div>".to_string()
    };
    html.push_str(&rate_limit_html);
    
    let avg_latency = if report.latency_samples.is_empty() { 0.0 } else { report.latency_samples.iter().sum::<f64>() / report.latency_samples.len() as f64 };
    html.push_str(&format!("<div class='stat-box'><div class='stat-label'>Avg Latency (ms)</div><div class='metric'>{}</div></div>", avg_latency.round()));
    html.push_str("</div></div>");

    // Status Breakdown
    html.push_str("<div class='card'>");
    html.push_str("<h2>HTTP Status Breakdown</h2>");
    if report.status_breakdown.is_empty() {
        html.push_str("<p>No requests were made.</p>");
    } else {
        html.push_str("<table><tr><th>Status Code</th><th>Count</th></tr>");
        let mut codes: Vec<_> = report.status_breakdown.keys().collect();
        codes.sort();
        for code in codes {
            let count = report.status_breakdown.get(code).unwrap();
            let cls = match *code {
                200..=299 => "badge-success",
                300..=399 => "badge-warning",
                _ => "badge-error",
            };
            html.push_str(&format!("<tr><td><span class='badge {}'>{}</span></td><td>{}</td></tr>", cls, code, count));
        }
        html.push_str("</table>");
    }
    html.push_str("</div>");

    // Security Headers
    if !report.security_headers.is_empty() {
        html.push_str("<div class='card'>");
        html.push_str("<h2>Important Response Headers</h2>");
        html.push_str("<table><tr><th>Header</th><th>Value</th></tr>");
        for (k, v) in &report.security_headers {
            html.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>", k, v));
        }
        html.push_str("</table></div>");
    }
    
    // API Endpoints
    if let Some(endpoints) = &report.api_endpoints {
        html.push_str("<div class='card'>");
        html.push_str("<h2>API Fuzzer Discovery</h2>");
        if endpoints.is_empty() {
            html.push_str("<p>No endpoints discovered.</p>");
        } else {
            html.push_str("<table><tr><th>Path</th><th>Status</th><th>Classification</th></tr>");
            for ep in endpoints {
                let badge_cls = match ep.classification {
                    crate::fuzzer::EndpointClassification::Public => "badge-success",
                    crate::fuzzer::EndpointClassification::Protected => "badge-warning",
                    _ => "badge-error",
                };
                html.push_str(&format!("<tr><td>{}</td><td>{}</td><td><span class='badge {}'>{:?}</span></td></tr>", ep.url, ep.status, badge_cls, ep.classification));
            }
            html.push_str("</table>");
        }
        html.push_str("</div>");
    }
    
    // WS Endpoints
    if let Some(websockets) = &report.ws_endpoints {
        html.push_str("<div class='card'>");
        html.push_str("<h2>WebSocket Auto-Discovery</h2>");
        if websockets.is_empty() {
            html.push_str("<p>No websockets tested/discovered.</p>");
        } else {
            html.push_str("<table><tr><th>URL</th><th>Status</th><th>Message</th></tr>");
            for ws in websockets {
                let badge_cls = if ws.is_open { "badge-success" } else { "badge-error" };
                let status_str = if ws.is_open { "OPEN" } else { "CLOSED/AUTH" };
                html.push_str(&format!("<tr><td>{}</td><td><span class='badge {}'>{}</span></td><td>{}</td></tr>", ws.url, badge_cls, status_str, ws.message));
            }
            html.push_str("</table>");
        }
        html.push_str("</div>");
    }

    html.push_str("</body></html>");

    let mut file = File::create(output_path)?;
    file.write_all(html.as_bytes())?;
    Ok(())
}
