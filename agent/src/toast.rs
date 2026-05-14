// Windows toast notifications.
//
// Uses the legacy WSH-style approach via PowerShell so we don't need
// any extra crate or COM/WinRT setup. Toast appears in Action Center
// and stays in history. Title is "BASTION" plus severity uppercase;
// body is the event summary.
//
// Best-effort: failures are logged at debug level and never propagate.
// Throttled per-call by the caller (notifier).

use anyhow::Result;
use tokio::process::Command;

const APP_ID: &str = "BASTION";

/// Show a Windows 10/11 toast. Severity controls the icon/category.
pub async fn show(title: &str, body: &str) -> Result<()> {
    // PowerShell snippet: register the AppUserModelID then push a toast.
    // Single-quoted heredoc-ish script with placeholders we substitute via -EncodedCommand
    // to dodge quoting hell entirely.
    let xml = format!(
        r#"<toast><visual><binding template="ToastGeneric"><text>{}</text><text>{}</text></binding></visual></toast>"#,
        xml_escape(title),
        xml_escape(body),
    );

    let script = format!(
        r#"
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime] | Out-Null
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml(@'
{xml}
'@)
$t = New-Object Windows.UI.Notifications.ToastNotification $x
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{APP_ID}').Show($t)
"#,
        xml = xml,
        APP_ID = APP_ID,
    );

    // -EncodedCommand sidesteps quoting; it expects UTF-16 LE base64.
    let utf16: Vec<u16> = script.encode_utf16().collect();
    let mut bytes = Vec::with_capacity(utf16.len() * 2);
    for u in utf16 {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &b64])
        .output()
        .await?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("toast failed: {}", stderr.trim());
    }
    Ok(())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
