use tauri::Manager;
use tauri_plugin_shell::ShellExt;
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use std::sync::Mutex;

struct AgentChild(Mutex<Option<CommandChild>>);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .plugin(tauri_plugin_shell::init())
    .manage(AgentChild(Mutex::new(None)))
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }

      // Spawn the bundled agent sidecar so the dashboard can talk to 127.0.0.1:7878.
      match app.shell().sidecar("bastion-agent") {
        Ok(cmd) => match cmd.spawn() {
          Ok((mut rx, child)) => {
            log::info!("bastion-agent sidecar spawned (pid {})", child.pid());
            app.state::<AgentChild>().0.lock().unwrap().replace(child);
            tauri::async_runtime::spawn(async move {
              while let Some(ev) = rx.recv().await {
                match ev {
                  CommandEvent::Stdout(b) => log::info!("agent: {}", String::from_utf8_lossy(&b)),
                  CommandEvent::Stderr(b) => log::warn!("agent[err]: {}", String::from_utf8_lossy(&b)),
                  CommandEvent::Terminated(p) => { log::warn!("agent terminated: {:?}", p); break; }
                  _ => {}
                }
              }
            });
          }
          Err(e) => log::error!("failed to spawn bastion-agent sidecar: {e}"),
        },
        Err(e) => log::error!("sidecar lookup failed: {e}"),
      }

      Ok(())
    })
    .on_window_event(|window, event| {
      if let tauri::WindowEvent::Destroyed = event {
        if let Some(child) = window.app_handle().state::<AgentChild>().0.lock().unwrap().take() {
          let _ = child.kill();
        }
      }
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
