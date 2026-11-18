#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Some(code) = sesame_lib::run_terminal_command() {
        std::process::exit(code);
    }
    sesame_lib::run()
}
