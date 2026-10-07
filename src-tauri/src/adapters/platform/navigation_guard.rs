use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};
use url::Url;

pub(crate) fn plugin<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("sesame-navigation-guard")
        .on_navigation(|webview, url| {
            let development_url = if cfg!(debug_assertions) {
                webview.config().build.dev_url.as_ref()
            } else {
                None
            };
            is_app_url(url, cfg!(windows), development_url)
        })
        .build()
}

fn is_app_url(url: &Url, windows: bool, development_url: Option<&Url>) -> bool {
    let (scheme, host) = if windows {
        ("http", "tauri.localhost")
    } else {
        ("tauri", "localhost")
    };
    has_origin(url, scheme, host, None)
        || development_url.is_some_and(|development| {
            development.host_str().is_some_and(|development_host| {
                has_origin(
                    url,
                    development.scheme(),
                    development_host,
                    development.port(),
                )
            })
        })
}

fn has_origin(url: &Url, scheme: &str, host: &str, port: Option<u16>) -> bool {
    url.scheme() == scheme
        && url.host_str() == Some(host)
        && url.port() == port
        && url.username().is_empty()
        && url.password().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: &str) -> Url {
        Url::parse(value).unwrap()
    }

    fn development() -> Url {
        parse("http://localhost:5173")
    }

    #[test]
    fn the_app_pages_are_allowed_on_linux() {
        for page in [
            "tauri://localhost",
            "tauri://localhost/",
            "tauri://localhost/index.html",
            "tauri://localhost/quick-access.html",
            "tauri://localhost/index.html?view=vault#top",
        ] {
            assert!(is_app_url(&parse(page), false, None), "{page}");
        }
    }

    #[test]
    fn the_app_pages_are_allowed_on_windows() {
        for page in [
            "http://tauri.localhost",
            "http://tauri.localhost/",
            "http://tauri.localhost/index.html",
            "http://tauri.localhost/quick-access.html",
            "http://TAURI.localhost/index.html",
        ] {
            assert!(is_app_url(&parse(page), true, None), "{page}");
        }
    }

    #[test]
    fn each_platform_allows_only_its_own_app_origin() {
        assert!(!is_app_url(&parse("http://tauri.localhost/"), false, None));
        assert!(!is_app_url(&parse("tauri://localhost/"), true, None));
        assert!(!is_app_url(&parse("https://tauri.localhost/"), true, None));
    }

    #[test]
    fn remote_pages_are_refused_on_both_platforms() {
        for target in [
            "https://phish.example/",
            "http://phish.example/",
            "https://example.com/tauri.localhost",
            "ftp://phish.example/",
            "ws://phish.example/",
        ] {
            for windows in [false, true] {
                assert!(
                    !is_app_url(&parse(target), windows, None),
                    "{target} on windows={windows}"
                );
            }
        }
    }

    #[test]
    fn look_alike_hosts_credentials_and_ports_are_refused() {
        for target in [
            "tauri://localhost.phish.example/",
            "tauri://localhost@phish.example/",
            "tauri://localhost:phish@phish.example/",
            "tauri://user@localhost/",
            "tauri://:secret@localhost/",
            "tauri://localhost:8080/",
            "tauri://localhost./",
            "tauri://phish.localhost/",
            "tauri://LOCALHOST/",
        ] {
            assert!(!is_app_url(&parse(target), false, None), "{target}");
        }
        for target in [
            "http://tauri.localhost.phish.example/",
            "http://tauri.localhost@phish.example/",
            "http://user:secret@tauri.localhost/",
            "http://:secret@tauri.localhost/",
            "http://tauri.localhost:8080/",
            "http://tauri.localhost./",
            "http://phish.tauri.localhost/",
            "http://ipc.localhost/",
            "http://asset.localhost/",
        ] {
            assert!(!is_app_url(&parse(target), true, None), "{target}");
        }
    }

    #[test]
    fn local_documents_and_script_urls_are_refused() {
        for target in [
            "file:///etc/passwd",
            "file://localhost/etc/passwd",
            "about:blank",
            "javascript:alert(1)",
            "data:text/html,<p>phish</p>",
            "blob:tauri://localhost/00000000-0000-0000-0000-000000000000",
            "asset://localhost/etc/passwd",
            "ipc://localhost/vault",
        ] {
            for windows in [false, true] {
                assert!(
                    !is_app_url(&parse(target), windows, None),
                    "{target} on windows={windows}"
                );
            }
        }
    }

    #[test]
    fn the_development_server_is_allowed_only_when_one_is_passed() {
        let server = development();
        for page in [
            "http://localhost:5173",
            "http://localhost:5173/",
            "http://localhost:5173/index.html",
            "http://localhost:5173/quick-access.html?t=1",
        ] {
            assert!(is_app_url(&parse(page), false, Some(&server)), "{page}");
            assert!(!is_app_url(&parse(page), false, None), "{page}");
        }
    }

    #[test]
    fn the_development_server_allowance_is_exact() {
        let server = development();
        for target in [
            "http://localhost:5174/",
            "http://localhost/",
            "https://localhost:5173/",
            "http://127.0.0.1:5173/",
            "http://localhost.phish.example:5173/",
            "http://user@localhost:5173/",
            "ws://localhost:5173/",
        ] {
            assert!(
                !is_app_url(&parse(target), false, Some(&server)),
                "{target}"
            );
        }
    }

    #[test]
    fn a_development_url_without_a_host_allows_nothing_extra() {
        let server = parse("data:text/plain,development");
        assert!(!is_app_url(
            &parse("data:text/plain,development"),
            false,
            Some(&server)
        ));
        assert!(!is_app_url(
            &parse("https://phish.example/"),
            false,
            Some(&server)
        ));
    }
}
