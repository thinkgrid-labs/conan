use conan_core::{event::EventPayload, registry::Registry, traits::Ingestor};
use conan_os::CodebaseIngestor;

fn empty_registry() -> Registry {
    Registry::new()
}

fn ingestor(dir: &std::path::Path) -> CodebaseIngestor {
    CodebaseIngestor::new(empty_registry(), dir.to_path_buf())
}

// ── detects known key patterns ────────────────────────────────────────────────

#[tokio::test]
async fn detects_openai_key_in_js_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.js"),
        "const API_KEY = 'sk-abcdefghijklmnopqrstu';\n",
    )
    .unwrap();

    let events = ingestor(dir.path()).ingest().await.unwrap();
    assert!(events.iter().any(|e| {
        matches!(&e.payload, EventPayload::CodebaseFile { matched_text, .. }
            if matched_text == "openai_key")
    }));
}

#[tokio::test]
async fn detects_anthropic_key_in_python_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("client.py"),
        "client = Anthropic(api_key='sk-ant-api01-abcdefghijklmnopqrstu')\n",
    )
    .unwrap();

    let events = ingestor(dir.path()).ingest().await.unwrap();
    assert!(events.iter().any(|e| {
        matches!(&e.payload, EventPayload::CodebaseFile { matched_text, .. }
            if matched_text == "anthropic_key")
    }));
}

#[tokio::test]
async fn detects_huggingface_key_in_py_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("model.py"),
        "token = 'hf_ABCDEFGHIJKLMNOPQRSTUvwxyz'\n",
    )
    .unwrap();

    let events = ingestor(dir.path()).ingest().await.unwrap();
    assert!(events.iter().any(|e| {
        matches!(&e.payload, EventPayload::CodebaseFile { matched_text, .. }
            if matched_text == "huggingface_key")
    }));
}

#[tokio::test]
async fn detects_generic_api_key_pattern() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("settings.py"),
        r#"API_KEY = "supersecretkey1234567890abcdef""#,
    )
    .unwrap();

    let events = ingestor(dir.path()).ingest().await.unwrap();
    assert!(!events.is_empty(), "expected generic_api_key to match");
}

// ── clean files produce no findings ──────────────────────────────────────────

#[tokio::test]
async fn no_findings_in_clean_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("math.py"),
        "def add(a, b):\n    return a + b\n",
    )
    .unwrap();

    assert!(ingestor(dir.path()).ingest().await.unwrap().is_empty());
}

// ── skip rules ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ignores_target_directory() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(
        target.join("build.rs"),
        "let key = 'sk-abcdefghijklmnopqrstu';\n",
    )
    .unwrap();

    assert!(
        ingestor(dir.path()).ingest().await.unwrap().is_empty(),
        "target/ should be skipped"
    );
}

#[tokio::test]
async fn ignores_git_directory() {
    let dir = tempfile::tempdir().unwrap();
    let git = dir.path().join(".git");
    std::fs::create_dir(&git).unwrap();
    std::fs::write(
        git.join("config"),
        "sk-abcdefghijklmnopqrstu\n",
    )
    .unwrap();

    assert!(
        ingestor(dir.path()).ingest().await.unwrap().is_empty(),
        ".git/ should be skipped"
    );
}

#[tokio::test]
async fn ignores_node_modules_directory() {
    let dir = tempfile::tempdir().unwrap();
    let nm = dir.path().join("node_modules");
    std::fs::create_dir(&nm).unwrap();
    std::fs::write(
        nm.join("pkg.js"),
        "const k = 'sk-abcdefghijklmnopqrstu';",
    )
    .unwrap();

    assert!(
        ingestor(dir.path()).ingest().await.unwrap().is_empty(),
        "node_modules/ should be skipped"
    );
}

#[tokio::test]
async fn ignores_unknown_file_extensions() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("data.bin"),
        "sk-abcdefghijklmnopqrstuvwxyz1234567890\n",
    )
    .unwrap();

    assert!(
        ingestor(dir.path()).ingest().await.unwrap().is_empty(),
        ".bin files should be skipped"
    );
}

// ── metadata correctness ──────────────────────────────────────────────────────

#[tokio::test]
async fn reports_correct_line_number() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("app.ts"),
        "// line 1\nconst key = 'sk-abcdefghijklmnopqrstu';\n",
    )
    .unwrap();

    let events = ingestor(dir.path()).ingest().await.unwrap();
    assert_eq!(events.len(), 1);
    if let EventPayload::CodebaseFile { line_number, .. } = &events[0].payload {
        assert_eq!(*line_number, Some(2));
    } else {
        panic!("expected CodebaseFile payload");
    }
}

#[tokio::test]
async fn scans_multiple_supported_extensions() {
    let dir = tempfile::tempdir().unwrap();
    for ext in &["js", "ts", "py", "go", "rs"] {
        std::fs::write(
            dir.path().join(format!("file.{ext}")),
            "const k = 'sk-abcdefghijklmnopqrstu';\n",
        )
        .unwrap();
    }

    let events = ingestor(dir.path()).ingest().await.unwrap();
    assert_eq!(events.len(), 5, "expected one finding per file");
}
