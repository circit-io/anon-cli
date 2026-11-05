use anon_cli::pdf_adapter::{sanitize_pdf, PdfReport};
use anon_cli::policy::Policy;
use lopdf::{Dictionary, Document, Object, Stream, StringFormat};
use std::path::PathBuf;

fn load_policy() -> Policy {
    let path = format!(
        "{}/tests/fixtures/policy_valid.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    Policy::from_yaml(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn new_doc() -> (Document, lopdf::ObjectId, lopdf::ObjectId, lopdf::ObjectId) {
    let mut doc = Document::with_version("1.7");
    let page = Dictionary::from_iter(vec![("Type".to_string(), Object::Name(b"Page".to_vec()))]);
    let page_id = doc.add_object(Object::Dictionary(page));
    let pages = Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Pages".to_vec())),
        (
            "Kids".to_string(),
            Object::Array(vec![Object::Reference(page_id)]),
        ),
        ("Count".to_string(), Object::Integer(1)),
    ]);
    let pages_id = doc.add_object(Object::Dictionary(pages));
    let catalog = Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Catalog".to_vec())),
        ("Pages".to_string(), Object::Reference(pages_id)),
    ]);
    let catalog_id = doc.add_object(Object::Dictionary(catalog));
    doc.trailer.set("Root", Object::Reference(catalog_id));
    (doc, catalog_id, pages_id, page_id)
}

fn get_dict(doc: &mut Document, id: lopdf::ObjectId) -> &mut Dictionary {
    doc.objects.get_mut(&id).unwrap().as_dict_mut().unwrap()
}

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(name)
}

fn raw_bytes(path: &PathBuf) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn removes_javascript() {
    let (mut doc, catalog_id, _, _) = new_doc();
    let js = Stream::new(Dictionary::new(), b"app.alert('x');".to_vec());
    let js_id = doc.add_object(Object::Stream(js));
    let names = Dictionary::from_iter(vec![(
        "JavaScript".to_string(),
        Object::Dictionary(Dictionary::from_iter(vec![(
            "Names".to_string(),
            Object::Array(vec![
                Object::String(b"evil".to_vec(), StringFormat::Literal),
                Object::Reference(js_id),
            ]),
        )])),
    )]);
    get_dict(&mut doc, catalog_id).set("Names", Object::Dictionary(names));

    let input = tmp("anon-pdf-js.pdf");
    doc.save(&input).unwrap();
    let output = tmp("anon-pdf-js-out.pdf");
    let report: PdfReport = sanitize_pdf(&input, &output, &load_policy()).unwrap();

    assert!(!report.quarantined);
    assert!(report.objects_removed > 0, "expected removed objects");

    let bytes = raw_bytes(&output);
    assert!(
        !contains(&bytes, b"JavaScript"),
        "JS name tree must be gone"
    );
    assert!(!contains(&bytes, b"app.alert"), "JS stream must be gone");
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&output).ok();
}

#[test]
fn scrubs_metadata_and_annotations() {
    let (mut doc, _, _, page_id) = new_doc();
    let annot = Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Annot".to_vec())),
        ("Subtype".to_string(), Object::Name(b"Link".to_vec())),
    ]);
    let annot_id = doc.add_object(Object::Dictionary(annot));
    get_dict(&mut doc, page_id).set("Annots", Object::Array(vec![Object::Reference(annot_id)]));

    doc.trailer.set(
        "Info",
        Object::Dictionary(Dictionary::from_iter(vec![
            (
                "Title".to_string(),
                Object::String(b"Secret Title".to_vec(), StringFormat::Literal),
            ),
            (
                "Author".to_string(),
                Object::String(b"Jane Doe".to_vec(), StringFormat::Literal),
            ),
        ])),
    );

    let input = tmp("anon-pdf-meta.pdf");
    doc.save(&input).unwrap();
    let output = tmp("anon-pdf-meta-out.pdf");
    let report = sanitize_pdf(&input, &output, &load_policy()).unwrap();

    assert!(!report.quarantined);
    assert!(report.metadata_scrubbed);

    let bytes = raw_bytes(&output);
    assert!(!contains(&bytes, b"Secret Title"));
    assert!(!contains(&bytes, b"Jane Doe"));
    assert!(!contains(&bytes, b"Annot"), "annotation dict must be gone");
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&output).ok();
}

#[test]
fn removes_embedded_files() {
    let (mut doc, catalog_id, _, _) = new_doc();
    let ef = Stream::new(Dictionary::new(), b"payload".to_vec());
    let ef_id = doc.add_object(Object::Stream(ef));
    let filespec = Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Filespec".to_vec())),
        (
            "F".to_string(),
            Object::String(b"evil.bin".to_vec(), StringFormat::Literal),
        ),
        (
            "EF".to_string(),
            Object::Dictionary(Dictionary::from_iter(vec![(
                "F".to_string(),
                Object::Reference(ef_id),
            )])),
        ),
    ]);
    let fs_id = doc.add_object(Object::Dictionary(filespec));
    let names = Dictionary::from_iter(vec![(
        "EmbeddedFiles".to_string(),
        Object::Dictionary(Dictionary::from_iter(vec![(
            "Names".to_string(),
            Object::Array(vec![
                Object::String(b"f".to_vec(), StringFormat::Literal),
                Object::Reference(fs_id),
            ]),
        )])),
    )]);
    get_dict(&mut doc, catalog_id).set("Names", Object::Dictionary(names));
    get_dict(&mut doc, catalog_id).set("AF", Object::Array(vec![Object::Reference(fs_id)]));

    let input = tmp("anon-pdf-ef.pdf");
    doc.save(&input).unwrap();
    let output = tmp("anon-pdf-ef-out.pdf");
    let report = sanitize_pdf(&input, &output, &load_policy()).unwrap();
    assert!(!report.quarantined);

    let bytes = raw_bytes(&output);
    assert!(!contains(&bytes, b"EmbeddedFiles"));
    assert!(!contains(&bytes, b"evil.bin"));
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&output).ok();
}

#[test]
fn malformed_pdf_quarantined_not_error() {
    let input = tmp("anon-pdf-broken.pdf");
    std::fs::write(&input, b"%PDF-1.7 not a real pdf body").unwrap();
    let output = tmp("anon-pdf-broken-out.pdf");
    let report = sanitize_pdf(&input, &output, &load_policy()).unwrap();

    assert!(report.quarantined);
    assert!(report.quarantine_reason.is_some());
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&output).ok();
}

#[test]
fn encrypted_pdf_quarantined() {
    let (mut doc, _, _, _) = new_doc();
    doc.trailer.set(
        "ID",
        Object::Array(vec![
            Object::String(b"id1".to_vec(), StringFormat::Hexadecimal),
            Object::String(b"id2".to_vec(), StringFormat::Hexadecimal),
        ]),
    );
    let state =
        lopdf::encryption::EncryptionState::try_from(lopdf::encryption::EncryptionVersion::V1 {
            document: &doc,
            owner_password: "owner",
            user_password: "user",
            permissions: lopdf::encryption::Permissions::default(),
        })
        .expect("encryption state");
    doc.encrypt(&state).expect("encrypt");

    let input = tmp("anon-pdf-enc.pdf");
    doc.save(&input).unwrap();

    let output = tmp("anon-pdf-enc-out.pdf");
    let report = sanitize_pdf(&input, &output, &load_policy()).unwrap();
    assert!(report.quarantined);
    let reason = report.quarantine_reason.unwrap();
    assert!(
        reason.contains("encrypt"),
        "reason should mention encryption, got: {reason}"
    );
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&output).ok();
}

#[test]
fn counts_pages_processed() {
    let (mut doc, _, _, _) = new_doc();
    let input = tmp("anon-pdf-pages.pdf");
    doc.save(&input).unwrap();
    let output = tmp("anon-pdf-pages-out.pdf");
    let report = sanitize_pdf(&input, &output, &load_policy()).unwrap();
    assert_eq!(report.pages_processed, 1);
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&output).ok();
}

#[test]
fn scrubs_page_level_metadata() {
    let (mut doc, _, _, page_id) = new_doc();
    let xmp = Stream::new(
        Dictionary::new(),
        b"<x:xmpmeta>secret@example.com</x:xmpmeta>".to_vec(),
    );
    let xmp_id = doc.add_object(Object::Stream(xmp));
    get_dict(&mut doc, page_id).set("Metadata", Object::Reference(xmp_id));

    let input = tmp("anon-pdf-pagemeta.pdf");
    doc.save(&input).unwrap();
    let output = tmp("anon-pdf-pagemeta-out.pdf");
    let report = sanitize_pdf(&input, &output, &load_policy()).unwrap();
    assert!(!report.quarantined);

    let bytes = raw_bytes(&output);
    assert!(
        !contains(&bytes, b"secret@example.com"),
        "page-level XMP metadata must be removed"
    );
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&output).ok();
}
