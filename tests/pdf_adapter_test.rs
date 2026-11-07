use anon_cli::pdf_adapter::{sanitize_pdf, sanitize_pdf_with_redactions, PdfReport};
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

fn doc_with_font_and_text(font: Dictionary, tounicode: Option<&[u8]>, content: &[u8]) -> Document {
    let mut doc = Document::with_version("1.7");
    let content_id = doc.add_object(Object::Stream(Stream::new(
        Dictionary::new(),
        content.to_vec(),
    )));
    let mut font = font;
    if let Some(cmap) = tounicode {
        let tu_id = doc.add_object(Object::Stream(Stream::new(
            Dictionary::new(),
            cmap.to_vec(),
        )));
        font.set("ToUnicode", Object::Reference(tu_id));
    }
    let font_id = doc.add_object(Object::Dictionary(font));
    let resources = Dictionary::from_iter(vec![(
        "Font".to_string(),
        Object::Dictionary(Dictionary::from_iter(vec![(
            "F1".to_string(),
            Object::Reference(font_id),
        )])),
    )]);
    let page = Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Page".to_vec())),
        ("Contents".to_string(), Object::Reference(content_id)),
        ("Resources".to_string(), Object::Dictionary(resources)),
    ]);
    let page_id = doc.add_object(Object::Dictionary(page));
    let pages_id = doc.add_object(Object::Dictionary(Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Pages".to_vec())),
        (
            "Kids".to_string(),
            Object::Array(vec![Object::Reference(page_id)]),
        ),
        ("Count".to_string(), Object::Integer(1)),
    ])));
    let catalog_id = doc.add_object(Object::Dictionary(Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Catalog".to_vec())),
        ("Pages".to_string(), Object::Reference(pages_id)),
    ])));
    doc.trailer.set("Root", Object::Reference(catalog_id));
    doc
}

fn font_dict(encoding: Object) -> Dictionary {
    Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Font".to_vec())),
        ("Subtype".to_string(), Object::Name(b"TrueType".to_vec())),
        ("BaseFont".to_string(), Object::Name(b"TestFont".to_vec())),
        ("Encoding".to_string(), encoding),
    ])
}

fn run_redaction(doc: &mut Document, tag: &str, raw: &str) -> PdfReport {
    let input = tmp(&format!("anon-pdf-{tag}-in.pdf"));
    let output = tmp(&format!("anon-pdf-{tag}-out.pdf"));
    doc.save(&input).unwrap();
    let report = sanitize_pdf_with_redactions(
        &input,
        &output,
        &load_policy(),
        None,
        &[(raw.to_string(), "sort_code".to_string())],
    )
    .unwrap();
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&output).ok();
    report
}

// 2-byte codes: 0001..0006 -> "ABC123", 0010..0013 -> "REDACT" letters, bfrange array 0020..0021 -> "XY"
const TEST_CMAP: &[u8] = b"/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def
/CMapName /Adobe-Identity-UCS def
/CMapType 2 def
1 begincodespacerange
<0000> <FFFF>
endcodespacerange
10 beginbfchar
<0001> <0041>
<0002> <0042>
<0003> <0043>
<0004> <0031>
<0005> <0032>
<0006> <0033>
<0010> <0052>
<0011> <0045>
<0012> <0044>
<0013> <0054>
endbfchar
1 beginbfrange
<0020> <0021> [<0058> <0059>]
endbfrange
endcmap
CMapName currentdict /CMap defineresource pop
end
end
";

#[test]
fn redacts_unknown_encoding_name_when_tounicode_present() {
    let font = font_dict(Object::Name(b"CustomEncoding".to_vec()));
    let content = b"BT /F1 12 Tf <000100020003000400050006> Tj ET";
    let mut doc = doc_with_font_and_text(font, Some(TEST_CMAP), content);
    let report = run_redaction(&mut doc, "unk-name", "ABC123");
    assert!(
        !report.quarantined,
        "quarantined: {:?}",
        report.quarantine_reason
    );
    assert_eq!(report.redactions_applied, 1);
}

#[test]
fn redacts_dictionary_base_encoding_with_differences() {
    let enc = Object::Dictionary(Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Encoding".to_vec())),
        (
            "BaseEncoding".to_string(),
            Object::Name(b"WinAnsiEncoding".to_vec()),
        ),
        (
            "Differences".to_string(),
            Object::Array(vec![
                Object::Integer(3),
                Object::Name(b"A".to_vec()),
                Object::Name(b"B".to_vec()),
                Object::Name(b"C".to_vec()),
            ]),
        ),
    ]));
    let font = font_dict(enc);
    let content = b"BT /F1 12 Tf <030405> Tj ET";
    let mut doc = doc_with_font_and_text(font, None, content);
    let report = run_redaction(&mut doc, "dict-diff", "ABC");
    assert!(
        !report.quarantined,
        "quarantined: {:?}",
        report.quarantine_reason
    );
    assert_eq!(report.redactions_applied, 1);
}

#[test]
fn falls_back_to_base_encoding_when_tounicode_cmap_broken() {
    let enc = Object::Dictionary(Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Encoding".to_vec())),
        (
            "BaseEncoding".to_string(),
            Object::Name(b"WinAnsiEncoding".to_vec()),
        ),
    ]));
    let font = font_dict(enc);
    let content = b"BT /F1 12 Tf <414243> Tj ET";
    let mut doc = doc_with_font_and_text(font, Some(b"this is not a cmap"), content);
    let report = run_redaction(&mut doc, "broken-tu", "ABC");
    assert!(
        !report.quarantined,
        "quarantined: {:?}",
        report.quarantine_reason
    );
    assert_eq!(report.redactions_applied, 1);
}

#[test]
fn dictionary_encoding_without_base_or_usable_tounicode_quarantines_fail_closed() {
    let enc = Object::Dictionary(Dictionary::from_iter(vec![(
        "Type".to_string(),
        Object::Name(b"Encoding".to_vec()),
    )]));
    let font = font_dict(enc);
    let content = b"BT /F1 12 Tf <414243> Tj ET";
    let mut doc = doc_with_font_and_text(font, Some(b"garbage, not a cmap"), content);
    let report = run_redaction(&mut doc, "no-base", "ABC");
    assert!(report.quarantined, "expected fail-closed quarantine");
    let reason = report.quarantine_reason.unwrap();
    assert!(
        reason.contains("redaction failed"),
        "unexpected reason: {reason}"
    );
}

#[test]
fn redacts_identity_h_with_tounicode_cmap() {
    let font = font_dict(Object::Name(b"Identity-H".to_vec()));
    let content = b"BT /F1 12 Tf <000100020003000400050006> Tj ET";
    let mut doc = doc_with_font_and_text(font, Some(TEST_CMAP), content);
    let report = run_redaction(&mut doc, "identity-h", "ABC123");
    assert!(
        !report.quarantined,
        "quarantined: {:?}",
        report.quarantine_reason
    );
    assert_eq!(report.redactions_applied, 1);
}

#[test]
fn scanned_pdf_without_text_layer_quarantines_with_clear_reason() {
    let mut doc = Document::with_version("1.7");
    let content = b"q 100 0 0 100 0 0 cm /Im1 Do Q";
    let content_id = doc.add_object(Object::Stream(Stream::new(
        Dictionary::new(),
        content.to_vec(),
    )));
    let page = Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Page".to_vec())),
        ("Contents".to_string(), Object::Reference(content_id)),
        (
            "Resources".to_string(),
            Object::Dictionary(Dictionary::new()),
        ),
    ]);
    let page_id = doc.add_object(Object::Dictionary(page));
    let pages_id = doc.add_object(Object::Dictionary(Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Pages".to_vec())),
        (
            "Kids".to_string(),
            Object::Array(vec![Object::Reference(page_id)]),
        ),
        ("Count".to_string(), Object::Integer(1)),
    ])));
    let catalog_id = doc.add_object(Object::Dictionary(Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Catalog".to_vec())),
        ("Pages".to_string(), Object::Reference(pages_id)),
    ])));
    doc.trailer.set("Root", Object::Reference(catalog_id));

    let report = run_redaction(&mut doc, "scanned", "ABC123");
    assert!(report.quarantined, "scanned pdf must quarantine");
    let reason = report.quarantine_reason.unwrap();
    assert!(
        reason.contains("no text layer"),
        "reason should name the no-text-layer class, got: {reason}"
    );
}

fn decoded_page_texts(path: &PathBuf) -> Vec<String> {
    let doc = Document::load(path).unwrap();
    let mut out = Vec::new();
    for page_id in doc.page_iter() {
        let content = doc.get_and_decode_page_content(page_id).unwrap();
        let fonts = doc.get_page_fonts(page_id).unwrap();
        let mut cur: Vec<u8> = Vec::new();
        let mut page_text = String::new();
        for op in &content.operations {
            if op.operator.as_str() == "Tf" {
                cur = op
                    .operands
                    .first()
                    .and_then(|o| o.as_name().ok())
                    .map(|n| n.to_vec())
                    .unwrap_or_default();
            }
            if matches!(op.operator.as_str(), "Tj" | "TJ") {
                if let Some(font) = fonts.get(&cur) {
                    let enc =
                        anon_cli::pdf_font_encoding::resolve_font_encoding(&doc, font).unwrap();
                    for operand in &op.operands {
                        match operand {
                            Object::String(bytes, _) => page_text.push_str(&enc.decode(bytes)),
                            Object::Array(items) => {
                                for it in items {
                                    if let Ok(b) = it.as_str() {
                                        page_text.push_str(&enc.decode(b));
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        out.push(page_text);
    }
    out
}

fn add_page_with_font(
    doc: &mut Document,
    font: Dictionary,
    tounicode: Option<&[u8]>,
    content: &[u8],
) -> lopdf::ObjectId {
    let content_id = doc.add_object(Object::Stream(Stream::new(
        Dictionary::new(),
        content.to_vec(),
    )));
    let mut font = font;
    if let Some(cmap) = tounicode {
        let tu_id = doc.add_object(Object::Stream(Stream::new(
            Dictionary::new(),
            cmap.to_vec(),
        )));
        font.set("ToUnicode", Object::Reference(tu_id));
    }
    let font_id = doc.add_object(Object::Dictionary(font));
    let resources = Dictionary::from_iter(vec![(
        "Font".to_string(),
        Object::Dictionary(Dictionary::from_iter(vec![(
            "F1".to_string(),
            Object::Reference(font_id),
        )])),
    )]);
    let page = Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Page".to_vec())),
        ("Contents".to_string(), Object::Reference(content_id)),
        ("Resources".to_string(), Object::Dictionary(resources)),
    ]);
    doc.add_object(Object::Dictionary(page))
}

fn finish_doc(doc: &mut Document, page_ids: Vec<lopdf::ObjectId>) {
    let pages_id = doc.add_object(Object::Dictionary(Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Pages".to_vec())),
        (
            "Kids".to_string(),
            Object::Array(page_ids.into_iter().map(Object::Reference).collect()),
        ),
        ("Count".to_string(), Object::Integer(1)),
    ])));
    let catalog_id = doc.add_object(Object::Dictionary(Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Catalog".to_vec())),
        ("Pages".to_string(), Object::Reference(pages_id)),
    ])));
    doc.trailer.set("Root", Object::Reference(catalog_id));
}

fn run_redaction_file(doc: &mut Document, tag: &str, raw: &str) -> (PdfReport, PathBuf) {
    let input = tmp(&format!("anon-pdf-{tag}-in.pdf"));
    let output = tmp(&format!("anon-pdf-{tag}-out.pdf"));
    doc.save(&input).unwrap();
    let report = sanitize_pdf_with_redactions(
        &input,
        &output,
        &load_policy(),
        None,
        &[(raw.to_string(), "account_number".to_string())],
    )
    .unwrap();
    std::fs::remove_file(&input).ok();
    (report, output)
}

#[test]
fn whitespace_compact_match_leaves_no_identifier_fragment() {
    // raw contains a space, document text does not: the compact-match path
    // must map back to exact byte offsets in the joined string
    let font = font_dict(Object::Name(b"WinAnsiEncoding".to_vec()));
    let mut doc = Document::with_version("1.7");
    let page_id = add_page_with_font(&mut doc, font, None, b"BT /F1 12 Tf (Account 12345678 end) Tj ET");
    finish_doc(&mut doc, vec![page_id]);
    let (report, output) = run_redaction_file(&mut doc, "ws-compact", "1234 5678");
    assert!(!report.quarantined, "{:?}", report.quarantine_reason);
    assert_eq!(report.redactions_applied, 1);
    let texts = decoded_page_texts(&output);
    assert_eq!(texts, vec!["Account REDACTED end".to_string()]);
    std::fs::remove_file(&output).ok();
}

#[test]
fn zero_redactions_on_text_bearing_pdf_quarantines_fail_closed() {
    let font = font_dict(Object::Name(b"WinAnsiEncoding".to_vec()));
    let mut doc = Document::with_version("1.7");
    let page_id = add_page_with_font(&mut doc, font, None, b"BT /F1 12 Tf (hello world) Tj ET");
    finish_doc(&mut doc, vec![page_id]);
    let (report, output) = run_redaction_file(&mut doc, "zero-hit", "ZZZ-NOT-PRESENT");
    assert!(report.quarantined, "must not silently pass with 0 applied");
    let reason = report.quarantine_reason.unwrap();
    assert!(
        reason.contains("zero applied"),
        "unexpected reason: {reason}"
    );
    std::fs::remove_file(&output).ok();
}

#[test]
fn text_op_with_unknown_font_quarantines_instead_of_skipping() {
    let font = font_dict(Object::Name(b"WinAnsiEncoding".to_vec()));
    let mut doc = Document::with_version("1.7");
    // content references /F9 but resources only define /F1
    let page_id = add_page_with_font(&mut doc, font, None, b"BT /F9 12 Tf (12345678) Tj ET");
    finish_doc(&mut doc, vec![page_id]);
    let (report, output) = run_redaction_file(&mut doc, "unknown-font", "12345678");
    assert!(report.quarantined, "unknown-font text op must quarantine");
    assert!(report
        .quarantine_reason
        .unwrap()
        .contains("not in the page font map"));
    std::fs::remove_file(&output).ok();
}

#[test]
fn same_font_name_on_different_pages_does_not_cross_contaminate_cache() {
    let mut doc = Document::with_version("1.7");
    // page 1: F1 = WinAnsi (1-byte codes), text "XABCX"
    let p1 = add_page_with_font(
        &mut doc,
        font_dict(Object::Name(b"WinAnsiEncoding".to_vec())),
        None,
        b"BT /F1 12 Tf (XABCX) Tj ET",
    );
    // page 2: F1 = Identity-H with 2-byte ToUnicode cmap, text "ABC"
    let p2 = add_page_with_font(
        &mut doc,
        font_dict(Object::Name(b"Identity-H".to_vec())),
        Some(TEST_CMAP),
        b"BT /F1 12 Tf <000100020003> Tj ET",
    );
    finish_doc(&mut doc, vec![p1, p2]);
    let (report, output) = run_redaction_file(&mut doc, "two-page", "ABC");
    assert!(!report.quarantined, "{:?}", report.quarantine_reason);
    assert_eq!(report.redactions_applied, 2);
    let texts = decoded_page_texts(&output);
    assert_eq!(texts[0], "XREDACTEDX");
    assert_eq!(texts[1], "REDACTED");
    std::fs::remove_file(&output).ok();
}

#[test]
fn extract_page_texts_decodes_via_resolved_font_encoding() {
    let font = font_dict(Object::Name(b"Identity-H".to_vec()));
    let doc = doc_with_font_and_text(
        font,
        Some(TEST_CMAP),
        b"BT /F1 12 Tf <000100020003000400050006> Tj ET",
    );
    let texts = anon_cli::pdf_adapter::extract_page_texts(&doc).unwrap();
    assert_eq!(texts, vec!["ABC123".to_string()]);
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
