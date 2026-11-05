use lopdf::{Dictionary, Document, Object, Stream, StringFormat};

const TITLE: &str = "Customer Statement";
const BODY: &[&str] = &[
    "Account holder: John Smith",
    "Account number: ACCT-99213344",
    "Email: john.smith@example.com",
    "Statement period: March 2024",
    "Total amount due: 1250.00 EUR",
    "Reference: INV-2024-03-0417",
];

fn escape(text: &str) -> String {
    text.replace('\\', r"\\")
        .replace('(', r"\(")
        .replace(')', r"\)")
}

fn content_bytes() -> Vec<u8> {
    let mut content = String::new();
    content.push_str("BT\n/F2 16 Tf\n72 740 Td\n(");
    content.push_str(&escape(TITLE));
    content.push_str(") Tj\nET\n");
    content.push_str("BT\n/F1 10 Tf\n72 700 Td\n18 TL\n");
    for line in BODY {
        content.push('(');
        content.push_str(&escape(line));
        content.push_str(") Tj\nT*\n");
    }
    content.push_str("ET\n");
    content.into_bytes()
}

fn font(base: &[u8]) -> Object {
    Object::Dictionary(Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Font".to_vec())),
        ("Subtype".to_string(), Object::Name(b"Type1".to_vec())),
        ("BaseFont".to_string(), Object::Name(base.to_vec())),
        (
            "Encoding".to_string(),
            Object::Name(b"WinAnsiEncoding".to_vec()),
        ),
    ]))
}

fn main() {
    let out = std::path::PathBuf::from("examples/statement_before.pdf");
    let mut doc = Document::with_version("1.7");

    let content = content_bytes();
    let mut content_dict = Dictionary::new();
    content_dict.set("Length", Object::Integer(content.len() as i64));
    let content_id = doc.add_object(Object::Stream(Stream::new(content_dict, content)));

    let regular_id = doc.add_object(font(b"Helvetica"));
    let bold_id = doc.add_object(font(b"Helvetica-Bold"));

    let annot_id = doc.add_object(Object::Dictionary(Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Annot".to_vec())),
        ("Subtype".to_string(), Object::Name(b"Text".to_vec())),
        (
            "Rect".to_string(),
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(0),
                Object::Integer(0),
                Object::Integer(0),
            ]),
        ),
        (
            "Contents".to_string(),
            Object::String(b"internal review note".to_vec(), StringFormat::Literal),
        ),
    ])));

    let page_id = doc.add_object(Object::Dictionary(Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Page".to_vec())),
        (
            "MediaBox".to_string(),
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(0),
                Object::Integer(612),
                Object::Integer(792),
            ]),
        ),
        (
            "Resources".to_string(),
            Object::Dictionary(Dictionary::from_iter(vec![(
                "Font".to_string(),
                Object::Dictionary(Dictionary::from_iter(vec![
                    ("F1".to_string(), Object::Reference(regular_id)),
                    ("F2".to_string(), Object::Reference(bold_id)),
                ])),
            )])),
        ),
        ("Contents".to_string(), Object::Reference(content_id)),
        (
            "Annots".to_string(),
            Object::Array(vec![Object::Reference(annot_id)]),
        ),
    ])));

    let pages_id = doc.add_object(Object::Dictionary(Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Pages".to_vec())),
        (
            "Kids".to_string(),
            Object::Array(vec![Object::Reference(page_id)]),
        ),
        ("Count".to_string(), Object::Integer(1)),
    ])));

    if let Ok(page) = doc.get_dictionary_mut(page_id) {
        page.set("Parent", Object::Reference(pages_id));
    }

    let js_id = doc.add_object(Object::Stream(Stream::new(
        Dictionary::new(),
        b"app.alert('x');".to_vec(),
    )));

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

    let catalog_id = doc.add_object(Object::Dictionary(Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Catalog".to_vec())),
        ("Pages".to_string(), Object::Reference(pages_id)),
        ("Names".to_string(), Object::Dictionary(names)),
    ])));

    doc.trailer.set("Root", Object::Reference(catalog_id));
    doc.trailer.set(
        "Info",
        Object::Dictionary(Dictionary::from_iter(vec![
            (
                "Title".to_string(),
                Object::String(b"Customer Statement".to_vec(), StringFormat::Literal),
            ),
            (
                "Author".to_string(),
                Object::String(b"Jane Doe".to_vec(), StringFormat::Literal),
            ),
            (
                "Subject".to_string(),
                Object::String(b"ACCT-99213344".to_vec(), StringFormat::Literal),
            ),
            (
                "Keywords".to_string(),
                Object::String(b"PII".to_vec(), StringFormat::Literal),
            ),
        ])),
    );

    doc.save(&out).expect("save statement_before.pdf");
    println!("wrote {}", out.display());
}
