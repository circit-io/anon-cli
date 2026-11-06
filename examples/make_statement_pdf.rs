use lopdf::{Dictionary, Document, Object, Stream, StringFormat};

const NAVY: (f32, f32, f32) = (0.09, 0.19, 0.36);
const GOLD: (f32, f32, f32) = (0.85, 0.66, 0.13);
const INK: (f32, f32, f32) = (0.13, 0.14, 0.16);
const GRAY: (f32, f32, f32) = (0.42, 0.44, 0.47);
const SHADE: (f32, f32, f32) = (0.94, 0.95, 0.97);
const WHITE: (f32, f32, f32) = (1.0, 1.0, 1.0);

fn escape(text: &str) -> String {
    text.replace('\\', r"\\")
        .replace('(', r"\(")
        .replace(')', r"\)")
}

fn fill_rect(c: &mut String, x: f32, y: f32, w: f32, h: f32, (r, g, b): (f32, f32, f32)) {
    c.push_str(&format!("{r} {g} {b} rg\n{x} {y} {w} {h} re f\n"));
}

fn hline(c: &mut String, x1: f32, x2: f32, y: f32, width: f32, gray: f32) {
    c.push_str(&format!("{gray} G\n{width} w\n{x1} {y} m\n{x2} {y} l S\n"));
}

fn text(c: &mut String, x: f32, y: f32, size: i32, font: &str, rgb: (f32, f32, f32), s: &str) {
    let (r, g, b) = rgb;
    c.push_str(&format!(
        "BT\n{font} {size} Tf\n{r} {g} {b} rg\n{x} {y} Td\n({}) Tj\nET\n",
        escape(s)
    ));
}

// crude Helvetica width estimate, good enough to right-align amounts
fn right_x(s: &str, size: i32, right_edge: f32) -> f32 {
    right_edge - s.len() as f32 * size as f32 * 0.53
}

fn content_bytes() -> Vec<u8> {
    let mut c = String::new();

    fill_rect(&mut c, 0.0, 712.0, 612.0, 80.0, NAVY);
    fill_rect(&mut c, 0.0, 704.0, 612.0, 4.0, GOLD);
    text(&mut c, 40.0, 756.0, 20, "/F2", WHITE, "ACME Bank");
    text(&mut c, 40.0, 738.0, 10, "/F1", WHITE, "Customer Statement");
    text(
        &mut c,
        right_x("Ref INV-2024-03-0417", 9, 572.0),
        738.0,
        9,
        "/F1",
        WHITE,
        "Ref INV-2024-03-0417",
    );

    text(&mut c, 40.0, 678.0, 12, "/F2", INK, "Account details");
    let rows: [(&str, &str); 4] = [
        ("Account holder", "John Smith"),
        ("Account number", "ACCT-99213344"),
        ("Email", "john.smith@example.com"),
        ("Statement period", "March 2024"),
    ];
    let mut y = 658.0;
    for (label, value) in rows {
        text(&mut c, 40.0, y, 9, "/F1", GRAY, label);
        text(&mut c, 200.0, y, 10, "/F1", INK, value);
        hline(&mut c, 40.0, 572.0, y - 6.0, 0.5, 0.88);
        y -= 20.0;
    }

    text(&mut c, 40.0, 562.0, 12, "/F2", INK, "Activity");

    fill_rect(&mut c, 40.0, 522.0, 532.0, 18.0, SHADE);
    text(&mut c, 48.0, 527.0, 8, "/F2", INK, "DATE");
    text(&mut c, 140.0, 527.0, 8, "/F2", INK, "DESCRIPTION");
    text(
        &mut c,
        right_x("AMOUNT", 8, 564.0),
        527.0,
        8,
        "/F2",
        INK,
        "AMOUNT",
    );

    let items: [(&str, &str, &str); 3] = [
        ("2024-03-04", "Wire transfer", "450.00 EUR"),
        ("2024-03-11", "Service fee (Q1)", "300.00 EUR"),
        ("2024-03-18", "Card settlement", "500.00 EUR"),
    ];
    y = 506.0;
    for (date, desc, amount) in items {
        text(&mut c, 48.0, y, 9, "/F1", INK, date);
        text(&mut c, 140.0, y, 9, "/F1", INK, desc);
        text(&mut c, right_x(amount, 9, 564.0), y, 9, "/F1", INK, amount);
        hline(&mut c, 40.0, 572.0, y - 6.0, 0.5, 0.88);
        y -= 22.0;
    }

    hline(&mut c, 40.0, 572.0, y + 10.0, 1.0, 0.3);
    fill_rect(&mut c, 40.0, y - 8.0, 532.0, 20.0, SHADE);
    text(&mut c, 140.0, y - 2.0, 9, "/F2", INK, "Total amount due");
    text(
        &mut c,
        right_x("1,250.00 EUR", 9, 564.0),
        y - 2.0,
        9,
        "/F2",
        INK,
        "1,250.00 EUR",
    );

    text(
        &mut c,
        40.0,
        36.0,
        7,
        "/F1",
        GRAY,
        "ACME Bank - synthetic example generated for the anon-cli README",
    );
    text(
        &mut c,
        right_x("1 / 1", 7, 572.0),
        36.0,
        7,
        "/F1",
        GRAY,
        "1 / 1",
    );

    c.into_bytes()
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
