use lopdf::{Dictionary, Document, Object, Stream, StringFormat};

fn main() {
    let out = std::path::PathBuf::from("tests/fixtures/sample.pdf");
    let mut doc = Document::with_version("1.7");

    let js = Stream::new(Dictionary::new(), b"app.alert('x');".to_vec());
    let js_id = doc.add_object(Object::Stream(js));
    let page = Dictionary::from_iter(vec![("Type".to_string(), Object::Name(b"Page".to_vec()))]);
    let page = doc.add_object(Object::Dictionary(page));
    let pages = Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Pages".to_vec())),
        (
            "Kids".to_string(),
            Object::Array(vec![Object::Reference(page)]),
        ),
        ("Count".to_string(), Object::Integer(1)),
    ]);
    let pages_id = doc.add_object(Object::Dictionary(pages));
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
    let catalog = Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Catalog".to_vec())),
        ("Pages".to_string(), Object::Reference(pages_id)),
        ("Names".to_string(), Object::Dictionary(names)),
    ]);
    let catalog_id = doc.add_object(Object::Dictionary(catalog));
    doc.trailer.set("Root", Object::Reference(catalog_id));
    doc.trailer.set(
        "Info",
        Object::Dictionary(Dictionary::from_iter(vec![(
            "Author".to_string(),
            Object::String(b"Jane Doe".to_vec(), StringFormat::Literal),
        )])),
    );

    doc.save(&out).expect("save sample.pdf");
    println!("wrote {}", out.display());
}
