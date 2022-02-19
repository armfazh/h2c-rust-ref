#[doc(hidden)]
#[macro_export]
macro_rules! register_in_map {
    ( [$($elem:ident),+] ) => {
        {
            let mut h = HashMap::new();
            $(
                h.insert(String::from($elem.name), $elem);
            )+
            h
        }
    }
}
