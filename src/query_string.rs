use std::collections::BTreeMap;

pub fn decode(input: &str) -> BTreeMap<&str, &str> {
    let pairs: Vec<Vec<&str>> = input.split("&").map(|raw_pair| raw_pair.split("=").collect()).collect();
    let mut result: BTreeMap<&str, &str> = BTreeMap::new();

    for pair in pairs {
        result.insert(pair[0], pair[1]);
    }
    result
}

pub fn encode(obj: &BTreeMap<&str, &str>) -> String {
    obj.iter()
        .map(|(key, val)| vec![key.clone(), val.clone()].join("="))
        .collect::<Vec<String>>()
        .join("&")
}

pub fn profile_for(email: &str) -> String {
    let safe_email = email.replace("&", "").replace("=", "");
    let mut obj: BTreeMap<&str, &str> = BTreeMap::new();
    obj.insert("email", safe_email.as_str());
    obj.insert("uid", "10");
    obj.insert("role", "user");
    encode(&obj)
}

mod tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)] // This is crap because we are using it.
    use std::collections::BTreeMap;

    #[test]
    fn test_decode() {
        let input = "foo=bar&baz=qux&zap=zazzle";
        let result = decode(&input);
        let mut expected_result = BTreeMap::new();
        expected_result.insert("foo", "bar");
        expected_result.insert("baz", "qux");
        expected_result.insert("zap", "zazzle");
        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_encode() {
        let mut input = BTreeMap::new();
        input.insert("foo", "bar");
        input.insert("baz", "qux");
        input.insert("zap", "zazzle");
        let result = encode(&input);
        // Ensure each pair is present in the output.
        assert!(result.contains("foo=bar"));
        assert!(result.contains("baz=qux"));
        assert!(result.contains("zap=zazzle"));

        // Ensure we can successfully round trip.
        let decoded = decode(&result.as_str());
        assert_eq!(input, decoded);
    }
}
