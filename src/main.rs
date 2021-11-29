use hmac::{Hmac, Mac, NewMac};
use percent_encoding::percent_encode;
use sha1::Sha1;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Opt {
    username: String,
    password: String,
}

const OAUTH_ASCII_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn generate_oauth_base_string(
    url_encoded: &str,
    method: &http::Method,
    params: &Vec<(&str, &str)>,
    oauth_params: &Vec<(&str, &str)>,
) -> String {
    let mut request_params_before_encoding = Vec::new();
    request_params_before_encoding.extend(oauth_params);
    request_params_before_encoding.extend(params);
    let mut request_params = request_params_before_encoding
        .iter()
        .map(|(k, v)| {
            let k = percent_encode(k.as_bytes(), &OAUTH_ASCII_SET).to_string();
            let v = percent_encode(v.as_bytes(), &OAUTH_ASCII_SET).to_string();
            (k, v)
        })
        .collect::<Vec<(String, String)>>();
    request_params.sort();
    let request_params_string = request_params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<String>>()
        .join("&");
    let base_string = format!(
        "{}&{}&{}",
        method.as_str(),
        url_encoded,
        percent_encode(request_params_string.as_bytes(), &OAUTH_ASCII_SET).to_string()
    );
    return base_string;
}

fn generate_oauth_signature(
    base_string: &str,
    oauth_consumer_secret: &str,
    oauth_token_secret: Option<&str>,
) -> String {
    let key = format!(
        "{}&{}",
        oauth_consumer_secret,
        oauth_token_secret.unwrap_or("")
    );
    let mut hmac = Hmac::<Sha1>::new_from_slice(key.as_bytes()).unwrap();
    hmac.update(base_string.as_bytes());
    let signature = hmac.finalize().into_bytes();
    return percent_encode(base64::encode(signature).as_bytes(), &OAUTH_ASCII_SET).to_string();
}

fn make_request(
    url: &str,
    method: http::Method,
    params: &Vec<(&str, &str)>,
    oauth_token: &str,
    oauth_token_secret: Option<&str>,
) -> String {
    let oauth_consumer_key = "8j30j19aj103911h";
    let oauth_consumer_secret = "0f5ur7d89sjv8d45";

    use rand::Rng;
    let oauth_nonce = format!("{}", rand::thread_rng().gen::<u64>());

    use std::time::SystemTime;
    let oauth_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => format!("{}", duration.as_secs()),
        Err(error) => panic!("{}", error),
    };

    let mut oauth_params = vec![
        ("oauth_consumer_key", oauth_consumer_key),
        ("oauth_nonce", &oauth_nonce),
        ("oauth_signature_method", "HMAC-SHA1"),
        ("oauth_timestamp", &oauth_timestamp),
        ("oauth_token", &oauth_token),
        ("oauth_version", "1.0"),
    ];

    let url_encoded = percent_encode(url.as_bytes(), &OAUTH_ASCII_SET).to_string();

    let oauth_base_string =
        generate_oauth_base_string(&url_encoded, &method, params, &oauth_params);
    let oauth_signature = generate_oauth_signature(
        &oauth_base_string,
        oauth_consumer_secret,
        oauth_token_secret,
    );

    oauth_params.insert(0, ("realm", &url_encoded));
    oauth_params.push(("oauth_signature", &oauth_signature));
    let auth_header = String::from("OAuth ")
        + &oauth_params
            .iter()
            .map(|(k, v)| format!("{}=\"{}\"", k, v))
            .collect::<Vec<String>>()
            .join(",");

    let client = reqwest::blocking::Client::new();
    let request_builder = client
        .request(method.clone(), url)
        .header("Authorization", auth_header);
    let request_builder = if method.eq(&http::Method::GET) {
        request_builder.query(&params)
    } else if method.eq(&http::Method::POST) {
        request_builder.form(&params)
    } else {
        panic!("Unsupported method: {}", method)
    };

    return request_builder.send().unwrap().text().unwrap();
}

fn get_token_secret(username: &str, password: &str) -> String {
    let data = format!(
        "<credentials><username>{}</username><password>{}</password></credentials>",
        username, password
    );
    let params = vec![("data", &*data)];

    let response = make_request(
        "https://www.app-api.ing.carrier.com/users/authenticated",
        http::Method::POST,
        &params,
        username,
        None,
    );

    let xml = roxmltree::Document::parse(&response).unwrap();
    return xml
        .root_element()
        .children()
        .find(|n| n.has_tag_name("accessToken"))
        .unwrap()
        .text()
        .unwrap()
        .to_string();
}
#[derive(Debug)]
struct System {
    location: String,
    name: String,
    url: String,
}

fn get_systems(username: &str, token_secret: &str) -> Vec<System> {
    let response = make_request(
        &format!(
            "https://www.app-api.ing.carrier.com/users/{}/locations",
            username
        ),
        http::Method::GET,
        &Vec::new(),
        username,
        Some(token_secret),
    );
    let xml = roxmltree::Document::parse(&response).unwrap();
    let mut results = Vec::new();
    for node1 in xml.root_element().children() {
        if node1.has_tag_name("location") {
            let location = node1
                .descendants()
                .find(|n| n.has_tag_name("name"))
                .unwrap()
                .text()
                .unwrap()
                .to_string();
            let systems = node1
                .children()
                .find(|n| n.has_tag_name("systems"))
                .unwrap();
            for node2 in systems.descendants() {
                if node2.has_tag_name("link") {
                    let name = node2.attribute("title").unwrap();
                    let url = node2.attribute("href").unwrap();
                    results.push(System {
                        location: location.to_string(),
                        name: name.to_string(),
                        url: url.to_string(),
                    });
                }
            }
        }
    }
    return results;
}

fn main() {
    let opt = Opt::from_args();
    let username = &opt.username;
    let token_secret = get_token_secret(username, &opt.password);
    let systems = get_systems(username, &token_secret);
    println!("{:?}", systems);
}
