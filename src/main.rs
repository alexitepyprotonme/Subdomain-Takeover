use async_std::sync::Arc;
use async_std::sync::Mutex;
use clap::{App, Arg};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use tokio::time::{Duration, Instant};
use trust_dns_resolver::{
    proto::rr::record_type::RecordType,
    TokioAsyncResolver,
};
use uuid::Uuid;

fn print_banner() {
    println!(r#"                                                    "#);
    println!(r#"     ┳┓       •    ┏┳┓  ┓             ┏┓            "#);
    println!(r#"     ┃┃┏┓┏┳┓┏┓┓┏┓   ┃ ┏┓┃┏┏┓┏┓┓┏┏┓┏┓  ┗┓┏┏┓┏┓┏┓┏┓┏┓ "#);
    println!(r#"     ┻┛┗┛┛┗┗┗┻┗┛┗   ┻ ┗┻┛┗┗ ┗┛┗┛┗ ┛   ┗┛┗┗┻┛┗┛┗┗ ┛  "#);
    println!(r#"                                                    "#);
}

#[derive(Debug, Deserialize, Serialize)]
struct ErrorItem {
    fingerprint: String,
}

#[derive(Debug, Serialize, Clone)]
struct StixOutput {
    id: String,
    created: String,
    modified: String,
    name: String,
    pattern: String,
    labels: Vec<String>,
    pattern_type: String,
    spec_version: String,
    r#type: String,
    valid_from: String,
    indicates: String,
    description: String,
    objects: Option<Campaign>,
}

#[derive(Debug, Serialize, Clone)]
struct Campaign {
    id: String,
    created: String,
    modified: String,
    name: String,
    r#type: String,
    spec_version: String,
    service: String,
    ip: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    print_banner();

    let start_time = Instant::now();

    let matches = App::new("HTTP Brute Force")
        .version("1.3")
        .author("Your Name")
        .about("Performs HTTP Brute Force using provided credentials")
        .arg(
            Arg::with_name("domain")
                .short("d")
                .long("domain")
                .help("Sets the file containing subdomains")
                .default_value("subdomain.txt"),
        )
        .arg(
            Arg::with_name("finger")
                .short("f")
                .long("finger")
                .help("Sets the file containing finger-prints")
                .default_value("fingerprint.json"),
        )
        .arg(
            Arg::with_name("limit")
                .short("l")
                .long("limit")
                .help(
                    "Sets the rate limit for controlling concurrency and number of parallel tasks",
                )
                .default_value("100"),
        )
        .arg(
            Arg::with_name("sleep")
                .short("s")
                .long("sleep")
                .help("Sets the sleep duration between groups of tasks in seconds")
                .default_value("1000"),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .help("Sets the output file path to write the result"),
        )
        .arg(
            Arg::with_name("random-agent")
                .short("r")
                .long("random-agent")
                .help("Sets a random User-Agent from agents.txt"),
        )
        .arg(
            Arg::with_name("continue")
                .short("c")
                .long("continue")
                .help("Continue the search until file end"),
        )
        .arg(
            Arg::with_name("stix")
                .long("stix")
                .help("Generate STIX format output"),
        )
        .get_matches();

    let (domain_file, rate_limit_str, sleep_duration_str, finger_file, continue_on_success) = (
        matches.value_of("domain").unwrap(),
        matches.value_of("limit").unwrap().parse::<usize>(),
        matches.value_of("sleep").unwrap().parse::<u64>(),
        matches.value_of("finger").unwrap(),
        matches.is_present("continue"),
    );

    // Reading fingerprints...
    let mut file = File::open(finger_file)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let fingerprints: Vec<String> = serde_json::from_str::<Vec<ErrorItem>>(&contents)?
        .iter()
        .map(|item| item.fingerprint.clone())
        .collect();

    let fingerprints = Arc::new(fingerprints);

    let domains: Vec<String> = fs::read_to_string(&domain_file)
        .expect("")
        .lines()
        .map(|line| line.to_string())
        .collect();

    let rate_limit: usize = rate_limit_str.unwrap_or_default();
    let sleep_duration: u64 = sleep_duration_str.unwrap_or_default();

    let found_items: Arc<Mutex<Vec<StixOutput>>> = Arc::new(Mutex::new(Vec::new()));

    for addr_chunk in domains.chunks(rate_limit) {
        let mut tasks: Vec<tokio::task::JoinHandle<Result<(), _>>> = vec![];

        for addrrr in addr_chunk.iter() {
            let found_items_clone = Arc::clone(&found_items);
            let fingerprints = Arc::clone(&fingerprints);
            let item = addrrr.to_string();
            let mut flag = false;
            let client = reqwest::Client::new();

            let task = tokio::spawn(async move {
                let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
                let cname_result = resolver
                    .lookup((&item).as_str(), RecordType::CNAME, Default::default())
                    .await;

                match cname_result {
                    Ok(result) => {
                        if let Some(cname) = result.iter().next() {
                            let cname_value: String = cname
                                .to_string()
                                .chars()
                                .take(cname.to_string().len() - 1)
                                .collect();
                            if cname_value != (&item).as_str() {
                                // println!("CNAME points to a different domain: {}", cname_value);
                                flag = true;
                            }
                        }
                    }
                    Err(err) => {
                        // Handle the error if needed
                    }
                }

                if flag {
                    let url = "http://".to_owned() + &item;
                    let req_builder = client.get(url);
                    let resp = async_std::future::timeout(Duration::from_millis(sleep_duration), {
                        req_builder.send()
                    })
                    .await;

                    match resp {
                        Ok(Ok(resp)) => {
                            let body = resp.text().await?;

                            for fingerprint in fingerprints.iter() {
                                if body.contains(fingerprint) {
                                    println!(
                                        "--------------------------------------------------------"
                                    );
                                    println!("Success found! item: {:?}", &item);
                                    println!("Match found for '{}'", fingerprint);
                                    let elapsed = start_time.elapsed();
                                    println!("Elapsed time: {:?}", elapsed);
                                    println!(
                                        "--------------------------------------------------------"
                                    );
                                    println!("========================================================================================");

                                    let stix_output = StixOutput {
                                        id: format!("indicator--{}", Uuid::new_v4()),
                                        created: chrono::Utc::now().to_rfc3339(),
                                        modified: chrono::Utc::now().to_rfc3339(),
                                        name: format!("Subdomain Takeover"),
                                        pattern: format!("[domain-name:value = '{}']", item),
                                        labels: vec!["vulnerable".to_string()],
                                        pattern_type: "stix".to_string(),
                                        spec_version: "2.1".to_string(),
                                        r#type: "indicator".to_string(),
                                        valid_from: chrono::Utc::now().to_rfc3339(),
                                        indicates: Uuid::new_v4().to_string(),
                                        description: "This indicator represents a subdomain takeover vulnerability.".to_string(),
                                        objects: Some(Campaign {
                                            id: Uuid::new_v4().to_string(),
                                            created: chrono::Utc::now().to_rfc3339(),
                                            modified: chrono::Utc::now().to_rfc3339(),
                                            name: "Subdomain Takeover Campaign".to_string(),
                                            r#type: "campaign".to_string(),
                                            spec_version: "2.1".to_string(),
                                            service: "smartling".to_string(),
                                            ip: "54.88.145.219".to_string(),
                                        }),
                                    };

                                    let mut locked_items = found_items_clone.lock().await;
                                    locked_items.push(stix_output.clone());

                                    if !continue_on_success {
                                        std::process::exit(0);
                                    }
                                    break;
                                }
                            }
                            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                        }
                        _ => Err("Request failed or timed out")?,
                    }
                } else {
                    Ok(())
                }
            });

            tasks.push(task);
        }

        for task in tasks {
            task.await?;
        }
    }

    if matches.is_present("stix") {
        let locked_items = found_items.lock().await;
        if !locked_items.is_empty() {
            let stix_output_filename = format!("found_items_stix.json");
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&stix_output_filename)?;

            write!(file, "[")?;

            for (index, stix_output) in locked_items.iter().enumerate() {
                if index > 0 {
                    write!(file, ",")?;
                }
                let stix_output_json = serde_json::to_string_pretty(stix_output)?;
                writeln!(file, "{}", stix_output_json)?;
            }

            write!(file, "]")?;

            println!("STIX format output written to: {}", stix_output_filename);
        }
    }

    let elapsed = start_time.elapsed();
    println!("Elapsed time: {:?}", elapsed);

    Ok(())
}
