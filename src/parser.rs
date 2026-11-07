use alloc::string::String;
use alloc::vec::Vec;
use smoltcp::wire::Ipv4Address;
use crate::{Direction, FilterVerdict, Ipv4Cidr, L4Protocol, Rule};

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    InvalidCommand,
    InvalidDirection,
    InvalidAction,
    InvalidProtocol,
    InvalidCidr,
    InvalidPort,
    TooFewArguments,
    MissingFlagValue(&'static str),
}

pub fn parse_rule_cmd(cmd: &str) -> Result<(Option<usize>, Rule), ParseError> {
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    if tokens.is_empty() {
        return Err(ParseError::TooFewArguments);
    }

    if tokens[0] == "iptables" || tokens[0] == "-A" || tokens[0] == "-I" {
        return parse_iptables_tokens(&tokens);
    }

    parse_dsl_tokens(&tokens)
}

fn parse_iptables_tokens(tokens: &[&str]) -> Result<(Option<usize>, Rule), ParseError> {
    let mut iter = tokens.iter().peekable();

    if let Some(&&"iptables") = iter.peek() {
        iter.next();
    }

    let action = iter.next().ok_or(ParseError::TooFewArguments)?;
    let mut insert_idx: Option<usize> = None;
    let mut direction: Option<Direction> = None;

    match *action {
        "-A" | "--append" => {
            let chain = iter.next().ok_or(ParseError::TooFewArguments)?;
            direction = parse_chain_to_direction(chain)?;
        }
        "-I" | "--insert" => {
            let chain = iter.next().ok_or(ParseError::TooFewArguments)?;
            direction = parse_chain_to_direction(chain)?;
            
            if let Some(&&next_token) = iter.peek() {
                if let Ok(idx) = next_token.parse::<usize>() {
                    insert_idx = Some(idx.saturating_sub(1));
                    iter.next();
                } else {
                    insert_idx = Some(0);
                }
            } else {
                insert_idx = Some(0);
            }
        }
        _ => return Err(ParseError::InvalidCommand),
    }

    let mut proto: Option<L4Protocol> = None;
    let mut src_cidr: Option<Ipv4Cidr> = None;
    let mut dst_cidr: Option<Ipv4Cidr> = None;
    let mut dst_port: Option<u16> = None;
    let mut verdict: FilterVerdict = FilterVerdict::Accept;

    while let Some(&token) = iter.next() {
        match token {
            "-p" | "--protocol" => {
                let val = iter.next().ok_or(ParseError::MissingFlagValue("-p"))?;
                proto = match *val {
                    "tcp" | "TCP" => Some(L4Protocol::Tcp),
                    "udp" | "UDP" => Some(L4Protocol::Udp),
                    "icmp" | "ICMP" => Some(L4Protocol::Icmp),
                    "all" | "any" => None,
                    _ => return Err(ParseError::InvalidProtocol),
                };
            }
            "-s" | "--source" => {
                let val = iter.next().ok_or(ParseError::MissingFlagValue("-s"))?;
                src_cidr = parse_cidr_token(val)?;
            }
            "-d" | "--destination" => {
                let val = iter.next().ok_or(ParseError::MissingFlagValue("-d"))?;
                dst_cidr = parse_cidr_token(val)?;
            }
            "--dport" | "--destination-port" => {
                let val = iter.next().ok_or(ParseError::MissingFlagValue("--dport"))?;
                if *val != "any" && *val != "*" {
                    dst_port = Some(val.parse::<u16>().map_err(|_| ParseError::InvalidPort)?);
                }
            }
            "-j" | "--jump" => {
                let val = iter.next().ok_or(ParseError::MissingFlagValue("-j"))?;
                verdict = match *val {
                    "ACCEPT" | "accept" => FilterVerdict::Accept,
                    "DROP" | "drop" => FilterVerdict::Drop,
                    "LOG_ACCEPT" | "log_accept" => FilterVerdict::LogAccept,
                    "LOG_DROP" | "log_drop" => FilterVerdict::LogDrop,
                    _ => return Err(ParseError::InvalidAction),
                };
            }
            _ => {
            }
        }
    }

    Ok((
        insert_idx,
        Rule {
            direction,
            proto,
            src_cidr,
            dst_cidr,
            dst_port,
            verdict,
        },
    ))
}

fn parse_chain_to_direction(chain: &str) -> Result<Option<Direction>, ParseError> {
    match chain {
        "INPUT" | "in" | "IN" => Ok(Some(Direction::Inbound)),
        "OUTPUT" | "out" | "OUT" => Ok(Some(Direction::Outbound)),
        "FORWARD" | "both" | "ANY" => Ok(None),
        _ => Err(ParseError::InvalidDirection),
    }
}

fn parse_dsl_tokens(tokens: &[&str]) -> Result<(Option<usize>, Rule), ParseError> {
    if tokens.len() < 7 {
        return Err(ParseError::TooFewArguments);
    }

    let mut idx = 0;
    let mut insert_idx = None;

    if tokens[idx] == "insert" {
        idx += 1;
        insert_idx = Some(tokens[idx].parse::<usize>().map_err(|_| ParseError::InvalidCommand)?);
        idx += 1;
    } else if tokens[idx] == "add" {
        idx += 1;
    } else {
        return Err(ParseError::InvalidCommand);
    }

    let direction = match tokens[idx] {
        "in" | "IN" => Some(Direction::Inbound),
        "out" | "OUT" => Some(Direction::Outbound),
        "both" | "ANY" => None,
        _ => return Err(ParseError::InvalidDirection),
    };
    idx += 1;

    let verdict = match tokens[idx] {
        "accept" | "ACCEPT" => FilterVerdict::Accept,
        "drop" | "DROP" => FilterVerdict::Drop,
        "log_accept" | "LOG_ACCEPT" => FilterVerdict::LogAccept,
        "log_drop" | "LOG_DROP" => FilterVerdict::LogDrop,
        _ => return Err(ParseError::InvalidAction),
    };
    idx += 1;

    let proto = match tokens[idx] {
        "tcp" | "TCP" => Some(L4Protocol::Tcp),
        "udp" | "UDP" => Some(L4Protocol::Udp),
        "icmp" | "ICMP" => Some(L4Protocol::Icmp),
        "any" | "ANY" => None,
        _ => return Err(ParseError::InvalidProtocol),
    };
    idx += 1;

    let src_cidr = parse_cidr_token(tokens[idx])?;
    idx += 1;
    let dst_cidr = parse_cidr_token(tokens[idx])?;
    idx += 1;

    let dst_port = if tokens[idx] == "any" || tokens[idx] == "*" {
        None
    } else {
        Some(tokens[idx].parse::<u16>().map_err(|_| ParseError::InvalidPort)?)
    };

    Ok((
        insert_idx,
        Rule {
            direction,
            proto,
            src_cidr,
            dst_cidr,
            dst_port,
            verdict,
        },
    ))
}

fn parse_cidr_token(token: &str) -> Result<Option<Ipv4Cidr>, ParseError> {
    if token == "any" || token == "*" || token == "0.0.0.0/0" {
        return Ok(None);
    }

    let mut parts = token.split('/');
    let ip_str = parts.next().ok_or(ParseError::InvalidCidr)?;
    let prefix_len = if let Some(len_str) = parts.next() {
        len_str.parse::<u8>().map_err(|_| ParseError::InvalidCidr)?
    } else {
        32
    };

    let ip = parse_ipv4(ip_str)?;
    Ok(Some(Ipv4Cidr::new(ip, prefix_len)))
}

fn parse_ipv4(s: &str) -> Result<Ipv4Address, ParseError> {
    let octets: Vec<&str> = s.split('.').collect();
    if octets.len() != 4 {
        return Err(ParseError::InvalidCidr);
    }
    let mut bytes = [0u8; 4];
    for i in 0..4 {
        bytes[i] = octets[i].parse::<u8>().map_err(|_| ParseError::InvalidCidr)?;
    }
    Ok(Ipv4Address::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}