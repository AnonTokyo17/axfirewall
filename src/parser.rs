use smoltcp::wire::Ipv4Address;
use crate::{Direction, FilterVerdict, Ipv4Cidr, L4Protocol, Rule};

pub enum ParseError {
    InvalidCommand,
    InvalidDirection,
    InvalidAction,
    InvalidProtocol,
    InvalidCidr,
    InvalidPort,
    TooFewArguments,
}

pub fn parse_rule_cmd(cmd: &str) -> Result<Rule, ParseError> {
    let parts: alloc::vec::Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() < 7 {
        return Err(ParseError::TooFewArguments);
    }

    if parts[0] != "add" && parts[0] != "insert" {
        return Err(ParseError::InvalidCommand);
    }

    let direction = match parts[1] {
        "in" | "IN" => Some(Direction::Inbound),
        "out" | "OUT" => Some(Direction::Outbound),
        "both" | "ANY" => None,
        _ => return Err(ParseError::InvalidDirection),
    };

    let verdict = match parts[2] {
        "accept" => FilterVerdict::Accept,
        "drop" => FilterVerdict::Drop,
        "log_accept" | "tap" => FilterVerdict::LogAccept,
        "log_drop" => FilterVerdict::LogDrop,
        _ => return Err(ParseError::InvalidAction),
    };

    let proto = match parts[3] {
        "tcp" | "TCP" => Some(L4Protocol::Tcp),
        "udp" | "UDP" => Some(L4Protocol::Udp),
        "icmp" | "ICMP" => Some(L4Protocol::Icmp),
        "any" | "ANY" => None,
        _ => return Err(ParseError::InvalidProtocol),
    };

    let src_cidr = parse_cidr_token(parts[4])?;
    let dst_cidr = parse_cidr_token(parts[5])?;

    let dst_port = if parts[6] == "any" || parts[6] == "*" {
        None
    } else {
        Some(parts[6].parse::<u16>().map_err(|_| ParseError::InvalidPort)?)
    };

    Ok(Rule {
        direction,
        proto,
        src_cidr,
        dst_cidr,
        dst_port,
        verdict,
    })
}

fn parse_cidr_token(token: &str) -> Result<Option<Ipv4Cidr>, ParseError> {
    if token == "any" || token == "*" {
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
    let octets: alloc::vec::Vec<&str> = s.split('.').collect();
    if octets.len() != 4 {
        return Err(ParseError::InvalidCidr);
    }
    let mut bytes = [0u8; 4];
    for i in 0..4 {
        bytes[i] = octets[i].parse::<u8>().map_err(|_| ParseError::InvalidCidr)?;
    }
    Ok(Ipv4Address::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}