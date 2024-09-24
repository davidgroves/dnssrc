use crate::Options;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use hickory_server::{
    authority::MessageResponseBuilder,
    proto::rr::{rdata::TXT, LowerName, Name, RData, Record},
    proto::{
        op::{Header, MessageType, OpCode, ResponseCode},
        rr::RecordType,
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};
use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tracing::*;

use hickory_server::proto::rr::rdata::soa::SOA;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid OpCode {0:}")]
    InvalidOpCode(OpCode),
    #[error("Invalid MessageType {0:}")]
    InvalidMessageType(MessageType),
    #[error("Invalid Zone {0:}")]
    InvalidZone(LowerName),
    #[error("IO error: {0:}")]
    Io(#[from] std::io::Error),
}

/// DNS Request Handler
#[derive(Clone, Debug)]
pub struct Handler {
    pub counter: Arc<AtomicU64>,
    pub root_zone: LowerName,
    pub counter_zone: LowerName,
    pub myip_zone: LowerName,
    pub myport_zone: LowerName,
    pub myaddr_zone: LowerName,
    pub help_zone: LowerName,
    pub random_zone: LowerName,
    pub edns_zone: LowerName,
    pub ednscs_zone: LowerName,
    pub timestamp_zone: LowerName,
    pub timestamp0_zone: LowerName,
    pub protocol_zone: LowerName,
    pub version_zone: LowerName,
    pub ttl: u32,
    pub ns_names: Vec<String>,
    pub soa_names: Vec<String>,
    pub soa_serial: u32,
    pub soa_refresh: i32,
    pub soa_retry: i32,
    pub soa_expire: i32,
    pub soa_minimum: u32,
}

fn parse_ednscs_subnet(subnet: Vec<u8>) -> ipnet::IpNet {
    let family = subnet[1];
    let prefix_length = subnet[2];

    if family == 0 {
        // Spec say this shouldn't ever exist, but it does in the wild from some software.
        // I think the meaning is "I'm aware of EDNS-CS" but don't want to use it for this request.
        todo!()
    } else if family == 1 {
        let mut x = subnet;
        x.resize(8, 0);
        let addr = ipnet::IpNet::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(x[4], x[5], x[6], x[7])),
            prefix_length,
        )
        .unwrap();
        return addr;
    } else if family == 2 {
        let mut x = subnet;
        x.resize(20, 0);
        let x: Vec<u16> = x
            .chunks_exact(2)
            .map(|a| u16::from_be_bytes([a[0], a[1]]))
            .collect();
        let addr = ipnet::IpNet::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9],
            )),
            prefix_length,
        )
        .unwrap();
        return addr;
    } else {
        todo!("Bad ednscs data: {:?}", subnet);
    }
}

impl Handler {
    /// Create new handler from command-line options.
    pub fn from_options(options: &Options) -> Self {
        let domain = &options.domain;
        Handler {
            counter: Arc::new(AtomicU64::new(0)),
            root_zone: LowerName::from(Name::from_str(domain).unwrap()),
            counter_zone: LowerName::from(Name::from_str(&format!("counter.{domain}")).unwrap()),
            myip_zone: LowerName::from(Name::from_str(&format!("myip.{domain}")).unwrap()),
            myport_zone: LowerName::from(Name::from_str(&format!("myport.{domain}")).unwrap()),
            myaddr_zone: LowerName::from(Name::from_str(&format!("myaddr.{domain}")).unwrap()),
            help_zone: LowerName::from(Name::from_str(&format!("help.{domain}")).unwrap()),
            random_zone: LowerName::from(Name::from_str(&format!("random.{domain}")).unwrap()),
            edns_zone: LowerName::from(Name::from_str(&format!("edns.{domain}")).unwrap()),
            ednscs_zone: LowerName::from(Name::from_str(&format!("edns-cs.{domain}")).unwrap()),
            protocol_zone: LowerName::from(Name::from_str(&format!("protocol.{domain}")).unwrap()),
            version_zone: LowerName::from(Name::from_str(&format!("version.{domain}")).unwrap()),
            timestamp_zone: LowerName::from(
                Name::from_str(&format!("timestamp.{domain}")).unwrap(),
            ),
            timestamp0_zone: LowerName::from(
                Name::from_str(&format!("timestamp0.{domain}")).unwrap(),
            ),
            ttl: options.ttl,
            ns_names: options.ns_records.clone(),
            soa_names: options.soa_names.clone(),
            soa_serial: options.soa_values[0] as u32,
            soa_refresh: options.soa_values[1] as i32,
            soa_retry: options.soa_values[2] as i32,
            soa_expire: options.soa_values[3] as i32,
            soa_minimum: options.soa_values[4] as u32,
        }
    }

    async fn do_handle_request_myip<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let rdata = RData::TXT(TXT::new(vec![request.src().ip().to_string()]));

        let records = vec![Record::from_rdata(
            request.query().name().into(),
            self.ttl,
            rdata,
        )];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_version<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let version = option_env!("CARGO_PKG_VERSION").unwrap_or("unknown");
        let rdata = RData::TXT(TXT::new(vec![version.to_string()]));

        let records = vec![Record::from_rdata(
            request.query().name().into(),
            self.ttl,
            rdata,
        )];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_protocol<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);

        let ipversion = match request.src() {
            addr if addr.is_ipv4() => "IPv4",
            addr if addr.is_ipv6() => "IPv6",
            _ => "Unknown",
        };

        let rdata = RData::TXT(TXT::new(vec![
            request.protocol().to_string() + " " + ipversion,
        ]));
        let records = vec![Record::from_rdata(
            request.query().name().into(),
            self.ttl,
            rdata,
        )];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_myport<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let rdata = RData::TXT(TXT::new(vec![request.src().port().to_string()]));
        let records = vec![Record::from_rdata(
            request.query().name().into(),
            self.ttl,
            rdata,
        )];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_myaddr<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let string_response = vec![
            request.src().ip().to_string(),
            request.src().port().to_string(),
        ];
        let rdata = RData::TXT(TXT::new(string_response));
        let records = vec![Record::from_rdata(
            request.query().name().into(),
            self.ttl,
            rdata,
        )];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_help<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let string_response = vec![
            "Available queries are: myip/TXT, myport/TXT, myaddr/TXT, counter/TXT, random/A/AAAA/TXT, ednsTXT, edns-cs/TXT, timestamp/TXT, timestamp0/TXT, help/TXT, protocol/TXT, version/TXT".to_string()
        ];
        let rdata = RData::TXT(TXT::new(string_response));
        let records = vec![Record::from_rdata(
            request.query().name().into(),
            self.ttl,
            rdata,
        )];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_counter<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let counter: u64 = self.counter.fetch_or(0, Ordering::SeqCst);
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let rdata = RData::TXT(TXT::new(vec![counter.to_string()]));
        let records = vec![Record::from_rdata(
            request.query().name().into(),
            self.ttl,
            rdata,
        )];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_timestamp<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
        ttlzero: bool,
    ) -> Result<ResponseInfo, Error> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let start = std::time::SystemTime::now();
        let since_the_epoch = start
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards");
        let timestamp = since_the_epoch.as_millis();
        let str_timestamp = format!("{}", timestamp);
        let rdata = RData::TXT(TXT::new(vec![str_timestamp]));
        println!("{}", request.query().name().base_name());
        let ttl = match ttlzero {
            true => 0,
            false => self.ttl,
        };
        let records = vec![Record::from_rdata(
            request.query().name().into(),
            ttl,
            rdata,
        )];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_edns<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        let edns = request.edns().unwrap();
        header.set_authoritative(true);
        let rdata = RData::TXT(TXT::new(vec![edns.to_string()]));
        let records = vec![Record::from_rdata(
            request.query().name().into(),
            self.ttl,
            rdata,
        )];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_ednscs<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let ednscs_option = request
            .edns()
            .unwrap()
            .options()
            .get(hickory_server::proto::rr::rdata::opt::EdnsCode::Subnet)
            .unwrap()
            .try_into()
            .unwrap_or_default();

        let ednscs: Vec<u8> = ednscs_option;
        let net = parse_ednscs_subnet(ednscs);
        let rdata = RData::TXT(TXT::new(vec![net.to_string()]));
        let records = vec![Record::from_rdata(
            request.query().name().into(),
            self.ttl,
            rdata,
        )];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_random<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let random_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);

        let rdata = match request.query().query_type() {
            RecordType::A => RData::A(hickory_server::proto::rr::rdata::A(
                std::net::Ipv4Addr::new(
                    rand::thread_rng().gen(),
                    rand::thread_rng().gen(),
                    rand::thread_rng().gen(),
                    rand::thread_rng().gen(),
                ),
            )),
            RecordType::AAAA => RData::AAAA(hickory_server::proto::rr::rdata::AAAA(
                std::net::Ipv6Addr::new(
                    rand::thread_rng().gen(),
                    rand::thread_rng().gen(),
                    rand::thread_rng().gen(),
                    rand::thread_rng().gen(),
                    rand::thread_rng().gen(),
                    rand::thread_rng().gen(),
                    rand::thread_rng().gen(),
                    rand::thread_rng().gen(),
                ),
            )),
            RecordType::TXT => RData::TXT(TXT::new(vec![random_string])),
            _ => RData::TXT(TXT::new(vec![String::from(
                "Unsupported RR type. Supported are A/AAAA/TXT",
            )])),
        };

        let records = vec![Record::from_rdata(
            request.query().name().into(),
            self.ttl,
            rdata,
        )];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_rootzone<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let header = Header::response_from_request(request.header());
        let builder = MessageResponseBuilder::from_message_request(request);
        let response;
        let mut records = vec![];

        if request.query().query_type().is_ns() {
            let mut rdatas = vec![];
            for ns_name in self.ns_names.clone().into_iter() {
                rdatas.push(RData::NS(hickory_server::proto::rr::rdata::NS(
                    Name::from_str(&ns_name).unwrap(),
                )));
            }
            for rdata in rdatas {
                records.push(Record::from_rdata(request.query().name().into(), 60, rdata))
            }
            response = builder.build(header, &records, &[], &[], &[]);
        } else if request.query().query_type().is_soa() {
            let rdata = RData::SOA(SOA::new(
                Name::from_str_relaxed(&self.soa_names[0]).unwrap(),
                Name::from_str_relaxed(&self.soa_names[1]).unwrap(),
                self.soa_serial,
                self.soa_refresh,
                self.soa_retry,
                self.soa_expire,
                self.soa_minimum,
            ));
            records = vec![Record::from_rdata(request.query().name().into(), 60, rdata)];
            response = builder.build(header, &records, &[], &[], &[]);
        } else {
            response = builder.build(header, &[], &[], &[], &[]);
        }

        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> Result<ResponseInfo, Error> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        if request.op_code() != OpCode::Query {
            return Err(Error::InvalidOpCode(request.op_code()));
        }

        if request.message_type() != MessageType::Query {
            return Err(Error::InvalidMessageType(request.message_type()));
        }

        match request.query().name() {
            name if self.myip_zone.zone_of(name) => {
                self.do_handle_request_myip(request, response).await
            }
            name if self.version_zone.zone_of(name) => {
                self.do_handle_request_version(request, response).await
            }
            name if self.myport_zone.zone_of(name) => {
                self.do_handle_request_myport(request, response).await
            }
            name if self.counter_zone.zone_of(name) => {
                self.do_handle_request_counter(request, response).await
            }
            name if self.myaddr_zone.zone_of(name) => {
                self.do_handle_request_myaddr(request, response).await
            }
            name if self.help_zone.zone_of(name) => {
                self.do_handle_request_help(request, response).await
            }
            name if self.random_zone.zone_of(name) => {
                self.do_handle_request_random(request, response).await
            }
            name if self.edns_zone.zone_of(name) => {
                self.do_handle_request_edns(request, response).await
            }
            name if self.ednscs_zone.zone_of(name) => {
                self.do_handle_request_ednscs(request, response).await
            }
            name if self.timestamp_zone.zone_of(name) => {
                self.do_handle_request_timestamp(request, response, false)
                    .await
            }
            name if self.timestamp0_zone.zone_of(name) => {
                self.do_handle_request_timestamp(request, response, true)
                    .await
            }
            name if self.protocol_zone.zone_of(name) => {
                debug!("Handling protocol request");
                self.do_handle_request_protocol(request, response).await
            }

            // This must be the last check, it will match before and run.
            name if self.root_zone.zone_of(name) => {
                self.do_handle_request_rootzone(request, response).await
            }

            name => Err(Error::InvalidZone(name.clone())),
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> ResponseInfo {
        // try to handle request
        match self.do_handle_request(request, response).await {
            Ok(info) => info,
            Err(error) => {
                error!("Error in RequestHandler: {error}");
                let mut header = Header::new();
                header.set_response_code(ResponseCode::ServFail);
                header.into()
            }
        }
    }
}
