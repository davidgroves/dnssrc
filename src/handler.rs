use crate::Options;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use std::{
    net::IpAddr,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tracing::*;
use hickory_server::{
    authority::MessageResponseBuilder,
    proto::rr::{rdata::TXT, LowerName, Name, RData, Record},
    proto::{
        op::{Header, MessageType, OpCode, ResponseCode},
        rr::RecordType,
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};

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
    pub ttl: u32,
    pub ns_names: Vec<String>,
    pub soa_names: Vec<String>,
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
            root_zone: LowerName::from(Name::from_str(domain).unwrap()),
            counter: Arc::new(AtomicU64::new(0)),
            counter_zone: LowerName::from(Name::from_str(&format!("counter.{domain}")).unwrap()),
            myip_zone: LowerName::from(Name::from_str(&format!("myip.{domain}")).unwrap()),
            myport_zone: LowerName::from(Name::from_str(&format!("myport.{domain}")).unwrap()),
            myaddr_zone: LowerName::from(Name::from_str(&format!("myaddr.{domain}")).unwrap())),
            help_zone: LowerName::from(Name::from_str(&format!("help.{domain}")).unwrap())),
            random_zone: LowerName::from(Name::from_str(&format!("random.{domain}")).unwrap())),
            edns_zone: LowerName::from(Name::from_str(&format!("edns.{domain}")).unwrap())),
            ednscs_zone: LowerName::from(Name::from_str(&format!("edns-cs.{domain}")).unwrap())),
            timestamp_zone: LowerName::from(
                Name::from_str(&format!("timestamp.{domain}")).unwrap(),
            ),
            timestamp0_zone: LowerName::from(
                Name::from_str(&format!("timestamp0.{domain}")).unwrap(),
            ),
            ttl: options.ttl,
            ns_names: options.ns_records.clone(),
            soa_names: options.soa_names.clone(),
        }
    }

    async fn increment_counter(&self) {
        self.counter.fetch_add(1, Ordering::SeqCst);
    }

    fn build_response(&self, request: &Request, records: Vec<Record>) -> MessageResponse {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        builder.build(header, records.iter(), &[], &[], &[])
    }

    fn create_records(&self, request: &Request, rdata: RData, ttl: Option<u32>) -> Vec<Record> {
        let ttl = ttl.unwrap_or(self.ttl);
        vec![Record::from_rdata(request.query().name().into(), ttl, rdata)]
    }

    async fn do_handle_request_myip<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        self.increment_counter().await;
        let rdata = match request.src().ip() {
            IpAddr::V4(ipv4) => RData::A(hickory_server::proto::rr::rdata::A(ipv4)),
            IpAddr::V6(ipv6) => RData::AAAA(hickory_server::proto::rr::rdata::AAAA(ipv6)),
        };
        let records = self.create_records(request, rdata, None);
        let response = self.build_response(request, records);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_myport<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        self.increment_counter().await;
        let rdata = RData::TXT(TXT::new(vec![request.src().port().to_string()]));
        let records = self.create_records(request, rdata, None);
        let response = self.build_response(request, records);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_myaddr<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        self.increment_counter().await;
        let string_response = vec![
            request.src().ip().to_string(),
            request.src().port().to_string(),
        ];
        let rdata = RData::TXT(TXT::new(string_response));
        let records = self.create_records(request, rdata, None);
        let response = self.build_response(request, records);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_help<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        self.increment_counter().await;
        let string_response = vec![
            "Available queries are: myip/A/AAAA/TXT, myport/TXT, myaddr/ANY, counter/TXT, random/A/AAAA/TXT, edns/A/AAAA/TXT, ednscs/A/AAAA, timestamp/TXT, timestamp0/TXT, help/ANY".to_string()
        ];
        let rdata = RData::TXT(TXT::new(string_response));
        let records = self.create_records(request, rdata, None);
        let response = self.build_response(request, records);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_counter<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        let rdata = RData::TXT(TXT::new(vec![counter.to_string()]));
        let records = self.create_records(request, rdata, None);
        let response = self.build_response(request, records);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_timestamp<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
        ttlzero: bool,
    ) -> Result<ResponseInfo, Error> {
        let start = std::time::SystemTime::now();
        let since_the_epoch = start
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards");
        let timestamp = since_the_epoch.as_millis();
        let str_timestamp = format!("{}", timestamp);
        let rdata = RData::TXT(TXT::new(vec![str_timestamp]));
        println!("{}", request.query().name().base_name());
        let ttl = if ttlzero { Some(0) } else { None };
        let records = self.create_records(request, rdata, ttl);
        let response = self.build_response(request, records);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_edns<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let edns = request.edns().unwrap();
        let rdata = RData::TXT(TXT::new(vec![edns.to_string()]));
        let records = self.create_records(request, rdata, None);
        let response = self.build_response(request, records);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_ednscs<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let ednscs_option = request
            .edns()
            .unwrap()
            .options()
            .get(hickory_server::proto::rr::rdata::opt::EdnsCode::Subnet)
            .unwrap()
            .try_into()
            .unwrap();
            
        let ednscs: Vec<u8> = ednscs_option;
        let net = parse_ednscs_subnet(ednscs);
        let rdata = RData::TXT(TXT::new(vec![net.to_string()]));
        let records = self.create_records(request, rdata, None);
        let response = self.build_response(request, records);
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

        let rdata = match request.query().query_type() {
            RecordType::A => RData::A(hickory_server::proto::rr::rdata::A(std::net::Ipv4Addr::new(
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
            ))),
            RecordType::AAAA => RData::AAAA(hickory_server::proto::rr::rdata::AAAA(std::net::Ipv6Addr::new(
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
            ))),
            RecordType::TXT => RData::TXT(TXT::new(vec![random_string])),
            _ => RData::TXT(TXT::new(vec![String::from(
                "Unsupported RR type. Supported are A/AAAA/TXT",
            )])),
        };

        let records = self.create_records(request, rdata, None);
        let response = self.build_response(request, records);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_rootzone<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let mut records = vec![];

        if request.query().query_type().is_ns() {
            let mut rdatas = vec![];
            for ns_name in self.ns_names.clone().into_iter() {
                rdatas.push(RData::NS(hickory_server::proto::rr::rdata::NS(Name::from_str(&ns_name).unwrap())));
            }
            for rdata in rdatas {
                records.push(Record::from_rdata(request.query().name().into(), 60, rdata))
            }
        } else if request.query().query_type().is_soa() {
            let rdata = RData::SOA(SOA::new(
                Name::from_str_relaxed(&self.soa_names[0]).unwrap(),
                Name::from_str_relaxed(&self.soa_names[1]).unwrap(),
                1000,
                60,
                60,
                31356000,
                0,
            ));
            records = vec![Record::from_rdata(request.query().name().into(), 60, rdata)];
        }

        let response = self.build_response(request, records);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> Result<ResponseInfo, Error> {
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
