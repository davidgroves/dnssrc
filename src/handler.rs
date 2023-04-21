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
use trust_dns_server::{
    authority::MessageResponseBuilder,
    client::rr::{rdata::TXT, LowerName, Name, RData, Record},
    proto::{
        op::{Header, MessageType, OpCode, ResponseCode},
        rr::RecordType,
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};

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
    pub random_zone: LowerName,
    pub edns_zone: LowerName,
    pub ednscs_zone: LowerName,
    pub timestamp_zone: LowerName,
    pub timestamp0_zone: LowerName,
    pub ttl: u32,
}

fn parse_ednscs_subnet(v: Vec<u8>) -> ipnet::IpNet {
    let family = v[1];
    let prefix_length = v[2];

    if family == 0 {
        // Spec say this shouldn't ever exist, but it does in the wild from some software.
        // I think the meaning is "I'm aware of EDNS-CS" but don't want to use it for this request.
        todo!()
    }
    else if family == 1 {
        let mut x = v;
        x.resize(8,0);
        let addr = ipnet::IpNet::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(x[4], x[5], x[6], x[7])), prefix_length).unwrap();
        return addr;
    }
    else if family == 2 {
        let mut x = v;
        x.resize(20, 0);
        let x: Vec<u16> = x.chunks_exact(2).map(|a| u16::from_be_bytes([a[0], a[1]])).collect();
        let addr = ipnet::IpNet::new(std::net::IpAddr::V6(std::net::Ipv6Addr::new(x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9])), prefix_length).unwrap();
        return addr;
    }
    else {
        todo!("Bad ednscs data: {:?}", v);
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
            myaddr_zone: LowerName::from(Name::from_str(&format!("myaddr.{domain}")).unwrap()),
            random_zone: LowerName::from(Name::from_str(&format!("random.{domain}")).unwrap()),
            edns_zone: LowerName::from(Name::from_str(&format!("edns.{domain}")).unwrap()),
            ednscs_zone: LowerName::from(Name::from_str(&format!("edns-cs.{domain}")).unwrap()),
            timestamp_zone: LowerName::from(Name::from_str(&format!("timestamp.{domain}")).unwrap()),
            timestamp0_zone: LowerName::from(Name::from_str(&format!("timestamp0.{domain}")).unwrap()),
            ttl: options.ttl,
            // hexdump_zone: LowerName::from(Name::from_str(&format!("hexdump.{domain}")).unwrap()),
        }
    }

    async fn do_handle_request_myip<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let rdata = match request.src().ip() {
            IpAddr::V4(ipv4) => RData::A(ipv4),
            IpAddr::V6(ipv6) => RData::AAAA(ipv6),
        };
        let records = vec![Record::from_rdata(request.query().name().into(), self.ttl, rdata)];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_myport<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let rdata = RData::TXT(TXT::new(vec![request.src().port().to_string()]));
        let records = vec![Record::from_rdata(request.query().name().into(), self.ttl, rdata)];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_myaddr<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let string_response = vec![
            request.src().ip().to_string(),
            request.src().port().to_string(),
        ];
        let rdata = RData::TXT(TXT::new(string_response));
        let records = vec![Record::from_rdata(request.query().name().into(), self.ttl, rdata)];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_counter<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let rdata = RData::TXT(TXT::new(vec![counter.to_string()]));
        let records = vec![Record::from_rdata(request.query().name().into(), self.ttl, rdata)];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_timestamp<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
        ttlzero: bool
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
            false => self.ttl
        };
        let records = vec![Record::from_rdata(request.query().name().into(), ttl, rdata)];
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
        let records = vec![Record::from_rdata(request.query().name().into(), self.ttl, rdata)];
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
        let ednscs: Vec<u8> = request
            .edns()
            .unwrap()
            .options()
            .get(trust_dns_server::proto::rr::rdata::opt::EdnsCode::Subnet)
            .unwrap()
            .into();

        let net = parse_ednscs_subnet(ednscs);
        let rdata = RData::TXT(TXT::new(vec![net.to_string()]));
        let records = vec![Record::from_rdata(request.query().name().into(), self.ttl, rdata)];
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
            RecordType::A => RData::A(std::net::Ipv4Addr::new(
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
            )),
            RecordType::AAAA => RData::AAAA(std::net::Ipv6Addr::new(
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
                rand::thread_rng().gen(),
            )),
            RecordType::TXT => RData::TXT(TXT::new(vec![random_string])),
            _ => RData::TXT(TXT::new(vec![String::from(
                "Unsupported RR type. Supported are A/AAAA/TXT",
            )])),
        };

        let records = vec![Record::from_rdata(request.query().name().into(), self.ttl, rdata)];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_default<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        header.set_response_code(ResponseCode::NXDomain);
        let response = builder.build_no_records(header);
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
                self.do_handle_request_timestamp(request, response, false).await
            }
            name if self.timestamp0_zone.zone_of(name) => {
                self.do_handle_request_timestamp(request, response, true).await
            }
            
            name if self.root_zone.zone_of(name) => {
                self.do_handle_request_default(request, response).await
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
