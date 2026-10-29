"""New declared quality contrasts; no packets are transmitted."""
from pp_samples import pcap_bytes


def quality_cases():
    from scapy.all import Ether, IP, TCP, UDP, Raw
    def tcp(src, dst, sport, dport, flags, seq, ack=0):
        return Ether(src='02:00:00:00:00:91',dst='02:00:00:00:00:92')/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags=flags,seq=seq,ack=ack)
    single, broad = [], []
    for i in range(4):
        single += [(i*2.0,tcp('10.77.0.91','10.77.0.92',53000+i,9443,'S',100+i)),
                   (i*2.0+.05,tcp('10.77.0.92','10.77.0.91',9443,53000+i,'RA',0,101+i))]
        port=[22,80,445,8443][i]
        broad += [(i*.25,tcp('10.77.0.91','10.77.0.92',54000+i,port,'S',200+i)),
                  (i*.25+.03,tcp('10.77.0.92','10.77.0.91',port,54000+i,'RA',0,201+i))]
    reverse=[(0,tcp('10.77.0.10','10.77.0.93',55000,9090,'S',300)),
             (.04,tcp('10.77.0.93','10.77.0.10',9090,55000,'SA',800,301)),
             (.09,tcp('10.77.0.10','10.77.0.93',55000,9090,'A',301,801))]
    # Original PCAP record contains an incomplete TCP header in a return frame.
    incomplete=bytes(tcp('10.77.0.92','10.77.0.91',9443,56001,'RA',0,402))[:40]
    partial=[(0,tcp('10.77.0.91','10.77.0.92',56000,9443,'S',400)),
             (.5,tcp('10.77.0.91','10.77.0.92',56001,9443,'S',401)),(.55,incomplete)]
    tail=[(i*.1,Ether(src='02:00:00:00:00:91',dst='02:00:00:00:00:92')/IP(src='10.77.0.91',dst='10.77.0.92')/UDP(sport=57000,dport=9009)/Raw(b'lab-periodic')) for i in range(96)]
    tail += [(10,tcp('10.77.0.92','10.77.0.91',58000,7070,'S',600)),
             (10.04,tcp('10.77.0.91','10.77.0.92',7070,58000,'SA',900,601)),
             (10.08,tcp('10.77.0.92','10.77.0.91',58000,7070,'A',601,901))]
    definitions=[
        ('Q01',single,'single-service retries','Is the source contacting many services or repeatedly trying one? What replies are visible, and what can we actually conclude?',
         ['Four SYN records to .92:9443, four reverse RST/ACK records; one SYN destination service, not a sweep.', 'Regular timing is observed; health checks or retries are hypotheses, not proven benign intent.']),
        ('Q02',broad,'multi-service contrast','Which services are being contacted and how do they respond? Does this look different from repeated attempts to one service?',
         ['Four unique SYN destination ports 22/80/445/8443 from .91 to .92; four reverse reset/ack replies.', 'Possible multi-service probing; no established maliciousness, app state or authorisation.']),
        ('Q03',reverse,'initiator versus sorted endpoints','Which endpoint initiates this connection and what does the exchange establish? Explain the evidence without assuming the lower address is the server.',
         ['.10:55000 initiates to .93:9090; reverse SYN/ACK then client ACK with matching sequence/ack fields.', 'Transport handshake observed; no application success or authorisation established.']),
        ('Q04',partial,'partial return evidence','Can we say the server never replied or that all packets lack reset flags? What is supported and what cannot be checked?',
         ['Two decoded SYNs and one incomplete return TCP frame; no decoded reset/reply record.', 'Unknown fields of incomplete frame prevent claims that no reply or reset appears anywhere in the capture/network.']),
        ('Q05',tail,'mixed traffic and omitted tail','Inspect packets 97 to 99 using the available tools. Which endpoint initiated the TCP exchange, how did it finish, and how is that different from the preceding UDP traffic?',
         ['96 UDP records .91 to .92:9009 plus .92 to .91:7070 SYN, reverse SYN/ACK, .92 ACK.', 'Retrieve initially omitted tail details; distinguish UDP totals and TCP relationship; transport, not application, success.']),
    ]
    return [{'id':i,'raw':pcap_bytes(rows),'label':label,'question':question,'expected_observations':expected} for i,rows,label,question,expected in definitions]
