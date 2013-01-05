'''
Created on Dec 28, 2012
 
@author: Artien "SphaZ" cyberphaz (at) gmail (dot) com
 
'''
import socket, traceback, base64, hashlib, thread
from scapy.all import *
from Crypto.Cipher import AES
 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verbose = 0
conf.verb=0
conf.L3socket = L3RawSocket
 
#doesnt work on another port, scapy issue?
port = 53
host = "127.0.0.1"
PASSWORD = ""
TERMINATOR = "[{]"
 
#specify your valid prefix to recognise chat messages
#list of prefixes?
VALID_PREFIX = [ "www1-","data","img","www.cdn-", "cnd-", "images.svr-", "static-", "www.svr" ]
#list of valid domains that we "handle" the shorter the better
#more space for messages:)
VALID_DOMAINS = [ "goo.gl","google.com","twitter.com","google.com","zug.com", "bit.ly", "t.co", "ts.com" ]
 
def byte_to_hex( byteStr ):
    return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()
 
#lets make a real packet to reply to the request!
#who knows, we might end up being a real DNS server, even if we relay the awnsers ;)
def send_dns_reply( pkt, qname ):
        ip = IP()
        udp = UDP()
        ip.src = pkt[ IP ].dst
        ip.dst = pkt[ IP ].src
        udp.sport = pkt[ UDP ].dport
        udp.dport = pkt[ UDP ].sport
       
        #here we create the response
        solved_ip = "31.33.7.31"
        qd = pkt[ UDP ].payload
       
        #an = answer section
        #ar = additional reply
        #nscount=authority section
        dns = DNS( id = qd.id, qr = 1, qdcount = 1, ancount = 1, arcount = 0, nscount = 0, rcode = 0 )
        dns.qd = qd[ DNSQR ]
        dns.an = DNSRR( rrname = qname, type='NS', ttl = 257540, rdlen = 12, rdata = solved_ip )
        #dns.ns = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = solved_ip)
        #dns.ar = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = solved_ip)
        #print "Sending the fake DNS reply to %s:%s" % ( ip.dst, udp.dport )
       
        send( ip/udp/dns )
 
 
#this procedure verifies if it's our super secret chat system or a normal dns reply
def is_this_ours( hostname ):
    #how do we see if this is a request by our chat client?
    #encrypted request is made up of:
    #[valid_prefix][messagenumber].chatstring.domain.com
    #max length is 255, but to be less obvious we should split up the message
    #until we find encoded /n"
    #
    #TODO: messagenumber: to see if you missed anything
    for prefixes in VALID_PREFIX:
        if hostname.startswith( prefixes ):
                for domains in VALID_DOMAINS:
                    if hostname.endswith( domains + "." ):
                        return True
    #not a valid chat message    
    return False
 
#lets get ONLY the message
def strip_msg( hostname ):
    #lets take off the prefix
    for prefixes in VALID_PREFIX:
        if hostname.startswith( prefixes ):
            hostname = hostname[ len( prefixes ): ]
            #lets take off the domain info
            for domains in VALID_DOMAINS:
                if hostname.endswith( domains + "." ):
                    message = hostname[ : -( len( domains ) + 2 ) ]
                    return message
               
def decrypt_AES( message ):
    #now we need to do the AES decryption step
    pwd= hashlib.sha256( PASSWORD ).digest()
    decryptor = AES.new( pwd )
    return decryptor.decrypt( message)
   
#its chat! decode it.
def decrypt_chat( pkt, qname ):
    #ok lets get the data that we need to decrypt.
    message = strip_msg( qname )
    #ok now thats not quite true, so lets cut off the number
    #of the message to see what the sequence number is
    message = message[ message.find( "." ) + 1 : ]
    #ignore the dots
    message = message.replace( ".", "" ).upper()
    #fix padding
    while len( message ) % 8 != 0 :
        message = message + "="
    decrypted_msg=decrypt_AES( base64.b32decode( message ) )
    #print "decrypted:", decrypted_msg
    if decrypted_msg.strip().endswith( TERMINATOR ):
        decrypted_msg = decrypted_msg.replace( TERMINATOR, "" )
        print decrypted_msg
    else:
        sys.stdout.write( decrypted_msg.strip() )
 
def start_server( host, port ):
    s = socket.socket( socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP )
    s.bind( (host, port) )
 
    #workaround to lock port and prevent ICMP unreachables
    s2 = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
    s2.bind( (host, port) )
   
    while 1:
        try:
            data, address = s.recvfrom( 8192 )
            pkt = IP( data )
            proto = pkt.proto
            if ( proto is 0x11 ) and ( pkt[UDP ].dport == port ):
                dns = pkt[ UDP ].payload
                qname = dns[ DNSQR ].qname
                #check if this is our chat or not
                if is_this_ours( qname ):
                    #todo: spoof valid DNS reply that message was received
                    #with some fake record
                    decrypt_chat( pkt, qname )
                    #todo: send reply that client knows we received correct?
                    send_dns_reply( pkt, qname )
                else:
                    #send real reply
                    print "its DNS, but not our stuff..lets just send a reply"
                    send_dns_reply( pkt, qname )
        except ( KeyboardInterrupt, SystemExit ):
            raise
        except:
            traceback.print_exc()
           
if __name__ == '__main__':
    print "DNSChat Proof of Concept Server"
    print "This server will receive DNS requests and if they are valid chat requests, decode and print them."
    print "by SphaZ"
    print ""
    print "starting server on ", host, ":", port
    print ""
    PASSWORD = raw_input( "password: " ).strip()
    start_server( host, port )
