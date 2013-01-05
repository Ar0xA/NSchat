'''
Created on Dec 28, 2012
 
@author: Artien "SphaZ" cyberphaz (at) gmail (dot) com
'''
import base64, hashlib, random, subprocess, shlex, sys
from scapy.all import *
from Crypto.Cipher import AES
 
 
BLOCK_SIZE = 16
PADDING = " "
PASSWORD = ""
SERVER = ""
MESSAGE = 0
TERMINATOR = "[{]"
 
#specify your valid prefix to recognise chat messages
#list of prefixes?
VALID_PREFIX = [ "www1-", "data", "img", "www.cdn-", "cnd-", "images.svr-", "static-", "www.svr" ]
#list of valid domains that we "handle" the shorter the better
#more space for messages:)
VALID_DOMAINS = [ "goo.gl", "google.com", "twitter.com", "google.com", "zug.com", "bit.ly", "t.co", "ts.com" ]
 
 
def encrypt_string( string_in ):
    #padding
    if len( string_in ) % BLOCK_SIZE != 0:
        string_in += PADDING * (BLOCK_SIZE - len( string_in ) % BLOCK_SIZE)
    pwd = hashlib.sha256( PASSWORD ).digest()
    cipher = AES.new( pwd )
    encodedAES = base64.b32encode( cipher.encrypt( string_in ) )
    return encodedAES
 
def send_dns_request(dns_query_domain):
    cmd = "dig @" + SERVER + " " + dns_query_domain
    proc = subprocess.Popen( shlex.split( cmd) , stdout = subprocess.PIPE )
    out, err = proc.communicate()
    #TODO: check for server saying they received our reply correct?
 
def send_dns( string_in ):  
    #encrypt and make lowercase
    crypted_str = encrypt_string( string_in ).lower()
    #remove padding
    crypted_str = crypted_str.replace( "==", "" )
    #TODO: insert some random dots
    random_prefix = VALID_PREFIX [ random.randint( 0,len( VALID_PREFIX ) -1 ) ]
    random_suffix = VALID_DOMAINS [random.randint(0, len( VALID_DOMAINS ) -1 ) ]
    dns_query_domain =random_prefix + str( MESSAGE ) + "." + crypted_str + "." + random_suffix
    send_dns_request( dns_query_domain )
 
def encode_string( string_in ):
    #first, lets figure out in how many blocks we need to cut the message
    #for obscurity's sake, lets not use more than 15-30 chat-characters per request
    #if its smaller then that, just go though
    #
    #on the server side we need to know when the message ends, this is done by
    # [{]
    max_size = random.randint( 5,16 )
    remainder = string_in
    while len( remainder ) > max_size:
        random_val = random.randint( 5, max_size )
        send_dns( remainder[ :random_val ] )
        remainder = remainder[ random_val: ]
    if len( remainder ) < max_size:
        send_dns( remainder + TERMINATOR )
                 
if __name__ == '__main__':
    print "DNSChat Proof of Concept Client"
    print "This client will obfuscate and encrypt chat into valid looking DNS requests"
    print "by SphaZ"
    print ""
   
    PASSWORD = raw_input( "password: " ).strip()
    SERVER = raw_input( "server ip: " ).strip()
    print "(type quit to stop)"
    while True:
        string_to_send = raw_input( "[to send]> " )
        if string_to_send == "quit":
            sys.exit( 0 )
        MESSAGE += 1
        encode_string( string_to_send )
