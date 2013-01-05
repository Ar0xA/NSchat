NSchat
======

A while ago a friend of mine on IRC challenged me to write a program for an idea of mine, to make a chat client and server using valid DNS requests.

It took me a while longer than I expected, but I wrote a proof of concept server and client that does the following:

- Exchange valid DNS queries and replies;
- base32 AES encrypted chat with password;
- Detection evasion by randomizing length, prefixes and domains.

Possible TODO's:
- The following could be done to make this a more viable application to be used in the real world:
- send replies on queries that include data from the server acknowledging that the data was received;
- Handling lost packets;
- Integrate server and client into one multi-threaded application;
- IPv6 (even less monitored!)
- If it's not a valid chat packet, return the actual legit DNS record by forwarding Google/OpenDNS's reply.
- Create replies differently, so that it's harder to spot that it's not a real reply
- Inserting dots '.' to break up the query string to make it look like different domains
- write it in a language that's easier to use in a multi-platform environement

Feel free to modify any of the code below, but how about being nice and mention me :)
