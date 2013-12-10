Description:
-------------
These scripts probe The Great Firewall of China (GFW)
with a censored keyword (peacehall). If a probe triggers 
GFW, we will observe injected TCP resets from GFW in our 
incoming traffic. If we don't see resets, this means that 
the corresponding probe can be extended into a circumvention
scheme. We used these probes to incrementally infer the 
content inspection model of GFW in our FOCI 13 work [1].

Note: I have a repo 'InjectedResetDetector' on my GitHub
page which can be used to identify injected TCP resets.
I have not tested it extensively; for our FOCI work, we 
sniffed/recorded all traffic on our machine which we later
manually inspected for resets from GFW (we also were able
to capture traffic on our host; we assumed that the 
resets that did not originate from the server <our host>
were injected by GFW).

[1] Sheharbano Khattak, Mobin Javed, Philip D. Anderson and Vern Paxson. 
Towards Illuminating a Censorship Monitor's Model to Facilitate Evasion, 
in proceedings of the 3rd USENIX Workshop on Free and Open Communications 
on the Internet (FOCI), August 2013. 
https://www.usenix.org/conference/foci13/towards-illuminating-censorship-monitors-model-facilitate-evasion 

How to use:
-------------- 
For IP probes:
python ip_prober.py test_name

For TCP probes:
python tcp_prober.py test_name

test_name: A string that represents which probe/test to
perform. Description of tests can be seen in the source
code as comments.

Limitations:
---------------
If the keyword 'peacehall' is not censored, source code
needs to be tweaked. This will require some effort for 
the tests that manipulate segment/fragment overlap.

TODO:
----------
1. It would be nice if we can get info about whether reset
from GFW was observed after a test. This will tell us right 
away if the test succeeded or not.

2. Make this generic; can we accept censored keyword as an
argument and tailor the probes accordingly?

---------------
That's all. I'll be happy to answer any queries you may have.

Sheharbano 
(Sheharbano.Khattak@cl.cam.ac.uk)
