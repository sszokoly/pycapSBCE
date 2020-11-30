# pycapSBCE

Call and flow monitoring tool for Avaya SBCE.

## Intro

SIP trunking is becoming the global standard and therefore an integral part of the telecommunication infrastructure in most modern business environment. A critical component of this solution is the Session Border Controller (SBC) which serves as a demarcation point between the Provider and the Enterprise therefore all SIP signaling and media, when authorized, pass through it. Avaya's Unified Communication portfolio offers the ASBCE which is a flexible, fit for purpose SBC for Enterprises.

## Business Problem

Every now and then problems can arise which require in-depth investigation across board and the SBC is not exempt from it. One of the most common issues of VoIP calls is poor or complete loss of audio one-way or in both directions between caller and callee, one if which may be one side of the SBC while the other is on the opposite side. The constant monitoring of SIP trunks which carry tens of thousands of calls every day for the purpose of troubleshooting audio issues is more often than not a challenging task. While the ASBCE can provide incident report for situations when media inactivity is detected the practical value of this functionality is limited due its uneasiness in finding the reports for the call you want and the lack
of information the reports provide about the media resources involved and media data received and sent.  

In summary to establish quickly whether the ASBCE several hours ago was or at that very moment is receiving media packets from
all resources involved in a call and it is properly relaying those packets between caller and caller is just not possible. It is also a laborious exercise to tell if the root cause of poor audio quality of an active call is possibly related to poor network performance (high packet-loss, jitter, skew, etc) or not.

## Solution

This tool is aiming to address the shortcomings mentioned above by:

- retaining in memory the negotiated and detected addresses/ports used for audio media of the last 1000 calls
- keeping the most important counters of RTP flows of those calls 
- providing easy access to all this information real-time through a TUI interface
- dumping data from memory to disk regularly (at every 1000 calls by default) automatically but in a rotating fashion 
- activating packet trace (tcpdump) for selected calls upon request or automatically using capture filters
- rendering RTP stream statistics for captured packet traces which, in addition to those provided by tshark, also include DSCP, RTP skew and RFC2388 payload detection
- allowing dumps to be read in later to look up media connection info and RTP flow counters for calls which happened several hours earlier but were only reported to have had audio issues later

## How it works

It makes use of the standard log files and commands available to any system administrator in Linux shell with root access.
SIP call and media information are obtained from `tracesbc_sip` log files. Flow counters are gathered from the output of `showflow` command. Finally the majority of RTP stream statistics except those mentioned above - are extracted using `tshark`'s `rtp,streams` functionality.

## Options

```
  -h, --help      show this help message and exit
  -a, --autodump  to dump data every time when max number of calls is reached
  -n <number>     number of calls retained in memory
                  default 1000, maximum 2000
  -c <number>     number of packets captured in a tcpdump sample
                  default 10000, maximum 20000 (on each iface)
  -f <secs>       number of seconds between flow updates
                  default 3, min 2
  -t <secs>       number of seconds between tshark updates
                  default 3, min 2
  -i <hrs>        number of hours worth of dumps kept on disk
                  default 8, max 24
  -b, --black     use mono color
  -g, --green     use mono green color
```

## Demo

![alt text](./images/pycapSBCE.gif?raw=true "pycapSBCE")
