jwafw00f
========

A java version of jwafw00f by Syed Afzal.
To do its magic, jwafw00f does the following:

Sends a normal HTTP request and analyses the response; this identifies a number of WAF solutions
If that is not successful, it sends a number of (potentially malicious) HTTP requests and uses simple logic to deduce which WAF it is
If that is also not successful, it analyses the responses previously returned and uses another simple algorithm to guess if a WAF or security solution is actively responding to our attacks.
