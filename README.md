syslog-sign
===========

Open Source "Signed Syslog Messages" (id est: rfc5848 implementation) addon for syslog-ng.

This project aims to implement an rfc5848 compliant syslog-signer,
to be used with (initially, at least) syslog-ng (open source version).

The idea is to have something like this in the syslog-ng.conf file:

destination d_program_syslog_sign {<br/>
        program("/usr/local/sbin/syslog-sign.pl -f /usr/local/etc/syslog-sign.conf" 
                flags("syslog-protocol")
        );<br/>
};<br/>

in order to properly generate all rfc5848 records.

Signature Blocks are already implemented, Certificate Blocks 
and Signature groups still missing.
We have (optional) encryption for the output (this is outside the standard,
and suboptimal)

Some (runtime configurable) deviations from the standards are present, as the 
previous optional output encryption layer.

Giovanni Faglioni &lt; giova at faglioni dot it &gt; 

The code is under the GPLv2 or, at your option, any later version.

** INSTALL **

  prerequisites (for ubuntu 14.04 LTS):
  apt-get install libcrypt-dsa-perl libcrypt-openssl-dsa-perl libtry-tiny-perl libpath-tiny-perl libfile-path-tiny-perl

  copy syslog-sign.pl in /usr/local/sbin/syslog-sign.pl
  copy syslog-sign.conf in /usr/local/etc/syslog-sign.conf
  edit syslog-sign.conf to suit your needs. :)
  add

destination d_program_syslog_sign {<br/>
       &nbsp;&nbsp; program("/usr/local/sbin/syslog-sign.pl -f /usr/local/etc/syslog-sign.conf" 
       &nbsp;&nbsp;&nbsp;&nbsp;         flags("syslog-protocol")
       &nbsp;&nbsp; );<br/>
};<br/>

  to your syslog-ng.conf file, and add the d_program_syslog_sign destination to at least one log {} section, for example:

log {
    &nbsp;&nbsp;    source(local);
    &nbsp;&nbsp;    filter(f_auth_authpriv);
    &nbsp;&nbsp;    destination(d_program_syslog_sign);
};
