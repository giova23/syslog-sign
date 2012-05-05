syslog-sign
===========

Open Source Syslog Sign (id est: rfc5848 implementation) addon for syslog-ng

This project aims to implement an rfc5848 compliant syslog-signer,
to be called from (initially, at least) syslog-ng (open source version).

The idea is to have something like this in the syslog-ng.conf file:

destination d_program_syslog_sign {
        program("/usr/local/sbin/syslog-sign.pl -f /usr/local/etc/syslog-sign.conf"
                flags("syslog-protocol")
        );
};

in order to properly generate all rfc5848 records (Signature Blocks will
be the first implemented, then Certificate Blocks and Signature groups 
will be the last, in our intentions).

Some (runtime configurable) deviations from the standards may be present.
(we intend to add an encryption layer to the standard)

Giovanni Faglioni &lt; giova at faglioni dot it &gt; 

The code will be under an Open Source License (GPL, presumably)

