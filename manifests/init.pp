# = Class: fail2ban_config
#
class fail2ban_config(
    $jails    = false,
    $bantime  = '600',
    $findtime = '600',
    $maxretry = '6',
    $ignoreip = ['127.0.0.1/8'],
    $mta      = 'sendmail',
    $backend  = 'auto',
    $protocol = 'tcp',
    $chain    = 'INPUT',
    $mailto   = '',
    ) {

    # if a jail configuration has been provided use it
    if ($jails != false and $jails != 'false') {
        $real_jails = $jails
    } else {
        case $::osfamily {
            # if not and this is a RedHat based system define a basic SSH jail
            RedHat: {
                $real_jails = {
                    'ssh-iptables' => {
                        enable   => 'true',
                        filter   => 'sshd',
                        action   => 'iptables[name=SSH, port=ssh, protocol=tcp]',
                        logpath  => '/var/log/secure',
                        maxretry => '3',
                    }
                }
            }
            # if not and its a Debian based system then do nothing as by default a SSH jail is configured out-of-the box
            Debian: {
                $real_jails = undef
            }
            default: {
                fail("fail2ban_config - Unsupported Operating System family: ${::osfamily}")
            }
        }
    }

    # if the ignore ip value provided is an array use as is
    if (is_array($ignoreip)) {
        $real_ignoreip = $ignoreip
    }
    # if however it is not an array convert it into one (assuming that the source string was comma delimited)
    else {
        $real_ignoreip  = split($ignoreip, ',')
    }

    # include the fail2ban class to install fail2ban
    class { 'fail2ban':
        jails_config   => 'concat',
        mailto         => $mailto,
        bantime        => $bantime,
        mta            => $mta,
        backend        => $backend,
        maxretry       => $maxretry,
        findtime       => $findtime,
        jails_protocol => $protocol,
        jails_chain    => $chain,
        ignoreip       => $real_ignoreip,
    }

    # if the is a jail set make sure its in a hash
    if ( $real_jails ) {
        # if the jail config is not a hash 
        if ( !is_hash($real_jails) ) {
            fail('fail2ban_config - The jail configuration provided is not a hash')
        }
        
        # create the jail(s)
        create_resources(fail2ban::jail , $real_jails)
    }

}