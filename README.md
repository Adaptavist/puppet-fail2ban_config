
# fail2ban_config Module

## Overview

The **puppet-fail2ban_config** module installs and configures fail2ban on any node where it has been included, 
it allows jails to be defined in hiera

## Configuration

Each of the configuration params below (except jails) is setting default values, they can be overwritten in individual jails

`fail2ban_config::bantime:` 

The amount of time a host will be banned for, defaults to **600**

`fail2ban_config::findtime:`
The amount of time (from now backwards) to analyse. defaults to **600**

`fail2ban_config::maxretry:`

The number of failures before a host get banned, defauts to **6**

`fail2ban_config::ignoreip:`

A list of IP addresses/CIDR masks or hostnames to ignore, this needs to be an array, however if a not the module will attempt to convert into a array assuming it is working with a comma delimited string, defaults to **['127.0.0.1/8']** 

`fail2ban_config::mta:`

The mail transport agent to use for notification, defaults to **sendmail**

`fail2ban_config::backend:`

The backend used to get files modification, defaults to **auto**

`fail2ban_config::protocol:`

The default protocol, defaults to **tcp**

`fail2ban_config::chain:`

The iptables chain where jumps would need to be added, defaults to **INPUT**

`fail2ban_config::mailto:`

'The email address to send notification to (if action_mw is used), defaults to **blank string**

`fail2ban_config::jails:`

A hash of jails to create, if set to false no jails wil be defined for Debian based systems however a basic SSH jail will be defined for redHat based systems, defaults to **false** 

## Example Hiera Usage:
 
    fail2ban_config::jails: false
    fail2ban_config::bantime: '600'
    fail2ban_config::findtime: '600'
    fail2ban_config::maxretry: '6'
    fail2ban_config::ignoreip: ['127.0.0.1/8']
    fail2ban_config::mta: 'sendmail'
    fail2ban_config::backend: 'auto'
    fail2ban_config::protocol: 'tcp'
    fail2ban_config::chain: 'INPUT'
    fail2ban_config::mailto: ''


## Dependencies

This module depends on the following puppet modules:

* fail2ban
