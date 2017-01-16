require 'spec_helper'
 
describe 'fail2ban_config', :type => 'class' do


bantime  = '300'
findtime = '300'
maxretry = '10'
ignoreip = '10.0.0.1/32'
mta      = 'sendmail'
backend  = 'auto'
protocol = 'tcp'
chain    = 'INPUT'
mailto   = ''

no_jails = false
custom_jail = {
    'vsftpd' => {
        'enable'   => 'true',
        'filter'   => 'vsftpd-special',
        'action'   => 'iptables[name=vsftpd, port="20, 21, 10204, 10205"]',
        'logpath'  => '/var/log/secure',
        'maxretry' => '5',
    }
}

no_filter = false
custom_filter = {
    'vsftpd-special' => {
          'filterenable' => 'true',
          'filtername'   => 'vsftpd-special',
          'filtersource' => "puppet:///modules/fail2ban_config/vsftpd-special.conf",
      }
}
    
  context "Should install fail2ban with default jail and filter on RedHat" do
    let(:facts) {
      { :osfamily => 'RedHat',
        :operatingsystem => 'RedHat',
        :operatingsystemrelease => '6.0',
        :concat_basedir => '/tmp',
        :kernel => 'Linux',
        :id => 'root',
        :path => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      }
    }
    let(:params) {
      { :jails => no_jails,
        :bantime => bantime,
        :findtime => findtime,
        :maxretry => maxretry,
        :ignoreip => ignoreip,
        :mta => mta,
        :backend => backend,
        :protocol => protocol,
        :chain => chain,
        :mailto => mailto,
        :filters => no_filter
      }
    }
    
    it do
      should contain_class('fail2ban').with(
          'jails_config' => 'concat',
          'bantime' => bantime,
          'findtime' => findtime,
          'maxretry' => maxretry,
          'ignoreip' => [ignoreip],
          'mta' => mta,
          'backend' => backend,
          'jails_protocol' => protocol,
          'jails_chain' => chain,
          'mailto' => mailto
      )

      should contain_fail2ban__jail('ssh-iptables').with(
          'enable'   => 'true',
          'filter'   => 'sshd-pam',
          'action'   => 'iptables[name=SSH, port=ssh, protocol=tcp]',
          'logpath'  => '/var/log/secure',
          'maxretry' => '3',
      )
      should contain_fail2ban__filter('ssh-pam_auth').with(
          'filterenable' => 'true',
          'filtername'   => 'sshd-pam',
          'filtersource' => "puppet:///modules/fail2ban_config/sshd-pam.conf",
      )
    end
  end  

  context "Should install fail2ban with custom jail/filter and no default jail/filter on RedHat" do
    let(:facts) {
      { :osfamily => 'RedHat',
        :operatingsystem => 'RedHat',
        :operatingsystemrelease => '6.0',
        :concat_basedir => '/tmp',
        :kernel => 'Linux',
        :id => 'root',
        :path => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      }
    }
    let(:params) {
      { :jails => custom_jail,
        :bantime => bantime,
        :findtime => findtime,
        :maxretry => maxretry,
        :ignoreip => ignoreip,
        :mta => mta,
        :backend => backend,
        :protocol => protocol,
        :chain => chain,
        :mailto => mailto,
        :filters => custom_filter
      }
    }
    
    it do
      should contain_class('fail2ban').with(
          'jails_config' => 'concat',
          'bantime' => bantime,
          'findtime' => findtime,
          'maxretry' => maxretry,
          'ignoreip' => [ignoreip],
          'mta' => mta,
          'backend' => backend,
          'jails_protocol' => protocol,
          'jails_chain' => chain,
          'mailto' => mailto
      )

      should_not contain_fail2ban__jail('ssh-iptables')

      should contain_fail2ban__jail('vsftpd').with(
          'enable'   => 'true',
          'filter'   => 'vsftpd-special',
          'action'   => 'iptables[name=vsftpd, port="20, 21, 10204, 10205"]',
          'logpath'  => '/var/log/secure',
          'maxretry' => '5',
      )

      should_not contain_fail2ban__filter('ssh-pam_auth')

      should contain_fail2ban__filter('vsftpd-special').with(
          'filterenable' => 'true',
          'filtername'   => 'vsftpd-special',
          'filtersource' => "puppet:///modules/fail2ban_config/vsftpd-special.conf",
      )

    end
  end 


  context "Should install fail2ban with no default jail or filters on Debian" do
    let(:facts) {
      { :osfamily => 'Debian',
        :operatingsystem => 'Debian',
        :operatingsystemrelease => '6.0',
        :concat_basedir => '/tmp',
        :kernel => 'Linux',
        :id => 'root',
        :path => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      }
    }
    let(:params) {
      { :jails => no_jails,
        :bantime => bantime,
        :findtime => findtime,
        :maxretry => maxretry,
        :ignoreip => ignoreip,
        :mta => mta,
        :backend => backend,
        :protocol => protocol,
        :chain => chain,
        :mailto => mailto
      }
    }
    
    it do
      should contain_class('fail2ban').with(
          'jails_config' => 'concat',
          'bantime' => bantime,
          'findtime' => findtime,
          'maxretry' => maxretry,
          'ignoreip' => [ignoreip],
          'mta' => mta,
          'backend' => backend,
          'jails_protocol' => protocol,
          'jails_chain' => chain,
          'mailto' => mailto
      )

      should_not contain_fail2ban__jail('ssh-iptables')
      should_not contain_fail2ban__filter('ssh-pam_auth')

    end
  end

end
