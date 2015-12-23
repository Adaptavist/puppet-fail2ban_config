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
        'filter'   => 'vsftpd',
        'action'   => 'iptables[name=vsftpd, port="20, 21, 10204, 10205"]',
        'logpath'  => '/var/log/secure',
        'maxretry' => '5',
    }
}
    
  context "Should install fail2ban with default jail on RedHat" do
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
        :mailto => mailto
      }
    }
    
    it do
      should contain_class('fail2ban').with(
          'jails_config' => 'concat',
          'bantime' => bantime,
          'findtime' => findtime,
          'maxretry' => maxretry,
          'ignoreip' => ignoreip,
          'mta' => mta,
          'backend' => backend,
          'jails_protocol' => protocol,
          'jails_chain' => chain,
          'mailto' => mailto
      )

      should contain_fail2ban__jail('ssh-iptables').with(
          'enable'   => 'true',
          'filter'   => 'sshd',
          'action'   => 'iptables[name=SSH, port=ssh, protocol=tcp]',
          'logpath'  => '/var/log/secure',
          'maxretry' => '3',
      )
    end
  end  

  context "Should install fail2ban with custom jail and no default jail on RedHat" do
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
        :mailto => mailto
      }
    }
    
    it do
      should contain_class('fail2ban').with(
          'jails_config' => 'concat',
          'bantime' => bantime,
          'findtime' => findtime,
          'maxretry' => maxretry,
          'ignoreip' => ignoreip,
          'mta' => mta,
          'backend' => backend,
          'jails_protocol' => protocol,
          'jails_chain' => chain,
          'mailto' => mailto
      )

      should_not contain_fail2ban__jail('ssh-iptables')

      should contain_fail2ban__jail('vsftpd').with(
          'enable'   => 'true',
          'filter'   => 'vsftpd',
          'action'   => 'iptables[name=vsftpd, port="20, 21, 10204, 10205"]',
          'logpath'  => '/var/log/secure',
          'maxretry' => '5',
      )

    end
  end  

  context "Should install fail2ban with no default jail on Debian" do
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
          'ignoreip' => ignoreip,
          'mta' => mta,
          'backend' => backend,
          'jails_protocol' => protocol,
          'jails_chain' => chain,
          'mailto' => mailto
      )

      should_not contain_fail2ban__jail('ssh-iptables')
    end
  end

end
