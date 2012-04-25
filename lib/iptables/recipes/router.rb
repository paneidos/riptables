table :raw do
  chain :PREROUTING => :ACCEPT do
    interface_in $WAN do
      call :zone_wan_notrack
    end
    interface_in $LAN do
      call :zone_lan_notrack
    end
  end
  chain :OUTPUT => :ACCEPT
  chain :zone_lan_notrack
  chain :zone_wan_notrack
end

table :nat do
  chain :PREROUTING => :ACCEPT do
    interface_in $WAN do
      call :zone_wan_prerouting
    end
    interface_in $LAN do
      call :zone_lan_prerouting
    end
    call :prerouting_rule
  end
  chain :POSTROUTING => :ACCEPT do
    call :port_forwards_lan_post
    call :postrouting_rule
    call :zone_wan_nat
  end
  chain :OUTPUT => :ACCEPT do
    #
  end
  chain :postrouting_rule
  chain :prerouting_lan
  chain :prerouting_rule
  chain :prerouting_wan
  
  chain :port_forwards_lan_post
  chain :port_forwards_lan_pre
  chain :port_forwards_wan_pre

  chain :zone_lan_nat do
    interface_out $LAN do
      jump :MASQUERADE
    end
  end
  chain :zone_lan_prerouting do
    call :port_forwards_lan_pre
    call :prerouting_lan
  end
  chain :zone_wan_nat do
    interface_out $WAN do
      jump :MASQUERADE
    end
  end
  chain :zone_wan_prerouting do
    call :port_forwards_wan_pre
    call :prerouting_wan
  end
end

# Default table
table :filter do
  chain :INPUT => :ACCEPT do
    state :RELATED, :ESTABLISHED do
      accept
    end
    interface_in :lo do
      accept
    end
    proto :tcp do
      tcp :syn => true do
        call :syn_flood
      end
    end
    call :input_rule
    call :input
    # interface_in :vpn do
    #   accept
    # end
  end
  chain :FORWARD => :DROP do
    call :zone_wan_MSSFIX
    state :RELATED, :ESTABLISHED do
      accept
    end
    call :port_forwards
    call :forwarding_rule
    call :forward
    call :reject
  end
  chain :OUTPUT => :ACCEPT do
    state :RELATED, :ESTABLISHED do
      accept
    end
    interface_out :lo do
      accept
    end
    call :output_rule
    call :output
  end
  
  chain :port_forwards
  
  chain :allow_ppp do
  end
  
  chain :forward do
    interface_in $LAN do
      call :zone_lan_forward
    end
    interface_in $WAN do
      call :zone_wan_forward
    end
  end
  chain :forwarding_lan do
  end
  chain :forwarding_rule do
    call :allow_ppp
  end
  chain :forwarding_wan do

  end
  chain :input do
    interface_in $LAN do
      call :zone_lan
    end
    interface_in $WAN do
      call :zone_wan
    end
  end
  chain :input_lan do

  end
  chain :input_rule do
    call :allow_ppp
  end
  
  chain :pptp_server do
    proto :gre do
      accept
    end
    proto :tcp do
      tcp :dport => 1723 do
        accept
      end
    end
  end
  
  chain :input_wan do
  end
  chain :output do
    call :zone_lan_ACCEPT
    call :zone_wan_ACCEPT
  end
  chain :output_rule do
    call :allow_ppp
  end
  chain :reject do
    proto :tcp do
      reject :with => :tcp_reset
    end
    reject :with => :icmp_port_unreachable
  end
  chain :syn_flood do
    proto :tcp do
      tcp :syn => true do
        limit "25/sec", :burst => 50 do
          jump :RETURN
        end
      end
    end
    drop
  end
  chain :zone_lan do
    call :input_lan
    jump :zone_lan_ACCEPT
  end
  chain :zone_lan_ACCEPT do
    interface $LAN do
      accept
    end
  end
  chain :zone_lan_DROP do
    interface $LAN do
      drop
    end
  end
  chain :zone_lan_MSSFIX do
    interface_out $LAN do
      proto :tcp do
        tcp :tcp_flags => "SYN,RST SYN" do
          jump :TCPMSS, :clamp_mss_to_pmtu => true
        end
      end
    end
  end
  chain :zone_lan_REJECT do
    interface $LAN do
      jump :reject
    end
  end
  chain :zone_lan_forward do
    call :zone_wan_ACCEPT
    call :forwarding_lan
    call :zone_lan_REJECT
  end

  chain :zone_wan do
    call :input_wan
    proto :udp do
      udp :dport => 68 do
        accept
      end
      udp :dport => 53 do
        reject :with => :icmp_port_unreachable
      end
    end
    jump :zone_wan_REJECT
  end
  chain :zone_wan_ACCEPT do
    interface $WAN do
      accept
    end
  end
  chain :zone_wan_DROP do
    interface $WAN do
      drop
    end
  end
  chain :zone_wan_MSSFIX do
    interface_out $WAN do
      proto :tcp do
        tcp :tcp_flags => "SYN,RST SYN" do
          jump :TCPMSS, :clamp_mss_to_pmtu => true
        end
      end
    end
  end
  chain :zone_wan_REJECT do
    interface $WAN do
      jump :reject
    end
  end
  chain :zone_wan_forward do
    call :forwarding_wan
    jump :zone_wan_REJECT
  end
end

define_rule :port_forward_tcp do |external_port,internal_host,internal_port|
  # Accept the packets
  table :filter do
    chain :port_forwards do
      destination internal_host do
        tcp :dport => internal_port do
          accept
        end
      end
    end
  end
  
  # Forward the packets
  table :nat do
    # Loopback forwarding to make it work from LAN
    chain :port_forwards_lan_pre do
      destination $EXTERNAL_IP do
        tcp :dport => external_port do
          jump :DNAT, :to_destination => "#{internal_host}:#{internal_port}"
        end
      end
    end
    
    # Masquerade the loopback forwarding, so the packets can get back
    chain :port_forwards_lan_post do
      source $LOCAL_NET do
        tcp :dport => internal_port do
          destination internal_host do
            jump :MASQUERADE
          end
        end
      end
    end
    
    # Forward from WAN (aka 'The Internet')
    chain :port_forwards_wan_pre do
      tcp :dport => external_port do
        jump :DNAT, :to_destination => "#{internal_host}:#{internal_port}"
      end
    end
  end
end

define_rule :port_forward_udp do |external_port,internal_host,internal_port|
  # Accept the packets
  table :filter do
    chain :port_forwards do
      destination internal_host do
        udp :dport => internal_port do
          accept
        end
      end
    end
  end

  # Forward the packets
  table :nat do
    # Loopback forwarding to make it work from LAN
    chain :port_forwards_lan_pre do
      destination $EXTERNAL_IP do
        udp :dport => external_port do
          jump :DNAT, :to_destination => "#{internal_host}:#{internal_port}"
        end
      end
    end
  
    # Masquerade the loopback forwarding, so the packets can get back
    chain :port_forwards_lan_post do
      source $LOCAL_NET do
        udp :dport => internal_port do
          destination internal_host do
            jump :MASQUERADE
          end
        end
      end
    end
  
    # Forward from WAN (aka 'The Internet')
    chain :port_forwards_wan_pre do
      udp :dport => external_port do
        jump :DNAT, :to_destination => "#{internal_host}:#{internal_port}"
      end
    end
  end
end

define_rule :forward_port do |port,target|
  external_port = port
  internal_host = target
  internal_port = port
  protos = [ :tcp ]
  if target.is_a?(Hash)
    internal_host = target[:to]
    internal_port = target[:port] || port
    if target[:proto] == :tcp or target[:proto] == :udp
      protos = [ target[:proto] ]
    elsif target[:proto].is_a?(Array)
      protos = target[:proto] & [:tcp,:udp]
    end
  end
  if protos.include?(:tcp)
    port_forward_tcp external_port, internal_host, internal_port
  end
  if protos.include?(:udp)
    port_forward_udp external_port, internal_host, internal_port
  end
end

define_rule :open_wan_port do |port|
  table :filter do
    chain :input_wan do
      tcp :dport => port do
        accept
      end
    end
  end
end

define_rule :allow_ppp do
  table :filter do
    chain :allow_ppp do
      interface "ppp+" do
        accept
      end
    end
  end
end

define_rule :pptp_server do
  allow_ppp
  table :filter do
    chain :input_wan do
      call :pptp_server
    end
  end
end
