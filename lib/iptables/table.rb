module IPTables
  class Table
    DEFAULT_CHAINS = {
      :filter => [ :INPUT, :FORWARD, :OUTPUT ],
      :nat => [ :PREROUTING, :OUTPUT, :POSTROUTING ],
      :mangle => [ :PREROUTING, :OUTPUT, :INPUT, :FORWARD, :POSTROUTING ],
      :raw => [ :PREROUTING, :OUTPUT ]
    }
    DEFAULT_TARGETS = [ :ACCEPT, :DROP, :QUEUE, :RETURN ]
    BUILTIN_TARGETS = [ :DNAT, :MASQUERADE, :REJECT, :TCPMSS ]
    
    attr_reader :name
    
    def initialize(name)
      @name = name
      @chains = {}
      @blocks = []
    end
    
    def has_chain?(name)
      @chains.include?(name) or DEFAULT_TARGETS.include?(name) or BUILTIN_TARGETS.include?(name)
    end
    
    def add_block(&block)
      @blocks << block
    end
    
    def configure
      obj = Object.new
      table = self
      chains = @chains
      obj.define_singleton_method :chain, do |name, &chain_block|
        policy = nil
        if name.is_a?(Hash)
          policy = name.values.first
          name = name.keys.first
        end
        chains[name.intern] ||= Chain.new name, table
        chains[name.intern].policy = policy if policy
        raise "Cannot set policy for user-defined chain" if policy and !DEFAULT_CHAINS[table.name].include?(name)
        chains[name.intern].add_block &chain_block
      end
      @blocks.each do |block|
        obj.instance_eval &block
      end
      
      chains.each do |name,chain|
        chain.do_blocks
      end
    end
    
    def print(only_chain=nil)
      @chains.each do |name,chain|
        if only_chain.nil? or only_chain.to_s == name.to_s
          puts "iptables -t #{@name} -P #{name} #{chain.policy}" if DEFAULT_CHAINS[@name].include?(name) and chain.policy
        end
      end
      @chains.each do |name,chain|
        if only_chain.nil? or only_chain.to_s == name.to_s
          unless DEFAULT_CHAINS[@name].include?(name)
            puts "iptables -t #{@name} -N #{name} || true"
          end
        end
      end
      @chains.each do |name,chain|
        if only_chain.nil? or only_chain.to_s == name.to_s
          puts "iptables -t #{@name} -F #{name}"
        end
      end
      @chains.each do |name,chain|
        if only_chain.nil? or only_chain.to_s == name.to_s
          chain.print
        end
      end
    end
  end
end