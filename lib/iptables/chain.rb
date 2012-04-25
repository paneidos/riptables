module IPTables
  class Chain
    attr_accessor :policy
    
    def initialize(name,table=nil)
      @name = name
      @policy = nil
      @blocks = []
      @table = table
      @rules = []
    end
    
    def add_block(&block)
      @blocks << block if block_given?
    end
    
    def add_rule rule
      @rules << rule
    end
    
    def can_call_chain?(other_chain)
      @table.has_chain? other_chain
    end
    
    def do_blocks
      chain = self
      @blocks.each do |block|
        rule = Rule.new chain
        rule.instance_eval &block
      end
    end
    
    def print
      @rules.each do |rule|
        puts "iptables -t #{@table.name} -A #{@name} #{rule.to_command}"
      end
    end
  end
end