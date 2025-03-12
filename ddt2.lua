-- ddt2.lua - D-Rats Data Transport Protocol


-- Some module-specific constants
local proto_shortname = "ddt2"
local proto_fullname  = "D-Rats Data Transport 2"

-- Protocol Definition
p_ddt2 = Proto ( proto_shortname, proto_fullname)

local DDT2_ESC_CHAR = 0x3D
local DDT2_OFFSET   = 0x40

function p_ddt2.dissector(buffer, pinfo, tree)
	local length = buffer:len()
	
	if ( length <= 10 and buffer( 0, 5):string() ~= "[SOB]" and buffer( length-5, 5):string() ~= "[EOB]" ) then return end
	
	local subtree = tree:add( p_ddt2, buffer())
	pinfo.cols.protocol = string.upper( proto_shortname)
	
	local ba_payload = ByteArray.new()
	
	local i=5
	while ( i < length-5 ) do
		if ( buffer( i, 1):uint() == DDT2_ESC_CHAR  and i < length-6 ) then
			-- Append the next escaped character
			ba_payload:append( ByteArray.new( string.format("%02X", bit.bxor (buffer(i+1,1):uint(), DDT2_OFFSET)) ) )
			i = i + 1
		else
			-- Add the current character
			ba_payload:append( ByteArray.new( string.format("%02X", buffer(i,1):uint()) ) )
		end
	
		i = i + 1
	end
	
	local payload_tvb = ba_payload:tvb( "DDT Payload" )
	subtree:add( p_ddt2, payload_tvb(), "Decoded yEnc Payload")
	
end

