-- dextra.lua
-- DExtra Protocol
local proto_shortname = "dextra"
local proto_longname = "DExtra Protocol"

p_dextra = Proto ( proto_shortname, proto_longname)

function p_dextra.dissector ( buffer, pinfo, tree)
	-- Validate packet length
	if ( buffer:len() < 3 ) then return end
	
	-- Set protocol name
	pinfo.cols.protocol = proto_shortname:upper()

	-- Subtree
	local subtree = tree:add( p_dextra, buffer(), proto_longname)
	
	if( buffer( 0,4):string() == "DSVT") then
		-- DVST Frame
		Dissector.get("dsvt"):call( buffer, pinfo, tree)
	end
end

local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add( 30001, p_dextra)


