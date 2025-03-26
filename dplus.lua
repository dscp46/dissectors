-- dplus.lua - DPlus Protocol
local proto_shortname = "dplus"
local proto_longname = "DPlus Protocol"
p_dplus = Proto ( proto_shortname, proto_longname)

local ascp_type = {
	[0]= "Control Item",
	[1]= "Current Control Item",
	[2]= "Control Item Range",
	[3]= "Data ACK",
	[4]= "D-Star Voice Trunk data",
	[5]= "Data Item 1",
	[6]= "Query",
	[7]= "Data Item 3",
}

local ctl_types = {
	[0x0018]= "State transition",
}

local query_types = {
	[0x0003]= "Version",
	[0x0004]= "Authentication",
	[0x0005]= "Linked Repeaters List",
	[0x0105]= "Linked Repeaters List (Reply)",
	[0x0006]= "Connected Users List",
	[0x0007]= "Last Heard List",
	[0x0008]= "Date",
}

local state_trans = {
	[0]= "Idle",
	[1]= "Active",
}

local auth_result = {
	["OKRO"]= "Success (read-only)",
	["OKRW"]= "Success",
	["BUSY"]= "No available slot",
	["FAIL"]= "Failure",
}

local client_type = {
	["A"]="DVAP",
	["D"]="Dongle",
	["H"]="Hotspot",
}

-- Fields
local pf_dplus_ascp_type      = ProtoField.uint16 ( proto_shortname .. ".ascp.type" , "ASCP Type", base.DEC, ascp_type, 0xE000)
local pf_dplus_ascp_length    = ProtoField.uint16 ( proto_shortname .. ".ascp.length" , "Payload Length", base.DEC, nil, 0x1FFF)
local pf_dplus_keepalive       = ProtoField.uint8 ( proto_shortname .. ".keepalive" , "Keepalive", base.DEC)
local pf_dplus_ctl_code       = ProtoField.uint16 ( proto_shortname .. ".ctl" , "Control Code", base.HEX)
local pf_dplus_ctl_state       = ProtoField.uint8 ( proto_shortname .. ".state" , "New state", base.HEX, state_trans)
local pf_dplus_query_type     = ProtoField.uint16 ( proto_shortname .. ".query.type" , "Type", base.HEX, query_types)
local pf_dplus_query_entries  = ProtoField.uint16 ( proto_shortname .. ".query.entries" , "Number of entries", base.DEC)
local pf_dplus_auth           = ProtoField.string ( proto_shortname .. ".auth" , "Authentication Result", base.ASCII, auth_result)
local pf_dplus_dongle_serial  = ProtoField.string ( proto_shortname .. ".dongle.sn" , "Dongle Serial Number", base.ASCII)
local pf_dplus_epoch          = ProtoField.uint32 ( proto_shortname .. ".epoch" , "*NIX Epoch", base.ASCII)

p_dplus.fields = {
	pf_dplus_ascp_type, pf_dplus_ascp_length, pf_dplus_keepalive, pf_dplus_ctl_code, pf_dplus_ctl_state, 
	pf_dplus_query_type, pf_dplus_query_entries, pf_dplus_auth, pf_dplus_dongle_serial, pf_dplus_epoch,
}

-- Ternary operator
local function fif(condition, if_true, if_false)
	if condition then return if_true else return if_false end
end

function p_dplus.dissector ( buffer, pinfo, tree)
	-- Validate packet length
	if ( buffer:len() < 3 ) then return end
	
	local len = buffer:len()
	local inner_len = bit.band( buffer( 0, 2):le_uint(), 0x1FFF)
	local ascp_header = buffer( 0, 2)
	local ascp_type = bit.rshift( bit.band( buffer( 1,1):uint(), 0xE0), 5)
		
	-- Validate length
	if ( len ~= inner_len ) then return end;
	
	-- Set protocol name
	pinfo.cols.protocol = "DPLUS"
	
	-- Subtree
	local subtree = tree:add( p_dplus, buffer(), "DPlus Protocol")
	local ascp_tree = subtree:add_le ( p_dplus, ascp_header, "Amateur Station Control Protocol Header" )
	ascp_tree:add_le( pf_dplus_ascp_type, ascp_header)
	ascp_tree:add_le( pf_dplus_ascp_length, ascp_header)
	local callsign = nil
	local serial = nil
	
	if ( ascp_type == 4 ) then
		-- Pass the information to the DSVT dissector
		Dissector.get("dsvt"):call( buffer(2):tvb(), pinfo, tree)

	elseif ( ascp_type == 3 and len == 3 ) then
		-- Keepalive
		pinfo.cols.info = "Keepalive"
		subtree:add( pf_dplus_keepalive, buffer(2,1))
		return

	elseif ( ascp_type == 0 and len >= 4 ) then
		-- Commands
		local command = buffer(2,2):le_uint()
		subtree:add_le( pf_dplus_ctl_code, buffer( 2, 2))
		
		if ( command == 0x0018 and len == 5 ) then
			-- Repeater state transition
			local state = buffer( 4,1):uint()
			subtree:add( pf_dplus_ctl_state, buffer( 4, 1))
			pinfo.cols.info = "New state: " .. state_trans[state]
			
		else
			local uncomm = subtree:add( buffer(2,1), "Unknown command")
			uncomm:add_expert_info( PI_UNDECODED, PI_WARN, "Unknown command")
		end
	elseif ( ascp_type == 6 ) then
		-- Queries
		local qtype = buffer( 2, 2):le_uint()
		subtree:add_le( pf_dplus_query_type, buffer( 2, 2))
		
		if ( qtype == 0x0004 and len == 8 ) then
			-- Authentication result
			local auth_tree = subtree:add( pf_dplus_auth, buffer(4))
			local result = buffer(4):string()
			pinfo.cols.info = "Auth result: " .. auth_result[result]
			auth_tree.text = string.format( "%s %s (%s)", auth_tree.text:sub( 1, -6), auth_result[result], result)
		
		elseif ( qtype == 0x0004 and len == 28 ) then
			-- Authentication request
			callsign = buffer( 4, 8):string()
			serial = buffer( 20, 8):string()
			
			subtree:add( buffer( 4, 8), "Callsign: " .. callsign )
			local serial_tree = subtree:add( buffer( 20, 8), "Dongle serial: " .. serial )
			if ( buffer( 20, 8):string() == "DV019999" ) then
				serial_tree:add_expert_info( PI_PROTOCOL, PI_COMMENT, "Not an actual dongle")
			end
			
			pinfo.cols.info = "Auth request from: " .. callsign
		
		elseif ( qtype == 0x0003 and len > 5 ) then
			-- Software version
			version = buffer( 4):string()
			subtree:add( buffer(4), "Software version: " .. version)
			pinfo.cols.info = "Software version: " .. version
		
		elseif ( qtype == 0x0008 and len == 34 ) then
			-- Date reply
			local time = buffer( 8):string()
			subtree:add_le( pf_dplus_epoch, buffer( 4, 4))
			local time_tree = subtree:add( buffer(8), "Current Date: " .. time)
			if ( buffer(28,5):string() == "     " ) then
				time_tree:add_expert_info( PI_PROTOCOL, PI_COMMENT, "Implied time zone: UTC")
			end
			pinfo.cols.info = "Current Date: " .. time
		
		elseif ( qtype == 0x0006 and math.fmod( len-8, 20) == 0 ) then
			-- Connected Users List
			local nb_results = buffer( 6, 2):le_uint()
			subtree:add_le( pf_dplus_query_entries, buffer( 6, 2))
			local cntd_tree = subtree:add( p_dplus, buffer(8), "Connected Users List")
			local i = 0
			while ( i < nb_results ) do
				local modl = buffer(8+(20*i),1)
				local mod_name = fif( modl:string() == " ", "(Unmapped)", modl:string())
				local qrz  = buffer(8+(20*i+1),9)
				local qrz_str = qrz:string():gsub( " ", "")
				local ctype = buffer(8+(20*i+10),2)
				local ctype_val = buffer(8+(20*i+10),1):string()
				local ts = buffer(8+(20*i+12),4)
				local entry = subtree:add( p_dplus, buffer(8+(20*i),20), string.format( "User %s on module %s", qrz_str, mod_name))
				
				entry:add( modl, "Mapped module: " .. mod_name)
				entry:add( qrz, "Callsign: " .. qrz_str)
				if ( client_type[ctype_val] ~= nil ) then
					entry:add( ctype, string.format("Client Type: %s ('%s')", client_type[ctype_val], ctype_val))
				else
					local unkent = entry:add( ctype, string.format( "Client Type: Unknown ('%s')", ctype_val))
					unkent:add_expert_info( PI_UNDECODED, PI_WARN, "Unknown client type")
				end
				
				entry:add_le ( ts, "Connected Since (epoch): " .. ts:le_uint())
				i = i + 1 
			end
			pinfo.cols.info = string.format( "Connected Users List, %d entr%s", nb_results, fif( nb_results ~= 1, "ies", "y"))
		
		elseif ( qtype == 0x0007 and math.fmod( len-6, 28) == 0 ) then
			-- Last Heard List
			local nb_results = buffer( 4, 2):le_uint()
			local ts = buffer(6,4)
			
			subtree:add_le( pf_dplus_query_entries, buffer( 4, 2))
			local cntd_tree = subtree:add( p_dplus, buffer(10), "Last Heard List")
			cntd_tree:add_le ( ts, "Generated at (epoch): " .. ts:le_uint())
			local i = 0
			while ( i < nb_results ) do
				--cal entry = subtree:add( p_dplus, buffer(8+(20*i),20), string.format( "User %s on module %s", qrz_str, mod_name))
				
				--entry:add_le ( ts, "Connected Since (epoch): " .. ts:le_uint())
				i = i + 1
			end
			pinfo.cols.info = string.format( "Last Heard List, %d entr%s", nb_results, fif( nb_results ~= 1, "ies", "y"))
		
		elseif ( query_types[qtype] ~= nil and len == 4 ) then
			pinfo.cols.info = query_types[qtype] .. " Request"
			
		else
			local unkquery = subtree:add( buffer( 4), "Unknown Query")
			unkquery:add_expert_info( PI_UNDECODED, PI_WARN, "Undocumented data")
		end
		
	else
		local undoc = subtree:add( buffer(2), "Undocumented data")
		undoc:add_expert_info( PI_UNDECODED, PI_WARN, "Undocumented data")
	end
end

local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add( 20001, p_dplus)


