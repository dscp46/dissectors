-- ccs.lua - Call Connection Service
local proto_shortname = "ccs"
local proto_longname = "Call Connection Service Protocol"
p_ccs = Proto ( proto_shortname, proto_longname)

local CCS_PORT = 30062

local header_list = {
	["IRPT"]="Repeater Information",
	["0001"]="User Message",
	["Find"]="User Search",
	["0002"]="User Status",
	["1002"]="User Status",
}

local data_src_list = {
	[0x30]="RF",
	[0x31]="XRF",
	[0x32]="DCS",
	[0x33]="Icom_add_on",
	[0x34]="REF",
	[0x35]="CCS",
	[0x36]="ircDDBGateway",
}

local pf_ccs_hdr       = ProtoField.string ( proto_shortname .. ".hdr" , "Header", base.ASCII, header_list)
local pf_ccs_qrz       = ProtoField.string ( proto_shortname .. ".qrz" , "Callsign", base.ASCII)
local pf_ccs_modl      = ProtoField.string ( proto_shortname .. ".module" , "Module ID", base.ASCII)
local pf_ccs_lat       = ProtoField.string ( proto_shortname .. ".lat" , "Latitude", base.ASCII)
local pf_ccs_lon       = ProtoField.string ( proto_shortname .. ".lon" , "Longitude", base.ASCII)
local pf_ccs_freq      = ProtoField.string ( proto_shortname .. ".freq" , "Frequency (MHz)", base.ASCII)
local pf_ccs_dup       = ProtoField.string ( proto_shortname .. ".dup" , "Duplex offset (MHz)", base.ASCII)
local pf_ccs_qth       = ProtoField.string ( proto_shortname .. ".qth" , "Repeater location (QTH)", base.ASCII)
local pf_ccs_desc      = ProtoField.string ( proto_shortname .. ".desc" , "Description", base.ASCII)
local pf_ccs_url       = ProtoField.string ( proto_shortname .. ".url" , "Url", base.ASCII)
local pf_ccs_banner    = ProtoField.string ( proto_shortname .. ".banner" , "Software name and version", base.ASCII)
local pf_ccs_contact   = ProtoField.string ( proto_shortname .. ".contact" , "Sysop contact info", base.ASCII)
local pf_ccs_rfl       = ProtoField.string ( proto_shortname .. ".rfl" , "Bound reflector", base.ASCII)
local pf_ccs_rfl_mod   = ProtoField.string ( proto_shortname .. ".rfl.modl" , "Bound reflector module", base.ASCII)
local pf_ccs_my_qrz    = ProtoField.string ( proto_shortname .. ".my.qrz" , "My Call", base.ASCII)
local pf_ccs_my_info   = ProtoField.string ( proto_shortname .. ".my.info" , "My Info", base.ASCII)
local pf_ccs_ur_qrz    = ProtoField.string ( proto_shortname .. ".ur.qrz" , "Ur Call", base.ASCII)
local pf_ccs_call      = ProtoField.uint16 ( proto_shortname .. ".call" , "Call ID", base.HEX)
local pf_ccs_source    = ProtoField.uint8  ( proto_shortname .. ".data_src" , "Data Source", base.HEX, data_src_list)
local pf_ccs_dv_mesg   = ProtoField.string ( proto_shortname .. ".dv.mesg" , "DV Message (Radio2Radio)", base.ASCII)
local pf_ccs_rptr      = ProtoField.string ( proto_shortname .. ".rptr" , "Target Repeater", base.ASCII)
local pf_ccs_rptr_modl = ProtoField.string ( proto_shortname .. ".rptr.modl" , "Target Module", base.ASCII)

p_ccs.fields = {
	pf_ccs_hdr, pf_ccs_qrz, pf_ccs_modl, pf_ccs_lat, pf_ccs_lon, pf_ccs_freq, pf_ccs_dup, pf_ccs_qth, pf_ccs_desc, 
	pf_ccs_url, pf_ccs_banner, pf_ccs_contact, pf_ccs_rfl, pf_ccs_rfl_mod, pf_ccs_my_qrz, pf_ccs_my_info, pf_ccs_ur_qrz,
	pf_ccs_call, pf_ccs_source, pf_ccs_dv_mesg, pf_ccs_rptr, pf_ccs_rptr_modl,
}

-- Ternary operator
local function fif(condition, if_true, if_false)
	if condition then return if_true else return if_false end
end

function p_ccs.dissector ( buffer, pinfo, tree)
	local len = buffer:len()
	local is_s2c = ( pinfo.src_port == CCS_PORT )
	
	local subtree = tree:add( p_ccs, buffer())
	pinfo.cols.protocol = string.upper(proto_shortname)
	
	if ( len == 133 and buffer( 0, 4):string() == "IRPT" ) then
		subtree.text = subtree.text .. " Repeater Information"
		pinfo.cols.info = "Repeater Information"
		subtree:add( pf_ccs_hdr, buffer(0,4))
		subtree:add( pf_ccs_qrz, buffer(4,7))
		subtree:add( pf_ccs_modl, buffer(12,1))
		subtree:add( pf_ccs_lat, buffer(13,10))
		subtree:add( pf_ccs_lon, buffer(23,10))
		subtree:add( pf_ccs_freq, buffer(33,10))
		subtree:add( pf_ccs_dup, buffer(43,10))
		subtree:add( pf_ccs_qth, buffer(53,20))
		subtree:add( pf_ccs_desc, buffer(73,20))
		subtree:add( pf_ccs_url, buffer(93,40))
		
	elseif ( len == 39 ) then
		-- Registration Message
		subtree.text = subtree.text .. " Registration Message"
		pinfo.cols.info = "Registration Message"
		subtree:add( pf_ccs_qrz, buffer(0,8))
		subtree:add( pf_ccs_modl, buffer(8,1))
		subtree:add( buffer(9,2), "Fixed value ('A@')" )
		subtree:add( pf_ccs_qth, buffer(11,6))
		subtree:add( buffer(17,2), "Fixed value (' @')" )
		subtree:add( pf_ccs_banner, buffer( 19, 20))
	
	elseif ( len == 19 ) then
		-- Cancellation Message
		subtree.text = subtree.text .. " Cancellation Message"
		pinfo.cols.info = "Cancellation Message"
		subtree:add( pf_ccs_qrz, buffer(0,8))
		subtree:add( pf_ccs_modl, buffer(8,1))
		subtree:add( buffer(9,10), "Padding")
		
	elseif ( len == 25 ) then
		-- Heartbeat
		subtree.text = subtree.text .. " Heartbeat"
		pinfo.cols.info = "Heartbeat"
		subtree:add( pf_ccs_qrz, buffer(0,8))
		subtree:add( pf_ccs_contact, buffer(8,17))
	
	elseif ( len == 100 and buffer( 0, 4):string() == "0001" and buffer( 23,8):string() == "CQCQCQ  " ) then
		-- User Status Message
		subtree.text = subtree.text .. " User Status Message"
		pinfo.cols.info = "User Status"
		subtree:add( pf_ccs_hdr, buffer(0,4))
		subtree:add( buffer(4,2), "Reserved" )
		subtree:add( pf_ccs_rfl, buffer(7,7) )
		subtree:add( pf_ccs_rfl_mod, buffer(14,1) )
		subtree:add( pf_ccs_qrz, buffer(15,8) )
		subtree:add( pf_ccs_ur_qrz, buffer(23,8))
		subtree:add( pf_ccs_my_qrz, buffer(31,8) )
		subtree:add( pf_ccs_my_info, buffer(39,4) )
		subtree:add_le( pf_ccs_call, buffer(43,2))
		subtree:add( buffer(45,16), "Reserved" )
		subtree:add( buffer(61,3), "Fixed value (\\x01\\x00!)" )
		subtree:add( buffer(64,20), "Reserved" )
		subtree:add( pf_ccs_source, buffer(93,1))
		subtree:add( buffer(94,6), "Reserved")
		
	elseif ( len == 100 and buffer( 0, 4):string() == "0001" and buffer( 23,8):string() ~= "CQCQCQ  " ) then
		-- User Voice/Data Message
		subtree.text = subtree.text .. " User Voice/Data Message"
		pinfo.cols.info = "User Voice/Data"
		subtree:add( pf_ccs_hdr, buffer(0,4))
		subtree:add( buffer(4,2), "Reserved" )
		subtree:add( pf_ccs_rfl, buffer(7,7) )
		subtree:add( pf_ccs_rfl_mod, buffer(14,1) )
		subtree:add( pf_ccs_qrz, buffer(15,8) )
		subtree:add( pf_ccs_ur_qrz, buffer(23,8))
		subtree:add( pf_ccs_my_qrz, buffer(31,8) )
		subtree:add( pf_ccs_my_info, buffer(39,4) )
		subtree:add_le( pf_ccs_call, buffer(43,2))
		subtree:add( buffer(45,1), "Sequence" )
		subtree:add( buffer(46,9), "AMBE Voice fragment")
		subtree:add( buffer(46,9), "DV Slow Data fragment")
		subtree:add( buffer(61,3), "Fixed value (\\x01\\x00!)" )
		subtree:add( pf_ccs_dv_mesg, buffer(64,20))
		if ( is_s2c == true ) then
			subtree:add( buffer(84,1), "Reserved")
			subtree:add( pf_ccs_rptr, buffer(85,7))
			subtree:add( pf_ccs_rptr_modl, buffer(92,1))
		else
			subtree:add( buffer(84,9), "Reserved")
		end
		subtree:add( pf_ccs_source, buffer(93,1))
		subtree:add( buffer(94,6), "Reserved")
		
	elseif ( len == 12 and buffer( 0, 4):string() == "Find" ) then
		-- Find user message
		subtree.text = subtree.text .. " Find User " .. fif( is_s2c, "Reply", "Query")
		subtree:add( pf_ccs_hdr, buffer(0,4))
		local qrz = buffer( 4, 8):string():gsub( '^%s*(.-)%s*$', '%1')
		if ( is_s2c == true ) then
			subtree:add( pf_ccs_rptr, buffer( 4, 8), qrz)
		else
			subtree:add( pf_ccs_qrz, buffer( 4, 8), qrz)
		end
	
	elseif ( len == 38 and buffer( 2, 4):string() == "0001" ) then
		-- Terminate CCS communication
		subtree.text = subtree.text .. " Terminate CCS communication"
		pinfo.cols.info = "Terminate CCS communication"
		subtree:add( pf_ccs_rptr, buffer( 0, 7))
		subtree:add( pf_ccs_rptr_modl, buffer( 7, 1))
		subtree:add( pf_ccs_hdr, buffer( 8, 4))
		subtree:add( pf_ccs_qrz, buffer( 12, 7))
		subtree:add( pf_ccs_modl, buffer( 19, 1))
		subtree:add( buffer( 20, 18), "Reserved")

	elseif ( len == 38 and buffer( 8, 4):string() == "0002" ) then
		-- Remote Station Status Query
		subtree.text = subtree.text .. " Remote Station Status Query"
		pinfo.cols.info = "Remote Station Status Query"
		subtree:add( pf_ccs_rptr, buffer( 0, 7))
		subtree:add( pf_ccs_rptr_modl, buffer( 7, 1))
		subtree:add( pf_ccs_hdr, buffer( 8, 4))
		subtree:add( pf_ccs_qrz, buffer( 12, 7))
		subtree:add( pf_ccs_modl, buffer( 19, 1))
		subtree:add( buffer( 20, 18), "Reserved")

	elseif ( len == 100 and buffer( 8, 4):string() == "0002" ) then
		-- Remote station Status Answer
		subtree:add( pf_ccs_hdr, buffer( 8, 4))
	
	elseif ( len == 100 and buffer( 8, 4):string() == "1002" ) then
		-- Remote station Status Answer 2
		subtree:add( pf_ccs_hdr, buffer( 8, 4))
		subtree:add( pf_ccs_qrz, buffer( 12, 7))
		subtree:add( pf_ccs_modl, buffer( 19, 1))
	end
end

local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add( CCS_PORT, p_ccs)
