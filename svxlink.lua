-- svxlink.lua -- SVXlink repeater to reflector protocol

-- Some module-specific constants
local proto_shortname   = "svx"
local proto_shortname_u = "svx_u"
local proto_fullname    = "SVXLink reflector Protocol"

-- Protocol Definitions
p_svx  = Proto ( proto_shortname  , proto_fullname)
p_svxu = Proto ( proto_shortname_u, proto_fullname .. " (UDP)")

-- Enums
local svx_type = {
	[1]="Heartbeat",
	[5]="Protocol Version",
	[10]="Auth Challenge",
	[11]="Auth Response",
	[12]="Auth OK",
	[13]="Auth Failed",
	[100]="Server Info",
	[101]="Node List",
	[102]="Node Joined",
	[103]="Node Left",
	[104]="Talker Start",
	[105]="Talker Stop",
}

local svx_utype = {
	[1]="Heartbeat",
	[101]="Audio frame",
	[102]="End of stream",
	[103]="All Samples Flushed",
}

-- Fields declaration
local pf_packet_len   = ProtoField.uint16 ( proto_shortname   .. ".len"               , "Length", base.DEC)
local pf_tcp_type     = ProtoField.uint16 ( proto_shortname   .. ".type"              , "Type", base.DEC, svx_type)
local pf_client_id    = ProtoField.uint16 ( proto_shortname   .. ".client_id"         , "Client ID", base.HEX)
local pf_callsign     = ProtoField.string ( proto_shortname   .. ".callsign"          , "Callsign", base.ASCII)
local pf_callsign_sz  = ProtoField.uint16 ( proto_shortname   .. ".callsign.len"      , "Callsign length", base.DEC)
local pf_challenge    = ProtoField.bytes  ( proto_shortname   .. ".auth.challenge"    , "Auth Challenge")
local pf_challenge_sz = ProtoField.uint16 ( proto_shortname   .. ".auth.challenge.len", "Auth Challenge Length", base.DEC)
local pf_errmsg       = ProtoField.string ( proto_shortname   .. ".errmsg"            , "Error Message", base.ASCII)
local pf_errmsg_sz    = ProtoField.uint16 ( proto_shortname   .. ".errmsg.len"        , "Error Message length", base.DEC)
local pf_response     = ProtoField.bytes  ( proto_shortname   .. ".auth.response"     , "Auth Response")
local pf_response_sz  = ProtoField.uint16 ( proto_shortname   .. ".auth.response.len" , "Auth Response Length", base.DEC)
local pf_ver_maj      = ProtoField.uint16 ( proto_shortname   .. ".version.major"     , "Major Version", base.DEC)
local pf_ver_min      = ProtoField.uint16 ( proto_shortname   .. ".version.minor"     , "Minor Version", base.DEC)

p_svx.fields  = { 
	pf_packet_len, pf_tcp_type,  pf_client_id,  pf_callsign, pf_callsign_sz, pf_challenge, pf_challenge_sz, pf_errmsg, pf_errmsg_sz,
	pf_response, pf_response_sz, pf_ver_maj, pf_ver_min 
}


local pf_udp_type   = ProtoField.uint16 ( proto_shortname_u .. ".type"      , "Type", base.DEC, svx_utype)
local pf_uclient_id = ProtoField.uint16 ( proto_shortname   .. ".client_id" , "Client ID", base.HEX)
local pf_seq        = ProtoField.uint16 ( proto_shortname   .. ".seq"       , "Sequence Number", base.HEX)

p_svxu.fields = { pf_udp_type, pf_uclient_id, pf_seq }

-- Dissector

function p_svx.dissector( buffer, pinfo, tree)
	local len = buffer:len()
	if ( len < 6 ) then return end
	
	local pkt_type = buffer( 4, 2):uint()
	
	-- Set protocol name
	pinfo.cols.protocol = "SVXLink"
	pinfo.cols.info = svx_type[pkt_type]
	
	local subtree = tree:add( p_svx, buffer(), proto_fullname)
	--subtree:add( pf_seq         , buffer( 0, 2))
	subtree:add( pf_packet_len  , buffer( 2, 2))
	subtree:add( pf_tcp_type    , buffer( 4, 2))
	
	if( pkt_type == 5 ) then
		-- Protocol Version
		subtree:add( pf_ver_maj, buffer( 6, 2))
		subtree:add( pf_ver_min, buffer( 8, 2))
		pinfo.cols.info:append( " " .. buffer( 6, 2):uint() .. "." .. buffer( 8, 2):uint())
		
	elseif ( pkt_type == 10 ) then
		-- Authentication challenge
		local challenge_sz = buffer( 6, 2):uint()
		subtree:add( pf_challenge_sz, buffer( 6, 2))
		subtree:add( pf_challenge, buffer( 8, challenge_sz))
	
	elseif ( pkt_type == 11 ) then
		-- Authentication response
		local callsign_sz = buffer( 6, 2):uint()	
		local callsign = buffer( 8, callsign_sz):string()
		
		subtree:add( pf_callsign_sz, buffer( 6, 2))
		subtree:add( pf_callsign, buffer( 8, callsign_sz))
		
		local resp_sz = buffer( 8+callsign_sz, 2):uint()
		subtree:add( pf_response_sz, buffer( 8+callsign_sz, 2))
		subtree:add( pf_response, buffer( 10+callsign_sz))
		pinfo.cols.info:append( ", QRZ: " .. callsign)
		
	elseif ( pkt_type == 13 ) then
		-- Authentication failed
		local errmsg_sz = buffer( 6, 2):uint()
		subtree:add( pf_errmsg_sz, buffer( 6, 2))
		subtree:add( pf_errmsg, buffer( 8, errmsg_sz))
		pinfo.cols.info:append( ":  " .. buffer( 8, errmsg_sz):string())
	
	elseif ( pkt_type == 102 or pkt_type == 103 or pkt_type == 104 or pkt_type == 105 ) then
		local callsign_sz = buffer( 6, 2):uint()	
		local callsign = buffer( 8, callsign_sz):string()
		
		subtree:add( pf_callsign_sz, buffer( 6, 2))
		subtree:add( pf_callsign, buffer( 8, callsign_sz))
		pinfo.cols.info:append( ": " .. callsign)
	end
	
end

function p_svxu.dissector( buffer, pinfo, tree)
	local len = buffer:len()
	if ( len < 6 ) then return end
	
	local pkt_type = buffer( 0, 2):uint()
	
	-- Set protocol name
	pinfo.cols.protocol = "SVXLink"
	pinfo.cols.info = svx_utype[pkt_type]
	
	local subtree = tree:add( p_svx, buffer(), proto_fullname)
	subtree:add( pf_udp_type  , buffer( 0, 2))
	subtree:add( pf_uclient_id, buffer( 2, 2))
	subtree:add( pf_seq       , buffer( 4, 2))
	
	if ( pkt_type == 101 ) then
		subtree:add( buffer(6), "Audio Payload")
	end
end

-- Register protocols
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add( 5300, p_svx)
tcp_port:add_for_decode_as( p_svx)

local udp_port = DissectorTable.get("udp.port")
udp_port:add( 5300, p_svxu)
udp_port:add_for_decode_as( p_svxu)

