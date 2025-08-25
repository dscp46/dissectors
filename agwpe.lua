-- agwpe.lua - AGW Packet Engine protocol
-- Spec reference: docs/agwpe-api.md

-- Some module-specific constants
local proto_shortname = "agwpe"
local proto_fullname  = "AGWPE Protocol"

-- Protocol Definition
p_agwpe = Proto ( proto_shortname, proto_fullname)

local settings = 
{
	enabled = true,
	port = 8000,
	max_len = 1024
}

-- Direction info (shim for versions < 3.4.4)
if( P2P_DIR_RECV == nil ) then
	P2P_DIR_UNKNOWN = -1
	P2P_DIR_SENT    =  0
	P2P_DIR_RECV    =  1
end

-- Fields
local pf_agwpe_src   = ProtoField.string( proto_shortname .. ".src" , "Source", base.ASCII)
local pf_agwpe_dst   = ProtoField.string( proto_shortname .. ".dst" , "Destination", base.ASCII)
local pf_agwpe_port   = ProtoField.uint8( proto_shortname .. ".port" , "Engine Port", base.DEC)
local pf_agwpe_kind  = ProtoField.string( proto_shortname .. ".kind", "DataKind", base.ASCII)
local pf_agwpe_pid    = ProtoField.uint8( proto_shortname .. ".pid" , "PID", base.DEC)
local pf_agwpe_dir     = ProtoField.int8( proto_shortname .. ".direction" , "Direction")
local pf_agwpe_mon   = ProtoField.string( proto_shortname .. ".mon" , "Monitor", base.ASCII)
local pf_agwpe_mon_s = ProtoField.string( proto_shortname .. ".mon.s" , "Monitor (S type)", base.ASCII)

p_agwpe.fields = {
	pf_agwpe_src, pf_agwpe_dst, pf_agwpe_port, pf_agwpe_kind, pf_agwpe_pid, pf_agwpe_dir, pf_agwpe_mon, pf_agwpe_mon_s
}

--- [ Dissector helper functions ] ---

-- Convert the datakind field into the matching packet name in the DTE->DCE direction
local function agw_get_tx_dkind_name ( datakind)
	if( datakind == 0x50 ) then return "Application login request" end -- 'P'
	if( datakind == 0x58 ) then return "Register callsign" end -- 'X'
	if( datakind == 0x78 ) then return "Unregister callsign" end -- 'x'
	if( datakind == 0x47 ) then return "Request port information" end -- 'G'
	if( datakind == 0x6D ) then return "Enable reception of monitoring frames" end -- 'm'
	if( datakind == 0x52 ) then return "AGWPE Version Info" end -- 'R'
	if( datakind == 0x67 ) then return "Request port capabilities" end -- 'g'
	if( datakind == 0x48 ) then return "Request heard callsign list" end -- 'H'
	if( datakind == 0x79 ) then return "Request number of frames waiting on a port" end -- 'y'
	if( datakind == 0x59 ) then return "Request number of frames waiting on a connection" end -- 'Y'
	if( datakind == 0x4D ) then return "UI Frame" end -- 'M'
	if( datakind == 0x43 ) then return "Initiate direct AX.25 connection" end -- 'C'
	if( datakind == 0x44 ) then return "Connected data" end -- 'D'
	if( datakind == 0x64 ) then return "Terminate AX.25 connection" end -- 'd'
	if( datakind == 0x76 ) then return "Initate digipeated AX.25 connection" end -- 'v'
	if( datakind == 0x56 ) then return "UI Frame (digipeated)" end -- 'V'
	if( datakind == 0x63 ) then return "Non-standard AX.25 connection (custom PID)" end -- 'c'
	if( datakind == 0x4B ) then return "Raw data frame" end -- 'K'
	if( datakind == 0x6B ) then return "Enable reception in raw format" end -- 'k'
	return "Undocumented"
end

-- Convert the datakind field into the matching packet name in the DCE->DTE direction
local function agw_get_rx_dkind_name ( datakind)
	if( datakind == 0x52 ) then return "Version" end -- 'R'
	if( datakind == 0x58 ) then return "Callsign registration" end -- 'X'
	if( datakind == 0x47 ) then return "Port Information" end -- 'G'
	if( datakind == 0x67 ) then return "Port Capabilities" end -- 'g'
	if( datakind == 0x79 ) then return "Outstanding frames on a port" end -- 'y'
	if( datakind == 0x59 ) then return "Outstanding frames on a connection" end -- 'Y'
	if( datakind == 0x48 ) then return "Head stations list" end -- 'H'
	if( datakind == 0x43 ) then return "AX.25 Connection Request" end -- 'C'
	if( datakind == 0x44 ) then return "Connected Data" end -- 'D'
	if( datakind == 0x49 ) then return "Monitored I frame" end -- 'I'
	if( datakind == 0x53 ) then return "Monitored S frame" end -- 'S'
	if( datakind == 0x55 ) then return "Monitored UI frame" end -- 'U'
	if( datakind == 0x54 ) then return "Monitoring own information" end -- 'T'
	if( datakind == 0x4B ) then return "Monitored Raw frame" end -- 'K'
	return "Undocumented"
end

local function agw_registration_result( result)
	if( result == 1 ) then return "Success" end
	return "Failed"
end

local function agwpe_count_ports( buffer)
	local result = 0
	local length = buffer:len()
	for i=0,length-1,1 do
		if( buffer(i, 1):uint() == 0x3B ) then
			result = result + 1
		end
	end
	return result
end

local function agwpe_port_substr( buffer)
	local length = buffer:len()
	local result = 0;
	for i=0,length-1,1 do
		if( buffer(i, 1):uint() == 0x3B ) then
			return result
		end
		result = result + 1
	end
	return result
end

local function agwpe_get_s_type( buffer)
	local length = buffer:len()
	local type_start = -1
	local type_len = 0
	for i=0,length-1,1 do
		if( buffer(i, 1):uint() == 0x3c ) then
			type_start = i + 1
			break
		end
	end
	if( type_start ~= -1 ) then
		for i=type_start,length-1,1 do
			if( buffer(i, 1):uint() == 0x20 ) then
				type_len = i - type_start
				return buffer( type_start, type_len)
			end
		end
	end
	return -1
end

local function agw_is_ui_aprs( buffer)
	local length = buffer:len()
	if ( length < 2 ) then return false end
	local aprs_type = buffer(0,1):uint()
	if ( aprs_type < 0x1c ) then return false end
	if ( aprs_type >= 0x1e and aprs_type <= 0x20 ) then return false end
	if ( aprs_type == 0x22 ) then return false end
	if ( aprs_type == 0x28 ) then return false end
	if ( aprs_type == 0x2D ) then return false end
	if ( aprs_type == 0x2E ) then return false end
	if ( aprs_type >= 0x30 and aprs_type <= 0x39 ) then return false end
	if ( aprs_type >= 0x41 and aprs_type <= 0x53 ) then return false end
	if ( aprs_type >= 0x55 and aprs_type <= 0x5A ) then return false end
	if ( aprs_type >= 0x5C and aprs_type <= 0x5E ) then return false end
	if ( aprs_type >= 0x61 and aprs_type <= 0x7A ) then return false end
	if ( aprs_type == 0x7C ) then return false end
	if ( aprs_type >= 0x7E ) then return false end
	return true
end


-- Safely extract a sometimes-not-null terminated string from a TVB
local function agw_get_string( buffer)
	local first_null_pos = -1
	local length = buffer:len()
	for i=0,length-1,1 do
		if( buffer:bytes():get_index(i) == 0 ) then
			first_null_pos = i
			break
		end
	end 

	if( first_null_pos == -1 ) then
		return buffer(0):string()
	end
	return buffer(0):stringz()
end

-- Is a packet from, or to the DTE
local function is_dte_to_dce ( pinfo)
	return pinfo.dst_port == settings.port
end

local function fif(condition, if_true, if_false)
	if condition then return if_true else return if_false end
end

--- [ Protocol dissector ] ---
function p_agwpe.dissector ( buffer, pinfo, tree)
	-- Validate minimal packet length
	if ( buffer:len() < 36 ) then return end

	-- Set protocol name
	pinfo.cols.protocol = "AGWPE"

	-- Variables
	local agw_port     = buffer(0,1):uint()
        local agw_rsv1     = buffer(1,3)
	local agw_datakind = buffer(4,1):uint()
	local agw_rsv2     = buffer(5,1)
	local agw_pid      = buffer(6,1):uint()
	local agw_rsv3     = buffer(7,1)
	local agw_callfrom = agw_get_string( buffer(8,10):tvb()):gsub('%s+', '')
	local agw_callto   = agw_get_string( buffer(18,10):tvb()):gsub('%s+', '')
	local agw_datalen  = buffer(28,4):le_uint()
	local agw_userrsv  = buffer(32,4):uint()

	-- Subtree title
	local subtree_title = "AGWPE Protocol, Src: \"" .. agw_callfrom .. "\", Dst: \"" .. agw_callto .. "\", PID: " .. agw_pid

	-- Update info column
	if( agw_datakind == 0x43 or agw_datakind == 0x63 or agw_datakind == 0x44 or agw_datakind == 0x64 or agw_datakind == 0x55 or agw_datakind == 0x59 or agw_datakind == 0x4D ) then
		pinfo.cols.info = "Src: " .. agw_callfrom .. ", Dst: " .. agw_callto .. ", PID: " .. agw_pid
	end

	-- Subtree
	local subtree = tree:add( p_agwpe, buffer(), subtree_title)
	subtree:add( pf_agwpe_dir, fif( is_dte_to_dce ( pinfo) == true, P2P_DIR_SENT, P2P_DIR_RECV), "[Direction: " .. fif(is_dte_to_dce ( pinfo) == true, "Outgoing", "Incoming") .. "]" )
	subtree:add( pf_agwpe_port, buffer( 0, 1), agw_port, "Engine Port: " .. agw_port)
	subtree:add( buffer( 1, 3), "Reserved")
	subtree:add( pf_agwpe_kind, buffer( 4, 1), buffer( 4, 1):string(), "DataKind: ".. fif( is_dte_to_dce ( pinfo) == true, agw_get_tx_dkind_name(agw_datakind), agw_get_rx_dkind_name(agw_datakind)))
	subtree:add( buffer( 5, 1), "Reserved")
	subtree:add( pf_agwpe_pid, buffer( 6, 1), agw_pid)
	subtree:add( buffer( 7, 1), "Reserved")
	subtree:add( pf_agwpe_src, buffer( 8,10), agw_callfrom, "Source: \"" .. agw_callfrom .. "\"")
	subtree:add( pf_agwpe_dst, buffer(18,10), agw_callto, "Destination: \"" .. agw_callto .. "\"")
	subtree:add_le( buffer(28, 4), "Data length: ".. agw_datalen)

	if( agw_datalen ~= 0 ) then
		-- The packet has a payload
		if( agw_datakind == 0x4B ) then
			-- The packet has a payload
			subtree:add( buffer(32, 4), "User (4 bytes)")
			subtree:add( buffer(36), "Payload (" .. agw_datalen .. " bytes)")
			-- Raw data frame, both DTE and DCE initiated
			-- KISS port identification
			-- subtree:add( buffer(36,1), "")

			-- We set the dissector to skip the first byte, which isn't the standard
			-- 0x7E flag
			Dissector.get("ax25"):call( buffer(37, buffer:len()-37):tvb(), pinfo, tree)
		end

		if( agw_datakind == 0x50 and is_dte_to_dce( pinfo) ) then
			-- Application Login
			if( buffer(32):len() == agw_datalen+4 ) then
				-- Non-compliant implementation
				local subtree_applogpad = subtree:add( buffer(32, 4), "Unexpected padding (4 bytes)")
				subtree_applogpad:add_expert_info( PI_PROTOCOL, PI_WARN, "The User field is 255 bytes zero-padded string for an application login request.")

				subtree:add( buffer(36, 255), "Username: "..agw_get_string( buffer(36, 255):tvb()))
				subtree:add( buffer(291, 255), "Password: "..agw_get_string( buffer(291, 255):tvb()))
				subtree:add_expert_info( PI_PROTOCOL, PI_WARN, "Non-standard implementation of application login")
				
			else
				subtree:add( buffer(32, 255), "Username: "..agw_get_string( buffer(32, 255):tvb()))
				subtree:add( buffer(287, 255), "Password: "..agw_get_string( buffer(287, 255):tvb()))
			end
		end

		if ( agw_datakind == 0x58 and not is_dte_to_dce( pinfo) ) then
			subtree:add( buffer(32, 4), "User (4 bytes)")
			if ( agw_datalen == 1 ) then
				local agw_reg_result = buffer(36, 1):uint()
				subtree:add( buffer(36, 1), "Registration result: " .. agw_registration_result( agw_reg_result) )
				
				pinfo.cols.info = "Callsign " .. agw_callfrom .. fif(agw_reg_result == 1, "", " not" ).. " registered."
			else
				subtree:add_expert_info( PI_PROTOCOL, PI_MALFORMED, "Malformed callsign registration answer")
			end
		end
		
		-- Connected Data
		if ( agw_datakind == 0x44 ) then
			pinfo.cols.info:append( ", Connected Data")
			subtree:add( buffer(36), "Connected data payload")
		end
		
		-- Port Information
		if ( agw_datakind == 0x47 and not is_dte_to_dce( pinfo) ) then
			local avail_ports = buffer(36, 1):uint()-0x30
			local count_ports = agwpe_count_ports( buffer(38))
			pinfo.cols.info = "Port information"
			subtree:add( buffer(32, 4), "User (Reserved)")
			local it_port = 1
			local cur_pos = 38
			local subtree_av_ports = subtree:add( "Available ports")
			for i=1,avail_ports,1 do
				local subbuf = buffer(cur_pos, agwpe_port_substr( buffer(cur_pos)))
				local str = subbuf( 6):string()
				subtree_av_ports:add( subbuf, it_port .. ": \"" .. str .. "\"")
				it_port = it_port + 1
				cur_pos = cur_pos + subbuf:len() + 1
			end
			if ( avail_ports ~= count_ports ) then
				local subtree_iv_ports = subtree:add( "Invisible ports")
				for i=it_port,count_ports,1 do
					local subbuf = buffer(cur_pos, agwpe_port_substr( buffer(cur_pos)))
					local str = subbuf( 6):string()
					subtree_iv_ports:add( subbuf, it_port .. ": \"" .. str .. "\"")
					it_port = it_port + 1
					cur_pos = cur_pos + subbuf:len() + 1
				end
			end
		end
		
		-- Outstanding frame
		if ( agw_datakind == 0x59 and not is_dte_to_dce( pinfo) ) then
			local outstanding_frames = buffer(36, 4)
			pinfo.cols.info:append( ", " .. outstanding_frames:le_uint() .. " frame(s) outstanding for connection")
			subtree:add( outstanding_frames, outstanding_frames:le_uint() .. " frame(s) outstanding for connection")
		end
		
		-- Disconnect
		if ( agw_datakind == 0x64 ) then
			pinfo.cols.info:append( " [DISC]")
		end
		
		-- Monitored Supervisory Info
		if ( agw_datakind == 0x53 ) then
			local packet_type = agwpe_get_s_type( buffer(36))
			if( packet_type ~= -1 ) then
				subtree:add( pf_agwpe_mon_s, packet_type, packet_type:string(), "S-Frame type: " .. packet_type:string())
				pinfo.cols.info = "Src: " .. agw_callfrom .. ", Dst: " .. agw_callto .. ", PID: " .. agw_pid .. " [" .. packet_type:string() .. "]" .. fif( packet_type:string() ~= "XID", " (mon)", "")
			else
				subtree:add_expert_info( PI_PROTOCOL, PI_MALFORMED, "Did not detect S frame type")
			end
		end
		
		-- Monitored own traffic
		if ( agw_datakind == 0x54 ) then
			local packet_type = agwpe_get_s_type( buffer(36))
			if ( packet_type ~= -1 and packet_type:string() ~= "I" ) then
				subtree:add( pf_agwpe_mon_s, packet_type, packet_type:string(), "S-Frame type: " .. packet_type:string())
				pinfo.cols.info = "Src: " .. agw_callfrom .. ", Dst: " .. agw_callto .. ", PID: " .. agw_pid .. " [" .. packet_type:string() .. "]" .. fif( packet_type:string() ~= "XID", " (own)", "")
			end
		end
		
		-- UI Frames
		if ( agw_datakind == 0x4D ) then
			pinfo.cols.info:append( " [UI]")
			subtree:add( buffer(32, 4), "User (4 bytes)")
			subtree:add( buffer(36), "Payload")
			if ( agw_is_ui_aprs( buffer(36)) ) then
				Dissector.get("aprs"):call( buffer(36):tvb(), pinfo, tree)
			end
		end
	else
		-- The packet doesn't have a payload
		subtree:add( buffer(32, 4), "User (4 bytes)")

		if ( agw_datakind == 0x58 ) then
			if( is_dte_to_dce( pinfo) ) then
				pinfo.cols.info = "Register callsign " .. agw_callfrom
			else
				subtree:add_expert_info( PI_PROTOCOL, PI_MALFORMED, "Malformed callsign registration answer")
			end
		end

		if ( agw_datakind == 0x6d and is_dte_to_dce( pinfo) ) then
			pinfo.cols.info = "Enable monitoring frames"
		end
		
		if ( agw_datakind == 0x47 and is_dte_to_dce( pinfo) ) then
			pinfo.cols.info = "Port info request"
		end
		
		if ( agw_datakind == 0x59 and is_dte_to_dce( pinfo) ) then
			pinfo.cols.info:append( ", Request outstanding frames on a connection")
		end
		
		if ( agw_datakind == 0x63 or agw_datakind == 0x43 or agw_datakind == 0x76 ) then
			pinfo.cols.info:append( " [SABM(E)]")
		end
		
		if ( agw_datakind == 0x64 ) then
			pinfo.cols.info:append( " [DISC]")
		end
	end
	
end

--- Dissector enable/disable functions
local function enableDissector()
	DissectorTable.get("tcp.port"):add( settings.port, p_agwpe)
end

local function disableDissector()
	DissectorTable.get("tcp.port"):remove( settings.port, p_agwpe) 
end

--- Initial dissector register
enableDissector()

--- Preferences handler
p_agwpe.prefs.enabled = Pref.bool( "Dissector enabled", settings.enabled,
				   "Whether the AGWPE dissector is enabled or not")

p_agwpe.prefs.port     = Pref.uint( "Dissector port", settings.port,
				   "Which TCP port the dissector will trigger on")

function p_agwpe.prefs_changed()
	settings.port = p_agwpe.prefs.port
	if settings.enabled ~= p_agwpe.prefs.enabled then
		settings.enabled = p_agwpe.prefs.enabled
		if settings.enabled then
			enableDissector()
		else
			disableDissector()
		end
		-- Reload the capture file
		reload()
	end
end

