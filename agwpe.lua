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

-- LUT for Booleans
local yesno = {
	[0] = "No",
	[1] = "Yes"
}

local xid_fi = {
	[0x82] = "General-Purpose XID Information"
}

local xid_gi = {
	[0x80] = "Parameters Negociation"
}

local xid_pi = {
	[0x2] = "Class of Procedures",
	[0x3] = "HDLC Optional Functions",
	[0x5] = "Max Tx I field length (N1)",
	[0x6] = "Max Rx I field length (N1)",
	[0x7] = "Tx Window size (k)",
	[0x8] = "Rx Window size (k)",
	[0x9] = "ACK Timer (T1)",
	[0xa] = "Max retries (N2)",
}

-- Fields
local pf_agwpe_src   = ProtoField.string( proto_shortname .. ".src" , "Source", base.ASCII)
local pf_agwpe_dst   = ProtoField.string( proto_shortname .. ".dst" , "Destination", base.ASCII)
local pf_agwpe_port   = ProtoField.uint8( proto_shortname .. ".port" , "Engine Port", base.DEC)
local pf_agwpe_kind  = ProtoField.string( proto_shortname .. ".kind", "DataKind", base.ASCII)
local pf_agwpe_pid    = ProtoField.uint8( proto_shortname .. ".pid" , "PID", base.DEC)
local pf_agwpe_dir     = ProtoField.int8( proto_shortname .. ".direction" , "Direction")
local pf_agwpe_mon   = ProtoField.string( proto_shortname .. ".mon" , "Monitor", base.ASCII)
local pf_agwpe_mon_s = ProtoField.string( proto_shortname .. ".mon.s" , "Monitor (S type)", base.ASCII)

local pf_agwpe_xid_fi          = ProtoField.uint8(  proto_shortname .. ".xid.fi"         , "Format Identifier"        , base.HEX, xid_fi)
local pf_agwpe_xid_gi          = ProtoField.uint8(  proto_shortname .. ".xid.gi"         , "Group Identifier"         , base.HEX, xid_gi)
local pf_agwpe_xid_gl          = ProtoField.uint16( proto_shortname .. ".xid.gl"         , "Group Length"             , base.UNIT_STRING, {" byte(s)"})
local pf_agwpe_xid_pi          = ProtoField.uint8(  proto_shortname .. ".xid.pi"         , "Parameter Identifier"     , base.HEX, xid_pi)
local pf_agwpe_xid_pl          = ProtoField.uint8(  proto_shortname .. ".xid.pl"         , "Parameter Length"         , base.UNIT_STRING, {" byte(s)"})
local pf_agwpe_xid_cop         = ProtoField.uint16( proto_shortname .. ".xid.cop"        , "Class of Procedures"      , base.HEX)
local pf_agwpe_xid_cop_abm     = ProtoField.uint16( proto_shortname .. ".xid.cop.abm"    , "Balanced ABM"             , base.DEC, yesno, 0x0001)
local pf_agwpe_xid_cop_unrmp   = ProtoField.uint16( proto_shortname .. ".xid.cop.unrmp"  , "Unbalanced NRM Primary"   , base.DEC, yesno, 0x0002)
local pf_agwpe_xid_cop_unrms   = ProtoField.uint16( proto_shortname .. ".xid.cop.unrms"  , "Unbalanced NRM Secondary" , base.DEC, yesno, 0x0004)
local pf_agwpe_xid_cop_uarmp   = ProtoField.uint16( proto_shortname .. ".xid.cop.uarmp"  , "Unbalanced ARM Primary"   , base.DEC, yesno, 0x0008)
local pf_agwpe_xid_cop_uarms   = ProtoField.uint16( proto_shortname .. ".xid.cop.uarms"  , "Unbalanced ARM Secondary" , base.DEC, yesno, 0x0010)
local pf_agwpe_xid_cop_hdx     = ProtoField.uint16( proto_shortname .. ".xid.cop.hdx"    , "Half Duplex"              , base.DEC, yesno, 0x0020)
local pf_agwpe_xid_cop_fdx     = ProtoField.uint16( proto_shortname .. ".xid.cop.fdx"    , "Full Duplex"              , base.DEC, yesno, 0x0040)
local pf_agwpe_xid_cop_rsvd    = ProtoField.uint16( proto_shortname .. ".xid.cop.rsvd"   , "Reserved"                 , base.HEX,   nil, 0xFF80)

local pf_agwpe_xid_hof         = ProtoField.uint32( proto_shortname .. ".xid.hof"        , "HDLC Optional Functions"  , base.HEX)
local pf_agwpe_xid_hof_rsvd_1  = ProtoField.uint32( proto_shortname .. ".xid.hof.rsvd1"  , "Reserved"                 , base.DEC,   nil, 0x00000001)
local pf_agwpe_xid_hof_rej     = ProtoField.uint32( proto_shortname .. ".xid.hof.rej"    , "REJ support"              , base.DEC, yesno, 0x00000002)
local pf_agwpe_xid_hof_srej    = ProtoField.uint32( proto_shortname .. ".xid.hof.srej"   , "SREJ support"             , base.DEC, yesno, 0x00000004)
local pf_agwpe_xid_hof_ui      = ProtoField.uint32( proto_shortname .. ".xid.hof.ui"     , "UI support"               , base.DEC, yesno, 0x00000008)
local pf_agwpe_xid_hof_srim    = ProtoField.uint32( proto_shortname .. ".xid.hof.sim_rim", "SIM/RIM support"          , base.DEC, yesno, 0x00000010)
local pf_agwpe_xid_hof_up      = ProtoField.uint32( proto_shortname .. ".xid.hof.up"     , "UP support"               , base.DEC, yesno, 0x00000020)
local pf_agwpe_xid_hof_badd    = ProtoField.uint32( proto_shortname .. ".xid.hof.badd"   , "Basic Address"            , base.DEC, yesno, 0x00000040)
local pf_agwpe_xid_hof_eadd    = ProtoField.uint32( proto_shortname .. ".xid.hof.eadd"   , "Extended Address"         , base.DEC, yesno, 0x00000080)
local pf_agwpe_xid_hof_delir   = ProtoField.uint32( proto_shortname .. ".xid.hof.delir"  , "Delete I Response"        , base.DEC, yesno, 0x00000100)
local pf_agwpe_xid_hof_delic   = ProtoField.uint32( proto_shortname .. ".xid.hof.delic"  , "Delete I Command"         , base.DEC, yesno, 0x00000200)
local pf_agwpe_xid_hof_mod8    = ProtoField.uint32( proto_shortname .. ".xid.hof.mod8"   , "Modulo 8"                 , base.DEC, yesno, 0x00000400)
local pf_agwpe_xid_hof_mod128  = ProtoField.uint32( proto_shortname .. ".xid.hof.mod128" , "Modulo 128"               , base.DEC, yesno, 0x00000800)
local pf_agwpe_xid_hof_rst     = ProtoField.uint32( proto_shortname .. ".xid.hof.rst"    , "RSET support"             , base.DEC, yesno, 0x00001000)
local pf_agwpe_xid_hof_tst     = ProtoField.uint32( proto_shortname .. ".xid.hof.tst"    , "TEST support"             , base.DEC, yesno, 0x00002000)
local pf_agwpe_xid_hof_rd      = ProtoField.uint32( proto_shortname .. ".xid.hof.rd"     , "RD support"               , base.DEC, yesno, 0x00004000)
local pf_agwpe_xid_hof_fcs16   = ProtoField.uint32( proto_shortname .. ".xid.hof.fcs16"  , "16-bit FCS"               , base.DEC, yesno, 0x00008000)
local pf_agwpe_xid_hof_fcs32   = ProtoField.uint32( proto_shortname .. ".xid.hof.fcs32"  , "32-bit FCS"               , base.DEC, yesno, 0x00010000)
local pf_agwpe_xid_hof_syntx   = ProtoField.uint32( proto_shortname .. ".xid.hof.syntx"  , "Synchronous TX"           , base.DEC, yesno, 0x00020000)
local pf_agwpe_xid_hof_stttx   = ProtoField.uint32( proto_shortname .. ".xid.hof.stttx"  , "Start/Stop TX"            , base.DEC, yesno, 0x00040000)
local pf_agwpe_xid_hof_stfctl  = ProtoField.uint32( proto_shortname .. ".xid.hof.stftcl" , "Start/Stop Basic Flow Ctl", base.DEC, yesno, 0x00080000)
local pf_agwpe_xid_hof_stotra  = ProtoField.uint32( proto_shortname .. ".xid.hof.stotra" , "Start/Stop Octet Transp." , base.DEC, yesno, 0x00100000)
local pf_agwpe_xid_hof_msrej   = ProtoField.uint32( proto_shortname .. ".xid.hof.msrej"  , "Multiframe SREJ Support"  , base.DEC, yesno, 0x00200000)
local pf_agwpe_xid_hof_segm    = ProtoField.uint32( proto_shortname .. ".xid.hof.segm"   , "Segmenter / Reassembler"  , base.DEC, yesno, 0x00400000)
local pf_agwpe_xid_hof_rsvd_23 = ProtoField.uint32( proto_shortname .. ".xid.hof.rsvd23" , "Reserved"                 , base.DEC,   nil, 0x00800000)

local pf_agwpe_xid_n1_tx       = ProtoField.uint16( proto_shortname .. ".xid.n1_tx"      , "Max Tx I field length (N1)", base.UNIT_STRING, { " bits"})
local pf_agwpe_xid_n1_rx       = ProtoField.uint16( proto_shortname .. ".xid.n1_rx"      , "Max Rx I field length (N1)", base.UNIT_STRING, { " bits"})
local pf_agwpe_xid_k_tx        = ProtoField.uint8(  proto_shortname .. ".xid.k_tx"       , "Tx Window size (k)", base.DEC)
local pf_agwpe_xid_k_rx        = ProtoField.uint8(  proto_shortname .. ".xid.k_rx"       , "Rx Window size (k)", base.DEC)
local pf_agwpe_xid_t1          = ProtoField.uint16( proto_shortname .. ".xid.t1"         , "Wait for ACK timer (T1)", base.UNIT_STRING, {" ms"})
local pf_agwpe_xid_n2          = ProtoField.uint8(  proto_shortname .. ".xid.n2"         , "Max retries (N2)", base.UNIT_STRING, {" time(s)"})

p_agwpe.fields = {
	pf_agwpe_src, pf_agwpe_dst, pf_agwpe_port, pf_agwpe_kind, pf_agwpe_pid, pf_agwpe_dir, pf_agwpe_mon, pf_agwpe_mon_s,
	pf_agwpe_xid_fi, pf_agwpe_xid_gi, pf_agwpe_xid_gl, pf_agwpe_xid_pi, pf_agwpe_xid_pl, pf_agwpe_xid_n2,
	pf_agwpe_xid_cop, pf_agwpe_xid_cop_abm, pf_agwpe_xid_cop_unrmp, pf_agwpe_xid_cop_unrms, pf_agwpe_xid_cop_uarmp, pf_agwpe_xid_cop_uarms, 
	pf_agwpe_xid_cop_hdx, pf_agwpe_xid_cop_fdx, pf_agwpe_xid_cop_rsvd, pf_agwpe_xid_n1_tx, pf_agwpe_xid_n1_rx, pf_agwpe_xid_k_tx, pf_agwpe_xid_k_rx,
	pf_agwpe_xid_t1, pf_agwpe_xid_hof_rsvd_1, pf_agwpe_xid_hof_rej, pf_agwpe_xid_hof_srej, pf_agwpe_xid_hof_ui, pf_agwpe_xid_hof_srim, 
	pf_agwpe_xid_hof_up, pf_agwpe_xid_hof_badd, pf_agwpe_xid_hof_eadd,  pf_agwpe_xid_hof_delir, pf_agwpe_xid_hof_delic, pf_agwpe_xid_hof_mod8,
	pf_agwpe_xid_hof_mod128, pf_agwpe_xid_hof_rst, pf_agwpe_xid_hof_tst, pf_agwpe_xid_hof_rd, pf_agwpe_xid_hof_fcs16, pf_agwpe_xid_hof_fcs32, 
	pf_agwpe_xid_hof_syntx, pf_agwpe_xid_hof_stttx, pf_agwpe_xid_hof_stfctl, pf_agwpe_xid_hof_stotra, pf_agwpe_xid_hof_msrej, pf_agwpe_xid_hof_segm,
	pf_agwpe_xid_hof_rsvd_23, pf_agwpe_xid_hof 
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

local function agwpe_is_final( buffer)
	return ( string.find( buffer():string(), "F=1") ~= nil )
end

local function agw_dissect_xid( buffer, pinfo, tree)
	local length = buffer:len()
	-- References the byte *AFTER* the first \r
	local xid_start = string.find( buffer():string(), "\r") 
	if ( xid_start == nil ) then
		return nil
	end
	-- Length including the Format Identifier
	local xid_len = buffer( xid_start+2, 2):uint() + 4
	local xid_pos = 4
	local xid_payload = buffer( xid_start, xid_len) 
	local subtree = tree:add( xid_payload, "AX.25 XID Payload" )
	subtree:add( pf_agwpe_xid_fi, xid_payload(0,1))
	subtree:add( pf_agwpe_xid_gi, xid_payload(1,1))
	subtree:add( pf_agwpe_xid_gl, xid_payload(2,2))
	while ( xid_pos+1 < xid_len ) do
		local param_id  = xid_payload( xid_pos  , 1):uint()
		local param_len = xid_payload( xid_pos+1, 1):uint()

		if     ( param_id == 0x2 ) then
			local cop_tree = subtree:add( pf_agwpe_xid_cop, xid_payload( xid_pos+2, param_len))
			cop_tree:add( pf_agwpe_xid_pi, xid_payload( xid_pos  , 1))
			cop_tree:add( pf_agwpe_xid_pl, xid_payload( xid_pos+1, 1))
			cop_tree:add_le( pf_agwpe_xid_cop_abm,   xid_payload( xid_pos+2, param_len))
			cop_tree:add_le( pf_agwpe_xid_cop_unrmp, xid_payload( xid_pos+2, param_len))
			cop_tree:add_le( pf_agwpe_xid_cop_unrms, xid_payload( xid_pos+2, param_len))
			cop_tree:add_le( pf_agwpe_xid_cop_uarmp, xid_payload( xid_pos+2, param_len))
			cop_tree:add_le( pf_agwpe_xid_cop_uarms, xid_payload( xid_pos+2, param_len))
			cop_tree:add_le( pf_agwpe_xid_cop_hdx,   xid_payload( xid_pos+2, param_len))
			cop_tree:add_le( pf_agwpe_xid_cop_fdx,   xid_payload( xid_pos+2, param_len))
			cop_tree:add_le( pf_agwpe_xid_cop_rsvd,  xid_payload( xid_pos+2, param_len))

		elseif ( param_id == 0x3 ) then
			local hof_tree = subtree:add( pf_agwpe_xid_hof, xid_payload( xid_pos+2, param_len))
			hof_tree:add( pf_agwpe_xid_pi, xid_payload( xid_pos  , 1))
			hof_tree:add( pf_agwpe_xid_pl, xid_payload( xid_pos+1, 1))
			hof_tree:add_le( pf_agwpe_xid_hof_rsvd_1,  xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_rej,     xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_srej,    xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_ui,      xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_srim,    xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_up,      xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_badd,    xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_eadd,    xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_delir,   xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_delic,   xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_mod8,    xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_mod128,  xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_rst,     xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_tst,     xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_rd,      xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_fcs16,   xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_fcs32,   xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_syntx,   xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_stttx,   xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_stfctl,  xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_stotra,  xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_msrej,   xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_segm,    xid_payload( xid_pos+2, param_len))
			hof_tree:add_le( pf_agwpe_xid_hof_rsvd_23, xid_payload( xid_pos+2, param_len))
			
		elseif ( param_id == 0x5 ) then
			local n1tx_tree = subtree:add( pf_agwpe_xid_n1_tx, xid_payload( xid_pos+2, param_len))
			n1tx_tree:add( pf_agwpe_xid_pi, xid_payload( xid_pos  , 1))
			n1tx_tree:add( pf_agwpe_xid_pl, xid_payload( xid_pos+1, 1))

		elseif ( param_id == 0x6 ) then
			local n1rx_tree = subtree:add( pf_agwpe_xid_n1_rx, xid_payload( xid_pos+2, param_len))
			n1rx_tree:add( pf_agwpe_xid_pi, xid_payload( xid_pos  , 1))
			n1rx_tree:add( pf_agwpe_xid_pl, xid_payload( xid_pos+1, 1))

		elseif ( param_id == 0x7 ) then
			local ktx_tree = subtree:add( pf_agwpe_xid_k_tx, xid_payload( xid_pos+2, param_len))
			ktx_tree:add( pf_agwpe_xid_pi, xid_payload( xid_pos  , 1))
			ktx_tree:add( pf_agwpe_xid_pl, xid_payload( xid_pos+1, 1))

		elseif ( param_id == 0x8 ) then
			local krx_tree = subtree:add( pf_agwpe_xid_k_tx, xid_payload( xid_pos+2, param_len))
			krx_tree:add( pf_agwpe_xid_pi, xid_payload( xid_pos  , 1))
			krx_tree:add( pf_agwpe_xid_pl, xid_payload( xid_pos+1, 1))

		elseif ( param_id == 0x9 ) then
			local t1_tree = subtree:add( pf_agwpe_xid_t1, xid_payload( xid_pos+2, param_len))
			t1_tree:add( pf_agwpe_xid_pi, xid_payload( xid_pos  , 1))
			t1_tree:add( pf_agwpe_xid_pl, xid_payload( xid_pos+1, 1))
			
		elseif ( param_id == 0xa ) then
			local n2_tree = subtree:add( pf_agwpe_xid_n2, xid_payload( xid_pos+2, param_len))
			n2_tree:add( pf_agwpe_xid_pi, xid_payload( xid_pos  , 1))
			n2_tree:add( pf_agwpe_xid_pl, xid_payload( xid_pos+1, 1))
			
		else
			local param_tree = subtree:add( xid_payload( xid_pos, 2+param_len), "Parameter TLV" )
			param_tree:add( pf_agwpe_xid_pi, xid_payload( xid_pos  , 1))
			param_tree:add( pf_agwpe_xid_pl, xid_payload( xid_pos+1, 1))
			param_tree:add_expert_info( PI_UNDECODED, PI_WARN, "Undocumented Parameter Value")
		end

		xid_pos = xid_pos + 2 + param_len
	end
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
				if ( packet_type:string() == "XID" ) then
					agw_dissect_xid( buffer(36):tvb(), pinfo, tree)
					pinfo.cols.info:append( fif( agwpe_is_final( buffer(36)), " (Final)", " (Poll)"))
				end
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
				if ( packet_type:string() == "XID" ) then
					agw_dissect_xid( buffer(36):tvb(), pinfo, tree)
					pinfo.cols.info:append( fif( agwpe_is_final( buffer(36)), " (Final)", " (Poll)"))
				end
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

