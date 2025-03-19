 -- dextra.lua - DExtra Protocol
local proto_shortname = "dextra"
local proto_longname = "DExtra Protocol"

p_dextra = Proto ( proto_shortname, proto_longname)

local band_list = {
	[0x41]="23 cm / 1.2 GHz",
	[0x42]="70 cm / 430~450 MHz",
	[0x43]="6m or 2m / 50~54MHz or 144~148MHz",
	[0x44]="Dongle",
}

local module_list = {
	[0x20]="Unbind from reflector",
	[0x41]="Bind to module A",
	[0x42]="Bind to module B",
	[0x43]="Bind to module C",
	[0x44]="Bind to module D",
	[0x45]="Bind to module E",
	[0x46]="Bind to module F",
	[0x47]="Bind to module G",
	[0x48]="Bind to module H",
	[0x49]="Bind to module I",
	[0x4A]="Bind to module J",
	[0x4B]="Bind to module K",
	[0x4C]="Bind to module L",
	[0x4D]="Bind to module M",
	[0x4E]="Bind to module N",
	[0x4F]="Bind to module O",
	[0x50]="Bind to module P",
	[0x51]="Bind to module Q",
	[0x52]="Bind to module R",
	[0x53]="Bind to module S",
	[0x54]="Bind to module T",
	[0x55]="Bind to module U",
	[0x56]="Bind to module V",
	[0x57]="Bind to module W",
	[0x58]="Unbind from reflector",	
	[0x59]="Bind to module Y",
	[0x5A]="Bind to module Z",
}

local result_list = {
	["ACK"]="Success",
	["NAK"]="Failure",
}

local pf_dextra_callsign = ProtoField.string ( proto_shortname .. ".callsign" , "Callsign", base.ASCII)
local pf_dextra_band     = ProtoField.uint8 ( proto_shortname .. ".band" , "Band", base.HEX, band_list)
local pf_dextra_module   = ProtoField.string ( proto_shortname .. ".callsign" , "Module", base.ASCII, module_list)
local pf_dextra_result   = ProtoField.string ( proto_shortname .. ".result" , "Result", base.ASCII, result_list)

p_dextra.fields = {
	pf_dextra_callsign, pf_dextra_band, pf_dextra_module, pf_dextra_result,
}

function p_dextra.dissector ( buffer, pinfo, tree)
	-- Validate packet length
	if ( buffer:len() < 3 ) then return end
	
	-- Set protocol name
	pinfo.cols.protocol = proto_shortname:upper()

	-- Subtree
	local subtree = tree:add( p_dextra, buffer(), proto_longname)
	local len = buffer():len()
	local callsign
	local rpt_band
	local xrf_module
	local result_code
	
	if( len == 9 ) then
		-- Keepalive
		callsign = buffer( 0, 8):string():gsub( " ", "")
		
		subtree:add( pf_dextra_callsign, buffer( 0, 8), callsign)
		subtree:add( buffer( 8, 1), "End of Message")
		pinfo.cols.info = "Keepalive from " .. callsign
		
	elseif ( len == 11 ) then
		-- Request
		callsign = buffer( 0, 8):string():gsub( " ", "")
		rpt_band = buffer( 8, 1):string()
		xrf_module = buffer( 9, 1):string()
		
		subtree:add( pf_dextra_callsign, buffer( 0, 8), callsign)
		subtree:add( pf_dextra_band, buffer( 8, 1))
		subtree:add( pf_dextra_module, buffer( 9, 1))
		subtree:add( buffer( 10, 1), "End of Message")
		if ( xrf_module ~= " " and xrf_module ~= "X" ) then
			pinfo.cols.info = "Bind request from: " .. callsign .. " " .. rpt_band .. ", module " .. xrf_module
		else
			pinfo.cols.info = "Disconnect request from: " .. callsign .. " " .. rpt_band
		end
		
	elseif ( len == 14 ) then
		-- Answer
		callsign = buffer( 0, 8):string():gsub( " ", "")
		rpt_band = buffer( 8, 1):string()
		xrf_module = buffer( 9, 1):string()
		result_code = buffer( 10, 3):string()
		
		subtree:add( pf_dextra_callsign, buffer( 0, 8), callsign)
		subtree:add( pf_dextra_band, buffer( 8, 1))
		subtree:add( pf_dextra_module, buffer( 9, 1))
		local result_subtree = subtree:add( pf_dextra_result, buffer( 10, 3))
		subtree:add( buffer( 13, 1), "End of Message")
		
		if ( xrf_module ~= " " and xrf_module ~= "X" ) then
			pinfo.cols.info = " bind from: " .. callsign .. " " .. rpt_band .. ", module " .. xrf_module
		else
			pinfo.cols.info = " disconnect from: " .. callsign .. " " .. rpt_band
		end
		
		if ( result_code == "ACK" ) then
			pinfo.cols.info:prepend("Successful")
			
		elseif ( result_code == "NAK" ) then
			pinfo.cols.info:prepend("Failed")
			
		else
			result_subtree:add_expert_info( PI_MALFORMED, PI_WARN, "Unknown result code")
			pinfo.cols.info = "[Unknown result code]"
		end
		
		
	elseif( buffer( 0,4):string() == "DSVT") then
		-- DVST Frame
		Dissector.get("dsvt"):call( buffer, pinfo, tree)
	end
end

local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add( 30001, p_dextra)
