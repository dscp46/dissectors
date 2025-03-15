-- ddt2.lua - D-Rats Data Transport Protocol

-- Some module-specific constants
local proto_shortname = "ddt2"
local proto_fullname  = "D-Rats Data Transport 2"

-- Protocol Definition
p_ddt2 = Proto ( proto_shortname, proto_fullname)

-- Direction info (shim for versions < 3.4.4)
if( P2P_DIR_RECV == nil ) then
	P2P_DIR_UNKNOWN = -1
	P2P_DIR_SENT    =  0
	P2P_DIR_RECV    =  1
end

-------------------------------------------------------------------------------
-- Constants
-------------------------------------------------------------------------------

local DDT2_ESC_CHAR = 0x3D
local DDT2_OFFSET   = 0x40

local DDT2_MAGIC_COMP = 0xDD
local DDT2_MAGIC_UCMP = 0x22

local DDT2_TYPE_STATELESS = 0
local DDT2_TYPE_GENERAL = 1
local DDT2_TYPE_FILE_XFER = 2
local DDT2_TYPE_FRM_XFER = 3
local DDT2_TYPE_SOCK = 4
local DDT2_TYPE_PPFILE_XFER = 5
local DDT2_TYPE_PPFRM_XFER = 6
local DDT2_TYPE_RPC = 7
local DDT2_TYPE_WARMUP = 254

local DDT2_STLESS_DEFAULT = 0
local DDT2_STLESS_PRQ = 1
local DDT2_STLESS_PRP = 2
local DDT2_STLESS_ERQ = 3
local DDT2_STLESS_ERP = 4
local DDT2_STLESS_STATUS = 5

local DDT2_SESSION_CHAT = 1
local DDT2_SESSION_RPC = 2
local DDT2_SESSION_ZERO = 0


local DDT2_RPC_REQ = 0
local DDT2_RPC_ACK = 1

local DDT2_DYNSESS_SYN = 1
local DDT2_DYNSESS_ACK = 2
local DDT2_DYNSESS_NAK = 3
local DDT2_DYNSESS_DATA = 4
local DDT2_DYNSESS_REQACK = 5

-------------------------------------------------------------------------------
-- Fields
-------------------------------------------------------------------------------

-- Other protocols' fields
local agwpe_status, f_agwpe_src = pcall( Field.new, "agwpe.src")

-- My own fields
local pf_ddt2_magic = ProtoField.uint8 ( proto_shortname .. ".magic" , "Magic Header", base.HEX)
local pf_ddt2_src   = ProtoField.string( proto_shortname .. ".src"   , "Source", base.ASCII)
local pf_ddt2_dst   = ProtoField.string( proto_shortname .. ".dst"   , "Destination", base.ASCII)
local pf_ddt2_seq   = ProtoField.uint16( proto_shortname .. ".seq"   , "Sequence", base.DEC)
local pf_ddt2_sess  = ProtoField.uint8 ( proto_shortname .. ".sess"  , "Session ID", base.DEC)
local pf_ddt2_type  = ProtoField.uint8 ( proto_shortname .. ".type"  , "Type", base.DEC)
local pf_ddt2_len   = ProtoField.uint16( proto_shortname .. ".len"   , "Length", base.DEC)
local pf_ddt2_loop  = ProtoField.bool  ( proto_shortname .. ".loopback" , "Loopback")

p_ddt2.fields = {
	pf_ddt2_src, pf_ddt2_dst, pf_ddt2_seq, pf_ddt2_sess, pf_ddt2_type, pf_ddt2_len
}

local p_ddt2_stream_attrs = {}

-------------------------------------------------------------------------------
-- Lookup tables
-------------------------------------------------------------------------------

-- Frame Type
local ddt2_frame_type = {
	[DDT2_TYPE_STATELESS]= { ["name"]="Stateless", ["deprecated"]=false },
	[DDT2_TYPE_GENERAL]= { ["name"]="General", ["deprecated"]=false },
	[DDT2_TYPE_FILE_XFER]= { ["name"]="Non-pipelined File Transfer", ["deprecated"]=true },
	[DDT2_TYPE_FRM_XFER]= { ["name"]="Non-pipelined Form Transfer", ["deprecated"]=true },
	[DDT2_TYPE_SOCK]= { ["name"]="Socket", ["deprecated"]=false },
	[DDT2_TYPE_PPFILE_XFER]= { ["name"]="Pipelined File Transfer", ["deprecated"]=false },
	[DDT2_TYPE_PPFRM_XFER]= { ["name"]="Pipelined Form Transfer", ["deprecated"]=false },
	[DDT2_TYPE_RPC]= { ["name"]="Remote Procedure Call", ["deprecated"]=false },
	[DDT2_TYPE_WARMUP]= { ["name"]="Radio warm-up frame (padding)", ["deprecated"]=false },
}

local ddt2_stateless_types = {
	[DDT2_STLESS_DEFAULT]= { ["name"]="Default", ["deprecated"]=false },
	[DDT2_STLESS_PRQ]= { ["name"]="Ping Request", ["deprecated"]=false },
	[DDT2_STLESS_PRP]= { ["name"]="Ping Reply", ["deprecated"]=false },
	[DDT2_STLESS_ERQ]= { ["name"]="Echo Request", ["deprecated"]=false },
	[DDT2_STLESS_ERP]= { ["name"]="Echo Reply", ["deprecated"]=false },
	[DDT2_STLESS_STATUS]= { ["name"]="Status Report", ["deprecated"]=false },
}

local ddt2_rpc_types = {
	[DDT2_RPC_REQ]= { ["name"]="RPC Request", ["deprecated"]=false },
	[DDT2_RPC_ACK]= { ["name"]="RPC Answer", ["deprecated"]=false },
}

local ddt2_dynsess_types = {
	[DDT2_DYNSESS_SYN]= { ["name"]="SYN", ["deprecated"]=false },
	[DDT2_DYNSESS_ACK]= { ["name"]="ACK", ["deprecated"]=false },
	[DDT2_DYNSESS_NAK]= { ["name"]="NAK", ["deprecated"]=false },
	[DDT2_DYNSESS_DATA]= { ["name"]="Data", ["deprecated"]=false },
	[DDT2_DYNSESS_REQACK]= { ["name"]="Request ACK", ["deprecated"]=false },
	[DDT2_TYPE_WARMUP]= { ["name"]="Radio warm-up frame (padding)", ["deprecated"]=false },
}

local ddt2_status = {
	[0]= "Unknown",
	[1]= "Online",
	[2]= "Unattended",
	[9]= "Offline",
}

local ddt2_rpc_jobs = {
	["RPCFileListJob"]=true,
	["RPCFormListJob"]=true,
	["RPCPullFileJob"]=true,
	["RPCDeleteFileJob"]=true,
	["RPCPullFormJob"]=true,
	["RPCPositionReport"]=true,
	["RPCGetVersion"]=true,
	["RPCCheckMail"]=true,
}

-- CRC lookup table
local ddt2_crc_lut = {
    0x0000,  0x1021,  0x2042,  0x3063,  0x4084,  0x50a5,  0x60c6,  0x70e7,
    0x8108,  0x9129,  0xa14a,  0xb16b,  0xc18c,  0xd1ad,  0xe1ce,  0xf1ef,
    0x1231,  0x0210,  0x3273,  0x2252,  0x52b5,  0x4294,  0x72f7,  0x62d6,
    0x9339,  0x8318,  0xb37b,  0xa35a,  0xd3bd,  0xc39c,  0xf3ff,  0xe3de,
    0x2462,  0x3443,  0x0420,  0x1401,  0x64e6,  0x74c7,  0x44a4,  0x5485,
    0xa56a,  0xb54b,  0x8528,  0x9509,  0xe5ee,  0xf5cf,  0xc5ac,  0xd58d,
    0x3653,  0x2672,  0x1611,  0x0630,  0x76d7,  0x66f6,  0x5695,  0x46b4,
    0xb75b,  0xa77a,  0x9719,  0x8738,  0xf7df,  0xe7fe,  0xd79d,  0xc7bc,
    0x48c4,  0x58e5,  0x6886,  0x78a7,  0x0840,  0x1861,  0x2802,  0x3823,
    0xc9cc,  0xd9ed,  0xe98e,  0xf9af,  0x8948,  0x9969,  0xa90a,  0xb92b,
    0x5af5,  0x4ad4,  0x7ab7,  0x6a96,  0x1a71,  0x0a50,  0x3a33,  0x2a12,
    0xdbfd,  0xcbdc,  0xfbbf,  0xeb9e,  0x9b79,  0x8b58,  0xbb3b,  0xab1a,
    0x6ca6,  0x7c87,  0x4ce4,  0x5cc5,  0x2c22,  0x3c03,  0x0c60,  0x1c41,
    0xedae,  0xfd8f,  0xcdec,  0xddcd,  0xad2a,  0xbd0b,  0x8d68,  0x9d49,
    0x7e97,  0x6eb6,  0x5ed5,  0x4ef4,  0x3e13,  0x2e32,  0x1e51,  0x0e70,
    0xff9f,  0xefbe,  0xdfdd,  0xcffc,  0xbf1b,  0xaf3a,  0x9f59,  0x8f78,
    0x9188,  0x81a9,  0xb1ca,  0xa1eb,  0xd10c,  0xc12d,  0xf14e,  0xe16f,
    0x1080,  0x00a1,  0x30c2,  0x20e3,  0x5004,  0x4025,  0x7046,  0x6067,
    0x83b9,  0x9398,  0xa3fb,  0xb3da,  0xc33d,  0xd31c,  0xe37f,  0xf35e,
    0x02b1,  0x1290,  0x22f3,  0x32d2,  0x4235,  0x5214,  0x6277,  0x7256,
    0xb5ea,  0xa5cb,  0x95a8,  0x8589,  0xf56e,  0xe54f,  0xd52c,  0xc50d,
    0x34e2,  0x24c3,  0x14a0,  0x0481,  0x7466,  0x6447,  0x5424,  0x4405,
    0xa7db,  0xb7fa,  0x8799,  0x97b8,  0xe75f,  0xf77e,  0xc71d,  0xd73c,
    0x26d3,  0x36f2,  0x0691,  0x16b0,  0x6657,  0x7676,  0x4615,  0x5634,
    0xd94c,  0xc96d,  0xf90e,  0xe92f,  0x99c8,  0x89e9,  0xb98a,  0xa9ab,
    0x5844,  0x4865,  0x7806,  0x6827,  0x18c0,  0x08e1,  0x3882,  0x28a3,
    0xcb7d,  0xdb5c,  0xeb3f,  0xfb1e,  0x8bf9,  0x9bd8,  0xabbb,  0xbb9a,
    0x4a75,  0x5a54,  0x6a37,  0x7a16,  0x0af1,  0x1ad0,  0x2ab3,  0x3a92,
    0xfd2e,  0xed0f,  0xdd6c,  0xcd4d,  0xbdaa,  0xad8b,  0x9de8,  0x8dc9,
    0x7c26,  0x6c07,  0x5c64,  0x4c45,  0x3ca2,  0x2c83,  0x1ce0,  0x0cc1,
    0xef1f,  0xff3e,  0xcf5d,  0xdf7c,  0xaf9b,  0xbfba,  0x8fd9,  0x9ff8,
    0x6e17,  0x7e36,  0x4e55,  0x5e74,  0x2e93,  0x3eb2,  0x0ed1,  0x1ef0
}

-------------------------------------------------------------------------------
-- Internal Functions
-------------------------------------------------------------------------------
-- Ternary operator
local function fif(condition, if_true, if_false)
	if condition then return if_true else return if_false end
end

-- Checksum update function
local function ddt2_crc_update ( checksum, val)
	if ( val == nil ) then return nil end
	if ( checksum == nil ) then return nil end
	-- ((checksum << 8) ^ lzhuf_crc_lut[ (val & 0xFF) ^ (checksum >> 8)])
	-- +1 because of initialized lua array indexing offset
	local result = bit.bxor( bit.lshift( checksum, 8), ddt2_crc_lut[ bit.bxor( bit.band( val, 0xFF), bit.rshift( checksum, 8))+1])
	return bit.band( result, 0xFFFF) -- Constrain result as a 16 bit integer
end

local function ddt2_crc16 ( buffer)
	if ( buffer == nil ) then return nil end
	local len = buffer():len()
	local checksum = 0;
	local i = 0
	
	while( i < len ) do
		if ( i ~= 5 and i ~= 6 ) then
			checksum = ddt2_crc_update( checksum, buffer( i, 1):uint())
		else
			-- Pad null bytes in place of checksum
			checksum = ddt2_crc_update( checksum, 0)
		end

		i = i + 1
	end
	
	return checksum
end

-- Decode type
local function decode_mesg_type ( buffer, pinfo, tree)
	local session = buffer( 3, 1):uint()
	local ftype = buffer( 4, 1):uint()
	local name = nil
	local deprecated = false
	
	if ( session == DDT2_SESSION_CHAT ) then
		-- Chat Session
		if ( ddt2_stateless_types[ftype] ~= nil ) then
			name = ddt2_stateless_types[ftype]["name"]
			deprecated = ddt2_stateless_types[ftype]["deprecated"]
		end
		
	elseif ( session == DDT2_SESSION_RPC ) then
		-- RPC Session
		if ( ddt2_rpc_types[ftype] ~= nil ) then
			name = ddt2_rpc_types[ftype]["name"]
			deprecated = ddt2_rpc_types[ftype]["deprecated"]
		end
		
	else
		-- Dynamic Session
		if ( ddt2_dynsess_types[ftype] ~= nil ) then
			name = ddt2_dynsess_types[ftype]["name"]
			deprecated = ddt2_dynsess_types[ftype]["deprecated"]
		end

	end
	
	if ( deprecated == true ) then
		tree:add_expert_info( PI_DEPRECATED, PI_WARN, "Deprecated Message Type")
	end
	
	if ( name == nil ) then
		name = "Unknown"
		tree:add_expert_info( PI_PROTOCOL, PI_WARN, "Undocumented Message Type")
		pinfo.cols.info = "[Unknown Frame Type]"
	else
		pinfo.cols.info = name
	end
	
	return name .. " (" .. ftype .. ")"
end

local function ddt2_is_valid_fix ( buffer)
	-- TODO: Validate presence of $GPGGA,$GPRMC or $$CRC in frame (first two are NMEA sentences, the last is an APRS sentence)
	return false
end

function p_ddt2.dissector(buffer, pinfo, tree)
	local length = buffer:len()
	
	if ( length <= 25 and buffer( 0, 5):string() ~= "[SOB]" and buffer( length-5, 5):string() ~= "[EOB]" ) then return end
	
	local subtree = tree:add( p_ddt2, buffer())
	pinfo.cols.protocol = string.upper( proto_shortname)
	
	local ba_payload = ByteArray.new()
	
	local i=5
	while ( i < length-5 ) do
		if ( buffer( i, 1):uint() == DDT2_ESC_CHAR  and i < length-6 ) then
			-- Append the next escaped character
			local esc_char = buffer(i+1,1):uint() - DDT2_OFFSET
			if ( esc_char < 0 ) then esc_char = esc_char + 256 end
			
			ba_payload:append( ByteArray.new( string.format("%02X", esc_char) ) )
			i = i + 1
		else
			-- Add the current character
			ba_payload:append( ByteArray.new( string.format("%02X", buffer(i,1):uint()) ) )
		end
	
		i = i + 1
	end
	
	local payload_tvb = ba_payload:tvb( "DDT2 Frame" )	
	
	--------------------------------------------------------------------
	-- DDT2 Header
	--------------------------------------------------------------------
	local header_tree = subtree:add( p_ddt2, payload_tvb( 0, 25), "DDT2 Frame Header")

	-- Magic header
	local magic_hdr = payload_tvb( 0, 1):uint()
	local compressed_payload = false

	if ( magic_hdr == DDT2_MAGIC_COMP ) then
		-- DEFLATE Compressed Payload
		header_tree:add( pf_ddt2_magic, payload_tvb( 0, 1), "Magic header: Compressed payload" )
		compressed_payload = true
		
	elseif ( magic_hdr == DDT2_MAGIC_UCMP ) then
		-- Uncompressed Payload
		header_tree:add( pf_ddt2_magic, payload_tvb( 0, 1), "Magic header: Uncompressed payload" )
		
	else
		local magic_tree = header_tree:add( pf_ddt2_magic, payload_tvb( 0, 1), "Magic header: Unknown payload" )
		magic_tree:add_expert_info( PI_PROTOCOL, PI_WARN, "Unknown Payload format")
		return
	end

	-- Sequence number
	local seq = payload_tvb( 1, 2):uint()
	header_tree:add( pf_ddt2_seq, payload_tvb( 1, 2))

	-- Session ID
	local session = payload_tvb( 3, 1):uint()
	header_tree:add( pf_ddt2_sess, payload_tvb( 3, 1))

	-- Type
	local mesg_type = payload_tvb( 4, 1):uint()	
	local mesg_type_tree = header_tree:add( pf_ddt2_type, payload_tvb( 4, 1), mesg_type, "Type: " )
	mesg_type_tree.text = mesg_type_tree.text .. decode_mesg_type( payload_tvb, pinfo, mesg_type_tree)
	
	-- Checksum
	local checksum = payload_tvb( 5, 2):uint()
	local checksum_tree = header_tree:add( p_ddt2, payload_tvb( 5, 2), "Checksum: " .. string.format( "%04X", checksum) )

	-- Length
	local mesg_len = payload_tvb( 7, 2):uint()
	header_tree:add( pf_ddt2_len, payload_tvb( 7, 2))

	-- Source
	local source = payload_tvb( 9, 8):string():gsub("~", "")
	header_tree:add( pf_ddt2_src, payload_tvb( 9, 8), source)

	-- Destination
	local destination = payload_tvb( 17, 8):string():gsub("~", "")
	header_tree:add( pf_ddt2_dst, payload_tvb( 17, 8), destination )

	-- Validate Checksum
	local computed_checksum = ddt2_crc16( payload_tvb())
	if ( computed_checksum == checksum ) then
		checksum_tree.text = checksum_tree.text .. " [valid]"
	else
		checksum_tree:add_expert_info( PI_MALFORMED, PI_WARN, "Invalid Checksum (got " .. string.format( "%04X", computed_checksum).. ", expected " .. string.format( "%04X", checksum) .. ")")
		pinfo.cols.info:append( " [Malformed]")
		return
	end
	
	-- TODO: Hide loopback packets
	if ( pinfo.cols.direction ~= nil and pinfo.cols.direction == P2P_DIR_RECV ) then
		--local agwpe_src = f_agwpe_src().value
		--[[ if ( agwpe_src ~= nil and agwpe_src ~= "" and source == mycall ) then
			pinfo.hidden = true 
			return
		end -- ]]--
	end
	
	
	-- Decode body if applicable
	if ( mesg_len > 0 ) then
		local body = payload_tvb( 25)
		local inner_type = nil
		
		if ( compressed_payload == true ) then
			local status, decomp_tvb = pcall(function() return body:uncompress_zlib() end)
			if ( status ) then body = decomp_tvb else body = body:uncompress() end
			
			
			if ( session == DDT2_SESSION_CHAT and mesg_type == DDT2_STLESS_STATUS ) then 
				-- In status reports, the inner type is the decimal value of the first byte.
				inner_type = tonumber( body( 0, 1):string())
			end
		end
		
		--------------------------------------------------------------------
		-- DDT2 Body
		--------------------------------------------------------------------
		
		local body_tree = subtree:add( p_ddt2, body, "DDT2 Frame Body")
		
		if( session == DDT2_SESSION_CHAT ) then
			-- Chat Session
			
			if ( mesg_type == DDT2_STLESS_STATUS ) then
				-- Status Report
				body_tree:add( p_ddt2, body( 0,1), "Message type: " .. ddt2_status[ inner_type] .. " (" .. inner_type .. ")")
				body_tree:add( p_ddt2, body( 1), "Message content: " .. body( 1):string())
				pinfo.cols.info = "Status report from " .. source .. ": " .. ddt2_status[ inner_type] .. ", \"" .. body( 1):string() .. "\""
				
			elseif ( mesg_type == DDT2_STLESS_PRQ ) then
			elseif ( mesg_type == DDT2_STLESS_PRP ) then
			elseif ( mesg_type == DDT2_STLESS_ERQ ) then
			elseif ( mesg_type == DDT2_STLESS_ERP ) then
				-- TODO: Ping and Echo Requests
				
			else
				-- Instant Message
				if ( ddt2_is_valid_fix( body) == true ) then
					-- TODO: GPS Fix
					return
				end
				
				body_tree:add( p_ddt2, body(), "DDT, Stateless, Instant message: " .. body():string())
				if ( destination == "CQCQCQ" ) then
					pinfo.cols.info = "Broadcast message from " .. source .. ": " .. body():string()
				else
					pinfo.cols.info = "Instant message from " .. source .. " to " .. destination .. ": " .. body():string()
				end
			end
			
		elseif ( session == DDT2_SESSION_RPC ) then
			-- TODO: Remote Procedure Call

		else
			-- Dynamic Session
			if ( mesg_type == DDT2_TYPE_WARMUP ) then
				--pinfo.cols.info = ddt2_frame_type[DDT2_TYPE_WARMUP]
				body_tree:add_expert_info( PI_UNDECODED, PI_CHAT, "Padding data to warmup power amplifier")
				return
			end
		end
	end
end
