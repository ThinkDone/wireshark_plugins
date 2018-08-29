local p_socket = Proto("socket", "Socket");

local f_bytes = ProtoField.bytes("socket.bytes", "Bytes")
local f_bool = ProtoField.bool("socket.bool", "Bool")
local f_int16 = ProtoField.int16("socket.int16", "Int16")
local f_int32 = ProtoField.int32("socket.int32", "Int32")

p_socket.fields = {f_bytes, f_bool, f_int16, f_int32}

local data_dis = Dissector.get("data")

local function socket_request_dissector(buf, pkt, tree)

	local subtree = tree:add(p_socket, buf)
	subtree:add(f_int32, buf(0,4):le_int())
	subtree:add(f_int16, buf(4,2):le_int())
	subtree:add(f_int16, buf(6,4):le_int())
	subtree:add(f_int32, buf(10,4):le_int())

	local data_len = buf(0,4):le_int()
	data_dis:call(buf(14, data_len):tvb(), pkt, tree)

end

local function socket_response_dissector(buf, pkt, tree)

	local subtree = tree:add(p_socket, buf)
	subtree:add(f_int32, buf(0,4):le_int())
	subtree:add(f_int16, buf(4,2):le_int())
	subtree:add(f_int16, buf(6,4):le_int())
	subtree:add(f_bool, buf(10,1))
	subtree:add(f_bytes, buf(11,1))
	subtree:add(f_int32, buf(12,4):le_int())

	local data_len = buf(0,4):le_int()
	data_dis:call(buf(14, data_len):tvb(), pkt, tree)

end

function p_socket.dissector(buf, pkt, tree)

	pkt.cols.protocol = p_socket.name
	
	local request_header_len = 14
	local response_header_len = 16

	local buf_len = buf:len()
	local body_len = buf(0,4):le_int()
	
	if buf_len == request_header_len + body_len then
		socket_request_dissector(buf, pkt, tree)
	elseif buf_len == response_header_len + body_len then
		socket_response_dissector(buf, pkt, tree)
	else
		data_dis:call(buf, pkt, tree)
	end

end

local tcp_encap_table = DissectorTable.get("tcp.port")

tcp_encap_table:add(6666, p_socket)
