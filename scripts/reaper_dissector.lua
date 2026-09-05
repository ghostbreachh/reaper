-- Reaper Lua Dissector for Wireshark
-- Place in ~/.local/lib/wireshark/plugins/ or Wireshark's plugin dir

local reaper_proto = Proto("reaper", "REAPER Custom Events")

-- Fields
local f_type   = ProtoField.string("reaper.type", "Event Type")
local f_ssid   = ProtoField.string("reaper.ssid", "SSID")
local f_bssid  = ProtoField.ether("reaper.bssid", "BSSID")
local f_rssi   = ProtoField.int8("reaper.rssi", "RSSI")
local f_score  = ProtoField.float("reaper.score", "Score")
local f_detail = ProtoField.string("reaper.detail", "Detail")

reaper_proto.fields = { f_type, f_ssid, f_bssid, f_rssi, f_score, f_detail }

function reaper_proto.dissector(buf, pinfo, tree)
    pinfo.cols.protocol = "REAPER"
    local subtree = tree:add(reaper_proto, buf())
    local json_text = buf(0):string()
    local ok, obj = pcall(json.decode, json_text)
    if not ok or type(obj) ~= "table" then
        subtree:add(f_type, "RAW: " .. json_text)
        return
    end
    subtree:add(f_type, obj.type or "unknown")
    if obj.ssid then subtree:add(f_ssid, obj.ssid) end
    if obj.bssid then subtree:add(f_bssid, obj.bssid) end
    if obj.rssi then subtree:add(f_rssi, tonumber(obj.rssi)) end
    if obj.score then subtree:add(f_score, tonumber(obj.score)) end
    if obj.detail then subtree:add(f_detail, obj.detail) end
end

register_postdissector(reaper_proto)
