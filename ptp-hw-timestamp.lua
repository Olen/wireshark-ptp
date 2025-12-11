-- Fix PTP packets with an extra 10-byte Meinberg HW timestamp header
-- and show the timestamp as a human-readable UTC time, while keeping
-- the IPv4 header at the normal top level (not nested inside this shim).

local ip_dissector = Dissector.get("ip")

local fix_ptp = Proto("fix_ptp_extra_header", "Meinberg HW Timestamp shim")

local f_ts_hi  = ProtoField.uint32("meinberg.ts_hi",  "Timestamp high (upper 32 bits)", base.HEX)
local f_ts_lo  = ProtoField.uint32("meinberg.ts_lo",  "Timestamp low (lower 32 bits)",  base.HEX)
local f_ts_ns  = ProtoField.string("meinberg.ts_ns",  "Timestamp since epoch (ns)",     base.ASCII)
local f_ts_utc = ProtoField.string("meinberg.ts_utc", "Timestamp (derived UTC)",        base.ASCII)

fix_ptp.fields = { f_len, f_ts_hi, f_ts_lo, f_ts_ns, f_ts_utc }

local function decode_timestamp(hi, lo)
    -- hi/lo are upper/lower 32 bits of nanoseconds since UNIX epoch
    local factor = 4294967296.0 / 1e9   -- 2^32 / 1e9
    local seconds = hi * factor + lo / 1e9

    local epoch_sec = math.floor(seconds)
    local frac = seconds - epoch_sec
    if frac < 0 then frac = 0 end
    local ns_rem = math.floor(frac * 1e9 + 0.5)

    local date_str = os.date("!%Y-%m-%d %H:%M:%S", epoch_sec) or "1970-01-01 00:00:00"
    local utc_str = string.format("%s.%09d UTC", date_str, ns_rem)

    local ns_approx = seconds * 1e9
    local ns_str = string.format("%.0f", ns_approx)

    return utc_str, ns_str
end

function fix_ptp.dissector(tvb, pinfo, tree)
    -- Need at least Ethernet (14) + shim (10) + minimal IP (20)
    if tvb:len() < 44 then return end

    -- Match dest MAC: 01:00:5e:00:01:81
    local b0 = tvb(0,1):uint()
    local b1 = tvb(1,1):uint()
    local b2 = tvb(2,1):uint()
    local b3 = tvb(3,1):uint()
    local b4 = tvb(4,1):uint()
    local b5 = tvb(5,1):uint()

    if not (b0 == 0x01 and b1 == 0x00 and b2 == 0x5e and
            b3 == 0x00 and b4 == 0x01 and b5 == 0x81) then
        return
    end

    -- Type/Length field at 12–13
    local type_len = tvb(12,2):uint()
    if type_len >= 0x0600 then
        -- standard Ethernet II (0x0800) etc – we leave those alone
        return
    end

    -- Inner Ethertype at 22–23 should be IPv4 (0x0800)
    local inner_type = tvb(22,2):uint()
    if inner_type ~= 0x0800 then
        return
    end

    if tvb:len() <= 24 then return end
    local ip_tvb = tvb(24):tvb()

    -- Let IP/UDP/PTP show up in the protocol column
    pinfo.cols.protocol = "IP"

    -- Add ONLY the shim as our subtree (10 bytes at offset 12)
    local shim = tree:add(fix_ptp, tvb(12,10), "Meinberg HW Timestamp Header")

    local hi = tvb(14,4):uint()
    local lo = tvb(18,4):uint()

    shim:add(f_ts_hi, tvb(14,4))
    shim:add(f_ts_lo, tvb(18,4))

    local utc_str, ns_str = decode_timestamp(hi, lo)
    shim:add(f_ts_ns,  tvb(14,8), ns_str)
    shim:add(f_ts_utc, tvb(14,8), utc_str)

    -- Now dissect the inner IPv4 directly at the top level
    ip_dissector:call(ip_tvb, pinfo, tree)
end

register_postdissector(fix_ptp)

