-- add_scan_id.lua
-- Fluent Bit Lua filter: ensures every record has a scan_id field.
-- If scan_id is not present in the log record, assigns "default".

function add_scan_id(tag, timestamp, record)
    if record["scan_id"] == nil or record["scan_id"] == "" then
        record["scan_id"] = "default"
    end
    return 1, timestamp, record
end
