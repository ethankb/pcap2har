process_pages = True

# Whether HTTP parsing should allow a trailing semicolon in the media type.
# Such a semicolon would violate the protocol, but they are sometimes seen in
# practice.
allow_trailing_semicolon = False

# Whether HTTP parsing should allow empty media type, like Content-Type: \n
# This is sometimes seen in practice.  If allowed, will convert to
# application/x-unknown-content-type.  If disallowed, will raise ValueError.
allow_empty_mediatype = False

# Whether HTTP parsing should case whether the format of the mediatype matches
# allowable patterns.
strict_mediatype_parsing = False

# Whether HTTP parsing should care whether the content length matches the
# content-length header.
strict_http_parse_body = True

# Whether to pad missing data in TCP flows with 0 bytes
pad_missing_tcp_data = True

# Max gap in sequence numbers between back-to-back packets in one direction of a
# flow before we decide it is a new flow
max_sequence_gap = 1000000
